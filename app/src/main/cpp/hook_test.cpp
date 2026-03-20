#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <android/log.h>
#include <sys/time.h>
#include <unwind.h>
#include <thread>
#include <cerrno>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <csignal>

#include "bytehook.h"
#include "monitor.h"

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "APM_Hook", __VA_ARGS__)

#define TYPE_MALLOC 1
#define TYPE_REALLOC 2
#define TYPE_CALLOC 3
#define TYPE_FREE 4
#define TYPE_MMAP 5
#define TYPE_MUNMAP 6

// ==========================================
// 全局变量定义
// ==========================================
typedef void* (*orig_malloc_t)(size_t);
static orig_malloc_t g_orig_malloc = nullptr;

typedef void* (*orig_realloc_t)(void*, size_t);
static orig_realloc_t g_orig_realloc = nullptr;

typedef void* (*orig_calloc_t)(size_t, size_t);
static orig_calloc_t g_orig_calloc = nullptr;

typedef void (*orig_free_t)(void*);
static orig_free_t g_orig_free = nullptr;

typedef void* (*orig_mmap_t)(void*, size_t, int, int, int, off_t);
static orig_mmap_t g_orig_mmap = nullptr;

typedef int (*orig_munmap_t)(void*, size_t);
static orig_munmap_t g_orig_munmap = nullptr;

#define MAX_HOOK_COUNT 10
static bytehook_stub_t g_hook_stubs[MAX_HOOK_COUNT];
static int g_hook_count = 0;

#define MAX_BACKTRACE_DEPTH 20
static size_t G_PAGE_SIZE = sysconf(_SC_PAGESIZE);
static struct sigaction old_sa;

// log保存路径
#define LOG_FILE_PATH "/storage/emulated/0/Android/data/com.example.application/files/mem_reg.log"
#define LOG_BUF_SIZE 4096

// 【极其关键】：线程局部防重入锁，保护 Hook 函数不发生死循环和误拦截！
static __thread bool g_in_hook = false;

static uint64_t get_current_time_ms() {
    timeval tv{};
    gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void write_memory_log(int type, void* address, size_t size, const char* stack) {
    uint64_t ts = get_current_time_ms();
    char log_buf[LOG_BUF_SIZE] = {0};
    snprintf(log_buf, sizeof(log_buf), "%" PRIu64 ",%d,%p,%zu, %s\n", ts, type, address, size, stack);

    FILE* fp = fopen(LOG_FILE_PATH, "a+");
    if (fp != nullptr) {
        fwrite(log_buf, 1, strlen(log_buf), fp);
        fflush(fp);
        fclose(fp);
    } else {
        LOG("打开日志文件失败: %s, 路径: %s", strerror(errno), LOG_FILE_PATH);
    }
}

struct BacktraceContext {
    uintptr_t* frames;
    size_t count;
    size_t max_count;
};

static _Unwind_Reason_Code unwind_callback(_Unwind_Context* ctx, void* arg) {
    BacktraceContext* context = (BacktraceContext*)arg;
    uintptr_t ip = _Unwind_GetIP(ctx);
    if (ip == 0) return _URC_NO_REASON;
    if (context->count < context->max_count) {
        context->frames[context->count++] = ip;
    } else {
        return _URC_END_OF_STACK;
    }
    return _URC_NO_REASON;
}

static void get_backtrace(char* buf, size_t buf_size) {
    if (!buf || buf_size == 0) {
        buf[0] = '\0';
        return;
    }
    uintptr_t frames[MAX_BACKTRACE_DEPTH];
    BacktraceContext context = { .frames = frames, .count = 0, .max_count = MAX_BACKTRACE_DEPTH };

    _Unwind_Backtrace(unwind_callback, &context);

    size_t offset = 0;
    for (size_t i = 0; i < context.count; i++) {
        if (offset >= buf_size - 30) break;
        int len = snprintf(buf + offset, buf_size - offset, "0x%" PRIxPTR "%s", frames[i], (i < context.count - 1) ? "," : "");
        offset += len;
    }
    buf[offset] = '\0';
}

// 识别逻辑访问
struct BacktraceState { uintptr_t* current; uintptr_t* end; };
static _Unwind_Reason_Code unwind_cb(struct _Unwind_Context* context, void* arg) {
    BacktraceState* state = static_cast<BacktraceState*>(arg);
    uintptr_t pc = _Unwind_GetIP(context);
    if (pc) {
        if (state->current == state->end) return _URC_END_OF_STACK;
        *state->current++ = pc;
    }
    return _URC_NO_REASON;
}

LogicID IdentifyLogicFromStack(uintptr_t* frames, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        Dl_info info;
        if (dladdr((void*)frames[i], &info) && info.dli_sname) {
            if (strstr(info.dli_sname, "logic_A_process")) return LogicID::LOGIC_A;
            if (strstr(info.dli_sname, "logic_B_process")) return LogicID::LOGIC_B;
        }
    }
    return LogicID::LOGIC_UNKNOWN;
}

// SIGSEGV 信号拦截器
static void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    // 【防重入保护】如果在处理信号时又崩溃了，或者我们主动挂了金牌，直接交回给系统兜底
    if (g_in_hook) {
        if (old_sa.sa_flags & SA_SIGINFO) old_sa.sa_sigaction(sig, info, ucontext);
        else if (old_sa.sa_handler != SIG_DFL && old_sa.sa_handler != SIG_IGN) old_sa.sa_handler(sig);
        return;
    }

    g_in_hook = true; // 挂上免死金牌，准备施展神仙操作

    uintptr_t fault_addr = (uintptr_t)info->si_addr;
    uintptr_t page_base = fault_addr & ~(G_PAGE_SIZE - 1);

    MonitorBlock block;
    if (MonitorManager::GetInstance().GetMonitorBlock(page_base, block)) {

        uint32_t offset = fault_addr - page_base;

        if (block.monitor_type == MonitorType::MEMBER) {
            // 需求 2：结构体成员精细拆解冷热
            MonitorManager::GetInstance().UpdateMemberHot(page_base, offset);
        }
        else if (block.monitor_type == MonitorType::SHARE) {
            // 需求 3：共享内存多逻辑访问溯源
            uintptr_t frames[15];
            BacktraceState state = {frames, frames + 15};
            _Unwind_Backtrace(unwind_cb, &state);
            size_t frame_count = state.current - frames;

            LogicID logic = IdentifyLogicFromStack(frames, frame_count);
            MonitorManager::GetInstance().UpdateLogicAccess(page_base, logic);
        }

        // 放行权限，让触发异常的那行汇编代码能继续跑下去
        mprotect((void*)page_base, block.size, PROT_READ | PROT_WRITE);

        g_in_hook = false; // 摘下免死金牌
        return;
    }

    g_in_hook = false; // 没命中监控，摘下免死金牌

    // 不是我们监控的页，把锅甩给系统原生的崩溃处理器
    if (old_sa.sa_flags & SA_SIGINFO) old_sa.sa_sigaction(sig, info, ucontext);
    else if (old_sa.sa_handler != SIG_DFL && old_sa.sa_handler != SIG_IGN) old_sa.sa_handler(sig);
}

// malloc 接管与内存隔离
void* my_malloc(size_t size) {
    // 【防重入保护】如果已经在 hook 流程里，说明是监控工具内部申请的内存，绝对不能拦截！
    if (g_in_hook || !g_orig_malloc) {
        return g_orig_malloc ? g_orig_malloc(size) : nullptr;
    }

    g_in_hook = true; // 进入沙盒模式
    void* result = nullptr;

    // --- 【需求 1 & 2】：识别小对象并强行放入独立页 ---
    if (size == 1024 /* 或者 size < 4096 */) {
        size_t alloc_size = G_PAGE_SIZE;
        void* page_ptr = mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (page_ptr != MAP_FAILED) {
            MonitorBlock block{};
            block.address = (uintptr_t)page_ptr;
            block.size = alloc_size;
            block.monitor_type = MonitorType::MEMBER;
            block.is_monitored = true;
            block.struct_meta = { "TestStruct", 1024, {
                    {"name", 0, 15, false}, {"id", 16, 19, false}, {"data", 20, 1023, false}
            }};

            MonitorManager::GetInstance().AddMonitorBlock(block);
            mprotect(page_ptr, alloc_size, PROT_NONE); // 上高压电！

            result = page_ptr; // 狸猫换太子，返回隔离页的地址
            LOG("成功接管 TestStruct，分配至隔离页: %p", result);
        }
    }
        // --- 【需求 3】：识别出共享大页 ---
    else if (size == 4096) {
        void* page_ptr = mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (page_ptr != MAP_FAILED) {
            MonitorBlock block{};
            block.address = (uintptr_t)page_ptr;
            block.size = 4096;
            block.monitor_type = MonitorType::SHARE;
            block.is_monitored = true;

            MonitorManager::GetInstance().AddMonitorBlock(block);
            mprotect(page_ptr, 4096, PROT_NONE);

            result = page_ptr;
            LOG("成功接管 共享大页，分配至隔离页: %p", result);
        }
    }

    // --- 原生兜底逻辑 ---
    if (result == nullptr) {
        uint64_t ts = get_current_time_ms();
        result = g_orig_malloc(size);

        char backtrace[1024];
        get_backtrace(backtrace, sizeof(backtrace));
        // write_memory_log(TYPE_MALLOC, result, size, backtrace);
        // LOG("%" PRIu64 ",%d,%p,%zu,%s", ts, TYPE_MALLOC, result, size, backtrace);
    }

    g_in_hook = false; // 退出沙盒模式
    return result;
}

void my_free(void* ptr) {
    if (!ptr) return;

    if (g_in_hook || !g_orig_free) {
        if (g_orig_free) g_orig_free(ptr);
        return;
    }

    g_in_hook = true; // 进入沙盒模式

    MonitorBlock block;
    // 【关键】：检查是不是我们 mmap 出来的隔离页？
    if (MonitorManager::GetInstance().GetMonitorBlock((uintptr_t)ptr, block)) {
        MonitorManager::GetInstance().RemoveMonitorBlock((uintptr_t)ptr);
        // 放开权限再 munmap，防止析构函数或操作系统回收时崩溃
        mprotect(ptr, block.size, PROT_READ | PROT_WRITE);
        munmap(ptr, block.size);
        LOG("释放受控隔离页: %p", ptr);
    } else {
        // 普通的 malloc 内存，交给原生的 free 释放
        uint64_t ts = get_current_time_ms();
        g_orig_free(ptr);
        // write_memory_log(TYPE_FREE, ptr, 0, nullptr);
    }

    g_in_hook = false; // 退出沙盒模式
}

// ==========================================
// 其他内存函数的 Hook (保持原有逻辑，但加上沙盒保护)
// ==========================================
void* my_realloc(void* ptr, size_t size) {
    if (g_in_hook || !g_orig_realloc) return g_orig_realloc ? g_orig_realloc(ptr, size) : nullptr;
    g_in_hook = true;

    uint64_t ts = get_current_time_ms();
    void* address = g_orig_realloc(ptr, size);
    char backtrace[1024];
    get_backtrace(backtrace, sizeof(backtrace));
    // write_memory_log(TYPE_REALLOC, address, size, backtrace);

    g_in_hook = false;
    return address;
}

void* my_calloc(size_t size, size_t per_size) {
    if (g_in_hook || !g_orig_calloc) return g_orig_calloc ? g_orig_calloc(size, per_size) : nullptr;
    g_in_hook = true;

    uint64_t ts = get_current_time_ms();
    void* address = g_orig_calloc(size, per_size);
    char backtrace[1024];
    get_backtrace(backtrace, sizeof(backtrace));
    size_t total = size * per_size;
    // write_memory_log(TYPE_CALLOC, address, total, backtrace);

    g_in_hook = false;
    return address;
}

void* my_mmap(void* address, size_t length, int prot, int flags, int fd, off_t offset) {
    if (g_in_hook || !g_orig_mmap) return g_orig_mmap ? g_orig_mmap(address, length, prot, flags, fd, offset) : nullptr;
    g_in_hook = true;

    uint64_t ts = get_current_time_ms();
    void* address_res = g_orig_mmap(address, length, prot, flags, fd, offset);
    char backtrace[1024];
    get_backtrace(backtrace, sizeof(backtrace));
    // write_memory_log(TYPE_MMAP, address_res, length, backtrace);

    g_in_hook = false;
    return address_res;
}

int my_munmap(void* address, size_t length) {
    if (g_in_hook || !g_orig_munmap) return g_orig_munmap ? g_orig_munmap(address, length) : -1;
    g_in_hook = true;

    uint64_t ts = get_current_time_ms();
    int res = g_orig_munmap(address, length);
    // write_memory_log(TYPE_MUNMAP, address, 0, nullptr);

    g_in_hook = false;
    return res;
}

// 钩子注册与生命周期管理
static void on_hooked(bytehook_stub_t stub, int status, const char* caller, const char* sym, void* new_func, void* orig_func, void* arg) {
    if (status == BYTEHOOK_STATUS_CODE_ORIG_ADDR) {
        if (strcmp(sym, "malloc") == 0) g_orig_malloc = (orig_malloc_t)orig_func;
        else if (strcmp(sym, "realloc") == 0) g_orig_realloc = (orig_realloc_t)orig_func;
        else if (strcmp(sym, "calloc") == 0) g_orig_calloc = (orig_calloc_t)orig_func;
        else if (strcmp(sym, "free") == 0) g_orig_free = (orig_free_t)orig_func;
        else if (strcmp(sym, "mmap") == 0) g_orig_mmap = (orig_mmap_t)orig_func;
        else if (strcmp(sym, "munmap") == 0) g_orig_munmap = (orig_munmap_t)orig_func;
        LOG("获取原函数地址成功: %s", sym);
    }
}

// 后台持续采样线程 (确保持续产生冷热数据)
static void start_monitor_thread() {
    std::thread([]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // 每 100ms 采样一次
            MonitorManager::GetInstance().ReprotectAllBlocks();
        }
    }).detach();
}

extern "C" int start_hook() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, &old_sa);
    start_monitor_thread();

    bytehook_init(BYTEHOOK_MODE_MANUAL, true);

    const char* symbols[] = {"malloc", "realloc", "calloc", "free", "mmap", "munmap"};
    void* new_func[] = {(void*)my_malloc, (void*)my_realloc, (void*)my_calloc,
                        (void*)my_free, (void*)my_mmap, (void*)my_munmap};

    for (int i = 0; i < 6; i++) {
        bytehook_stub_t stub = bytehook_hook_single("libsample.so", "libc.so", symbols[i], new_func[i], on_hooked, nullptr);
        if (stub && g_hook_count < MAX_HOOK_COUNT) {
            g_hook_stubs[g_hook_count++] = stub;
        }
    }
    return 0;
}

extern "C" int stop_hook() {
    for (int i = 0; i < g_hook_count; i++) {
        if (g_hook_stubs[i]) {
            bytehook_unhook(g_hook_stubs[i]);
            g_hook_stubs[i] = nullptr;
        }
    }
    g_hook_count = 0;
    g_orig_malloc = nullptr; g_orig_realloc = nullptr; g_orig_calloc = nullptr;
    g_orig_free = nullptr; g_orig_mmap = nullptr; g_orig_munmap = nullptr;
    LOG("Hook 卸载完成！");
    return 0;
}
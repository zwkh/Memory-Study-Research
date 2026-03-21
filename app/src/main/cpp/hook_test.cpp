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
            if (strstr(info.dli_sname, "logic_1_process")) return LogicID::LOGIC_1;
            if (strstr(info.dli_sname, "logic_2_process")) return LogicID::LOGIC_2;
            if (strstr(info.dli_sname, "logic_3_process")) return LogicID::LOGIC_3;
            if (strstr(info.dli_sname, "logic_4_process")) return LogicID::LOGIC_4;
        }
    }
    return LogicID::LOGIC_UNKNOWN;
}

// SIGSEGV 信号拦截器
static void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    uintptr_t fault_addr = (uintptr_t)info->si_addr;
    uintptr_t page_base = fault_addr & ~(G_PAGE_SIZE - 1); // 找到所属的内存页起址

    LOG("fwiqwhfiwnifncwoenc----------------------");
    MonitorBlock block;
    // 多线程安全点：GetMonitorBlock 内部已加锁，且做的是值拷贝！
    LOG("ndiansdias %d", MonitorManager::GetInstance().GetMonitorBlock(page_base, block));
    if (MonitorManager::GetInstance().GetMonitorBlock(page_base, block)) {

        uint32_t offset = fault_addr - page_base;

        // 策略 A：如果开启了成员监控，则计算偏移量
        if (block.monitor_type & MonitorType::MEMBER) {
            LOG("mo--------");
            MonitorManager::GetInstance().UpdateMemberHot(page_base, offset);
        }

        // 策略 B：如果开启了共享监控，则抓栈溯源
        if (block.monitor_type & MonitorType::SHARE) {
            LOG("mo1--------------");
            uintptr_t frames[15];
            BacktraceState state = {frames, frames + 15};
            _Unwind_Backtrace(unwind_cb, &state);
            size_t frame_count = state.current - frames;

            LogicID logic = IdentifyLogicFromStack(frames, frame_count);
            MonitorManager::GetInstance().UpdateLogicAccess(page_base, logic);
        }

        // 放开权限，让触发崩溃的业务代码能够继续执行
        mprotect((void*)page_base, block.size, PROT_READ | PROT_WRITE);
        return;
    }

    // 非隔离页，交给系统兜底处理
    if (old_sa.sa_flags & SA_SIGINFO) old_sa.sa_sigaction(sig, info, ucontext);
    else if (old_sa.sa_handler != SIG_DFL && old_sa.sa_handler != SIG_IGN) old_sa.sa_handler(sig);
}

// malloc 接管与内存隔离
void* my_malloc(size_t size) {
    void* result = nullptr;
    bool hook = false;
    auto metas = PendingMonitor::GetInstance().GetStructMetas();
    LOG("hhhhhhhhhh %d", metas.size());

    bool need_hook = false;
    if (!metas.empty()) {

        for (auto& meta : metas) {
            if (size != meta.struct_size) continue;
            need_hook = true;
            // 不管业务申请 24 还是 1024 字节，统一向上取整到一页(4KB)来进行高压电隔离
            size_t alloc_size = (size + G_PAGE_SIZE - 1) & ~(G_PAGE_SIZE - 1);
            void* page_ptr = mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

            if (page_ptr != MAP_FAILED) {
                MonitorBlock block{};
                block.address = (uintptr_t)page_ptr;
                block.size = alloc_size;
                block.req_size = size;       // 记录真实大小防越界
                block.is_monitored = true;   // 让后台线程来巡逻
                block.monitor_type = MonitorType::BOTH;
                block.struct_meta = meta;

                MonitorManager::GetInstance().AddMonitorBlock(block);
                mprotect(page_ptr, alloc_size, PROT_NONE); // 上锁

                result = page_ptr;
                LOG("成功接管自定义对象，真实大小: %zu，分配至隔离页: %p", size, result);

                char backtrace[1024]; get_backtrace(backtrace, sizeof(backtrace));
                write_memory_log(TYPE_MALLOC, result, size, backtrace);
            }
        }

    }

    // 如果当前线程没挂号（绝大多数情况），或者 mmap 失败，老老实实走系统原生分配
    if (!need_hook) {
        result = g_orig_malloc(size);

        // （可选）记录原生分配日志
        // char backtrace[1024]; get_backtrace(backtrace, sizeof(backtrace));
        // write_memory_log(TYPE_MALLOC, result, size, backtrace);
    }

    return result;
}

void my_free(void* ptr) {
    if (!ptr) return;

    MonitorBlock block;
    // 检查：这块内存是不是我们刚才偷偷用 mmap 搞出来的？
    if (MonitorManager::GetInstance().GetMonitorBlock((uintptr_t)ptr, block)) {
        MonitorManager::GetInstance().RemoveMonitorBlock((uintptr_t)ptr);

        // 关键步骤：先解开 mprotect 的锁，否则 munmap 时操作系统可能会内核崩溃！
        mprotect(ptr, block.size, PROT_READ | PROT_WRITE);
        munmap(ptr, block.size);
        write_memory_log(TYPE_FREE, ptr, 0, nullptr);
        LOG("释放自定义受控隔离页: %p", ptr);
    } else {
        // 原生的内存，乖乖交还给系统的 Scudo 分配器
        g_orig_free(ptr);
        write_memory_log(TYPE_FREE, ptr, 0, nullptr);
    }
}

// ==========================================
// 其他内存函数的 Hook (保持原有逻辑，但加上沙盒保护)
// ==========================================
void* my_realloc(void* ptr, size_t size) {
    if (!ptr) return my_malloc(size); // realloc(NULL, size) 等价于 malloc
    if (size == 0) { my_free(ptr); return nullptr; } // realloc(ptr, 0) 等价于 free

    MonitorBlock old_block;
    // 检查：业务试图扩容的这块旧内存，是不是我们的隔离页？
    if (MonitorManager::GetInstance().GetMonitorBlock((uintptr_t)ptr, old_block)) {

        // 1. 解开旧页的锁，因为稍后我们要读它里面的数据
        mprotect(ptr, old_block.size, PROT_READ | PROT_WRITE);

        // 2. 为业务申请新内存（可能也是隔离的，也可能是原生的，my_malloc 自己会判断）
        void* new_ptr = my_malloc(size);

        char backtrace[1024]; get_backtrace(backtrace, sizeof(backtrace));
        write_memory_log(TYPE_REALLOC, new_ptr, size, backtrace);
        if (new_ptr) {
            // 3. 搬运数据
            // 注意：如果新内存也被隔离了，它现在处于 PROT_NONE，我们必须临时解开新锁才能写入！
            MonitorBlock new_block;
            bool is_new_monitored = MonitorManager::GetInstance().GetMonitorBlock((uintptr_t)new_ptr, new_block);
            if (is_new_monitored) {
                mprotect(new_ptr, new_block.size, PROT_READ | PROT_WRITE);
            }

            // 防越界拷贝：只拷贝旧页中真实属于业务的数据大小
            size_t copy_size = (old_block.req_size < size) ? old_block.req_size : size;
            memcpy(new_ptr, ptr, copy_size);

            // 重新挂上新页的锁
            if (is_new_monitored) {
                mprotect(new_ptr, new_block.size, PROT_NONE);
            }
        }

        // 4. 彻底销毁旧的隔离页
        MonitorManager::GetInstance().RemoveMonitorBlock((uintptr_t)ptr);
        munmap(ptr, old_block.size);

        return new_ptr;
    }

    // 如果旧内存不是隔离页，正常交给系统扩容
    void* address = g_orig_realloc(ptr, size);
    char backtrace[1024]; get_backtrace(backtrace, sizeof(backtrace));
    write_memory_log(TYPE_REALLOC, address, size, backtrace);
    return address;
}

void* my_calloc(size_t size, size_t per_size) {
    uint64_t ts = get_current_time_ms();
    void *address = g_orig_calloc(size, per_size);
    char backtrace[1024];
    get_backtrace(backtrace, sizeof(backtrace));
    size_t total = size * per_size;
    write_memory_log(TYPE_CALLOC, address, total, backtrace);
    return address;
}

void* my_mmap(void* address, size_t length, int prot, int flags, int fd, off_t offset) {
    uint64_t ts = get_current_time_ms();
    void* address_res = g_orig_mmap(address, length, prot, flags, fd, offset);
    char backtrace[1024];
    get_backtrace(backtrace, sizeof(backtrace));
    write_memory_log(TYPE_MMAP, address_res, length, backtrace);
    return address_res;
}

int my_munmap(void* address, size_t length) {
    uint64_t ts = get_current_time_ms();
    int res = g_orig_munmap(address, length);
    write_memory_log(TYPE_MUNMAP, address, 0, nullptr);
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
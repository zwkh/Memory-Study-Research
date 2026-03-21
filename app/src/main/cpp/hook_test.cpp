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
#include "elf_reader.h"

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "hook_test", __VA_ARGS__)

#define TYPE_MALLOC 1
#define TYPE_REALLOC 2
#define TYPE_CALLOC 3
#define TYPE_FREE 4
#define TYPE_MMAP 5
#define TYPE_MUNMAP 6

// 原函数指针
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
static size_t g_page_size = sysconf(_SC_PAGESIZE);
static struct sigaction old_sa;

// log保存路径
#define LOG_FILE_PATH "/storage/emulated/0/Android/data/com.example.application/files/mem_reg.log"
#define LOG_BUF_SIZE 4096

static uint64_t GetTimeStamp() {
    timeval tv{};
    gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void WriteLog(int type, void* address, size_t size, const char* stack) {
    uint64_t ts = GetTimeStamp();
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

static _Unwind_Reason_Code UnwindCallBack(_Unwind_Context* ctx, void* arg) {
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

static void GetBackTrace(char* buf, size_t buf_size) {
    if (!buf || buf_size == 0) {
        buf[0] = '\0';
        return;
    }
    uintptr_t frames[MAX_BACKTRACE_DEPTH];
    BacktraceContext context = { .frames = frames, .count = 0, .max_count = MAX_BACKTRACE_DEPTH };

    _Unwind_Backtrace(UnwindCallBack, &context);

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
static _Unwind_Reason_Code UnwindLogic(struct _Unwind_Context* context, void* arg) {
    BacktraceState* state = static_cast<BacktraceState*>(arg);
    uintptr_t pc = _Unwind_GetIP(context);
    if (pc) {
        if (state->current == state->end) return _URC_END_OF_STACK;
        *state->current++ = pc;
    }
    return _URC_NO_REASON;
}

static LogicID IdentifyLogicFromStack(uintptr_t* frames, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        Dl_info info;
        if (dladdr((void*)frames[i], &info) && info.dli_sname) {
            if (strstr(info.dli_sname, "Logic1")) return LogicID::LOGIC_1;
            if (strstr(info.dli_sname, "Logic2")) return LogicID::LOGIC_2;
            if (strstr(info.dli_sname, "Logic3")) return LogicID::LOGIC_3;
            if (strstr(info.dli_sname, "Logic4")) return LogicID::LOGIC_4;
        }
    }
    return LogicID::LOGIC_UNKNOWN;
}

// SIGSEGV 信号拦截器
static void SigsegvHandler(int sig, siginfo_t *info, void *ucontext) {
    uintptr_t fault_addr = (uintptr_t)info->si_addr;
    uintptr_t page_base = fault_addr & ~(g_page_size - 1); // 找到所属的内存页起址
    
    MonitorBlock block;
    if (MonitorManager::GetInstance().GetMonitorBlock(page_base, block)) {

        uint32_t offset = fault_addr - page_base;
        // 策略 A：如果开启了成员监控，则计算偏移量
        if (block.monitor_type & MonitorType::MEMBER) {
            MonitorManager::GetInstance().UpdateMemberHot(page_base, offset);
        }
        // 策略 B：如果开启了共享监控，则抓栈溯源
        if (block.monitor_type & MonitorType::SHARE) {
            uintptr_t frames[15];
            BacktraceState state = {frames, frames + 15};
            _Unwind_Backtrace(UnwindLogic, &state);
            size_t frame_count = state.current - frames;
            LogicID logic = IdentifyLogicFromStack(frames, frame_count);
            MonitorManager::GetInstance().UpdateLogicAccess(page_base, logic);
        }
        
        mprotect((void*)page_base, block.size, PROT_READ | PROT_WRITE);
        return;
    }
    // 非隔离页，交给系统处理
    if (old_sa.sa_flags & SA_SIGINFO) old_sa.sa_sigaction(sig, info, ucontext);
    else if (old_sa.sa_handler != SIG_DFL && old_sa.sa_handler != SIG_IGN) old_sa.sa_handler(sig);
}

// malloc 代理函数
static void* MyMalloc(size_t size) {
    void* result = nullptr;
    bool hook = false;
    auto metas = PendingMonitor::GetInstance().GetStructMetas();

    bool need_hook = false;
    if (!metas.empty()) {
        for (auto& meta : metas) {
            if (size != meta.struct_size) continue;
            need_hook = true;
            // 统一申请到一整页（4KB）上，并禁止访问
            size_t alloc_size = (size + g_page_size - 1) & ~(g_page_size - 1);
            void* page_ptr = mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

            if (page_ptr != MAP_FAILED) {
                MonitorBlock block{};
                block.address = (uintptr_t)page_ptr;
                block.size = alloc_size;
                block.req_size = size;       // 记录真实大小防越界
                block.is_monitored = true;   // 让后台线程刷新页面权限
                block.monitor_type = MonitorType::BOTH;
                block.struct_meta = meta;

                MonitorManager::GetInstance().AddMonitorBlock(block);
                mprotect(page_ptr, alloc_size, PROT_NONE); // 上锁
                result = page_ptr;
                LOG("成功接管自定义对象，真实大小: %zu，分配至隔离页: %p", size, result);
                char backtrace[1024]; GetBackTrace(backtrace, sizeof(backtrace));
                WriteLog(TYPE_MALLOC, result, size, backtrace);
            }
        }

    }
    
    if (!need_hook) {
        result = g_orig_malloc(size);
        // char backtrace[1024]; GetBackTrace(backtrace, sizeof(backtrace));
        // WriteLog(TYPE_MALLOC, result, size, backtrace);
    }

    return result;
}

static void MyFree(void* ptr) {
    if (!ptr) return;

    MonitorBlock block;
    // 检查是否是被监控的内存
    if (MonitorManager::GetInstance().GetMonitorBlock((uintptr_t)ptr, block)) {
        MonitorManager::GetInstance().RemoveMonitorBlock((uintptr_t)ptr);

        // 解锁释放内存
        mprotect(ptr, block.size, PROT_READ | PROT_WRITE);
        munmap(ptr, block.size);
        WriteLog(TYPE_FREE, ptr, 0, nullptr);
        LOG("释放自定义受控隔离页: %p", ptr);
    } else {
        g_orig_free(ptr);
        WriteLog(TYPE_FREE, ptr, 0, nullptr);
    }
}

static void* MyRealloc(void* ptr, size_t size) {
    if (!ptr) return MyMalloc(size); 
    if (size == 0) { MyFree(ptr); return nullptr; } 

    MonitorBlock old_block;
    if (MonitorManager::GetInstance().GetMonitorBlock((uintptr_t)ptr, old_block)) {
        
        mprotect(ptr, old_block.size, PROT_READ | PROT_WRITE);
        void* new_ptr = MyMalloc(size);
        char backtrace[1024]; GetBackTrace(backtrace, sizeof(backtrace));
        WriteLog(TYPE_REALLOC, new_ptr, size, backtrace);
        if (new_ptr) {
            // 搬运数据
            MonitorBlock new_block;
            bool is_new_monitored = MonitorManager::GetInstance().GetMonitorBlock((uintptr_t)new_ptr, new_block);
            if (is_new_monitored) {
                mprotect(new_ptr, new_block.size, PROT_READ | PROT_WRITE);
            }
            size_t copy_size = (old_block.req_size < size) ? old_block.req_size : size;
            memcpy(new_ptr, ptr, copy_size);
            if (is_new_monitored) {
                mprotect(new_ptr, new_block.size, PROT_NONE);
            }
        }
        
        MonitorManager::GetInstance().RemoveMonitorBlock((uintptr_t)ptr);
        munmap(ptr, old_block.size);

        return new_ptr;
    }
    
    void* address = g_orig_realloc(ptr, size);
    char backtrace[1024]; GetBackTrace(backtrace, sizeof(backtrace));
    WriteLog(TYPE_REALLOC, address, size, backtrace);
    return address;
}

static void* MyCalloc(size_t size, size_t per_size) {
    uint64_t ts = GetTimeStamp();
    void *address = g_orig_calloc(size, per_size);
    char backtrace[1024];
    GetBackTrace(backtrace, sizeof(backtrace));
    size_t total = size * per_size;
    WriteLog(TYPE_CALLOC, address, total, backtrace);
    return address;
}

static void* MyMmap(void* address, size_t length, int prot, int flags, int fd, off_t offset) {
    uint64_t ts = GetTimeStamp();
    void* address_res = g_orig_mmap(address, length, prot, flags, fd, offset);
    char backtrace[1024];
    GetBackTrace(backtrace, sizeof(backtrace));
    WriteLog(TYPE_MMAP, address_res, length, backtrace);
    return address_res;
}

static int MyMunmap(void* address, size_t length) {
    uint64_t ts = GetTimeStamp();
    int res = g_orig_munmap(address, length);
    WriteLog(TYPE_MUNMAP, address, 0, nullptr);
    return res;
}

// 钩子注册与生命周期管理
static void OnHooked(bytehook_stub_t stub, int status, const char* caller, const char* sym, void* new_func, void* orig_func, void* arg) {
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

// 后台持续刷新页面权限
static void StartMonitor() {
    std::thread([]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // 每 100ms 采样一次
            MonitorManager::GetInstance().ReprotectAllBlocks();
        }
    }).detach();
}

extern "C" int StartHook() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = SigsegvHandler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, &old_sa);
    StartMonitor();

    ElfReader::Analyze("libsample.so");

    bytehook_init(BYTEHOOK_MODE_MANUAL, true);

    const char* symbols[] = {"malloc", "realloc", "calloc", "free", "mmap", "munmap"};
    void* new_func[] = {(void*)MyMalloc, (void*)MyRealloc, (void*)MyCalloc,
                        (void*)MyFree, (void*)MyMmap, (void*)MyMunmap};

    for (int i = 0; i < 6; i++) {
        bytehook_stub_t stub = bytehook_hook_single("libsample.so", "libc.so", symbols[i], new_func[i], OnHooked, nullptr);
        if (stub && g_hook_count < MAX_HOOK_COUNT) {
            g_hook_stubs[g_hook_count++] = stub;
        }
    }
    return 0;
}

extern "C" int StopHook() {
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
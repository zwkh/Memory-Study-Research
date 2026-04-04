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
#include <asm-generic/fcntl.h>
#include <fcntl.h>

#include "bytehook.h"
#include "monitor.h"
#include "elf_reader.h"

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "hook_test", __VA_ARGS__)

enum class AllocType : int {
    MALLOC = 1,
    REALLOC = 2,
    CALLOC = 3,
    FREE = 4,
    MMAP = 5,
    MUNMAP = 6
};

constexpr size_t MAX_HOOK_COUNT = 10;
constexpr size_t MAX_BACKTRACE_DEPTH = 20;
constexpr size_t LOG_BUF_SIZE = 4096;
constexpr std::string_view LOG_FILE_PATH = "/storage/emulated/0/Android/data/com.example.application/files/mem_reg.log";
constexpr std::string_view LOG_FILE_PATH_VIS = "/storage/emulated/0/Android/data/com.example.application/files/mem_visit.log";
constexpr std::string_view KERNEL_IDLE_BITMAP = "/sys/kernel/mm/page_idle/bitmap";
constexpr std::string_view PAGEMAP_PATH = "/proc/self/pagemap";

// 原函数指针
using OrigMalloc  = void* (*)(size_t);
using OrigRealloc = void* (*)(void*, size_t);
using OrigCalloc  = void* (*)(size_t, size_t);
using OrigFree    = void  (*)(void*);
using OrigMmap    = void* (*)(void*, size_t, int, int, int, off_t);
using OrigMunmap  = int   (*)(void*, size_t);

struct OrigFunction {
    OrigMalloc  malloc{nullptr};
    OrigRealloc realloc{nullptr};
    OrigCalloc  calloc{nullptr};
    OrigFree    free{nullptr};
    OrigMmap    mmap{nullptr};
    OrigMunmap  munmap{nullptr};
};
static OrigFunction g_orig;

static std::array<bytehook_stub_t, MAX_HOOK_COUNT> g_hook_stubs{};
static std::atomic<int> g_hook_count{0};
static std::atomic<bool> g_kernel_monitor{false};
static std::atomic<bool> g_kernel_refresh{false};

static const size_t g_page_size = sysconf(_SC_PAGESIZE);
static struct sigaction g_old_sa;

// 虚拟地址 -> 物理页帧号
static uint64_t GetPFN(uintptr_t va) {
    int fd = open(PAGEMAP_PATH.data(), O_RDONLY);
    if (fd < 0) return 0;
    uint64_t entry;
    // 每个 entry 8 字节
    if (pread(fd, &entry, 8, (va / g_page_size) * 8) != 8) {
        close(fd); return 0;
    }
    close(fd);
    // 物理页未加载到内存
    LOG("entry----------- %lu", entry);
    if (!(entry & (1ULL << 63))) return 0;
    // 找到PFN
    return entry & ((1ULL << 55) - 1);
}

static bool IsPageIdle(uint64_t pfn) {
    int fd = open(KERNEL_IDLE_BITMAP.data(), O_RDWR);
    LOG("fd------------- %d", fd);
    if (fd < 0) return false;
    uint64_t byte_offset = (pfn / 64) * 8;
    int bit_pos = pfn % 64;
    uint64_t bitmap_val;
    pread(fd, &bitmap_val, 8, byte_offset);
    // 判断该页访问没有
    bool idle = (bitmap_val >> bit_pos) & 1ULL;
    LOG("idle------- %d", idle);
    // 重置
    uint64_t set_val = 1ULL << bit_pos;
    pwrite(fd, &set_val, 8, byte_offset);
    close(fd);
    return idle;
}

static uint64_t GetTimeStamp() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

static void StartIdleMonitor() {
    bool expected = false;
    // 保证线程只启动一次
    if (!g_kernel_monitor.compare_exchange_strong(expected, true)) return;

    std::thread([]() {
        LOG("内核 Idle 独立监控线程已启动");
        while (g_kernel_monitor) {
            // 500毫秒监控一次
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            std::vector<MonitorBlock> all_blocks = MonitorManager::GetInstance().GetAllBlocks();
            if (all_blocks.empty()) continue;
            uint64_t ts = GetTimeStamp();
            FILE* fp = fopen(LOG_FILE_PATH_VIS.data(), "a+");
            if (fp) {
                for (auto& block : all_blocks) {
                    int hot_count = 0;
                    bool has_alloc = false;
                    int total_count = block.size / g_page_size;

                    // 遍历该块内的每一个物理页
                    for (uintptr_t curr = block.address; curr < block.address + block.size; curr += g_page_size) {
                        uint64_t pfn = GetPFN(curr);
                        if (pfn > 0 && !IsPageIdle(pfn)){
                            hot_count++;
                            has_alloc = true;
                        }
                    }
                    // 输出mem_visit.log
                    fprintf(fp, "%" PRIu64 ",%p, has_alloc: %d, total_page: %d, hot_page: %d\n", ts, (void*)block.address, has_alloc, total_count, hot_count);
                }
                fflush(fp);
                fclose(fp);
            } else {
                LOG("打开日志文件失败: %s, 路径: %s", strerror(errno), LOG_FILE_PATH);
            }
        }
        LOG("内核 Idle 独立监控线程已停止");
    }).detach();
}

// 输出mem_reg.log
static void WriteLog(AllocType type, void* address, size_t size, const char* stack) {
    uint64_t ts = GetTimeStamp();
    char log_buf[LOG_BUF_SIZE] = {0};
    snprintf(log_buf, sizeof(log_buf), "%" PRIu64 ",%d,%p,%zu, %s\n", ts, static_cast<int>(type), address, size, stack);

    FILE* fp = fopen(LOG_FILE_PATH.data(), "a+");
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
    auto* context = static_cast<BacktraceContext*>(arg);
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
    auto* state = static_cast<BacktraceState*>(arg);
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
            std::string_view sname(info.dli_sname);
            if (sname.find("Logic1") != std::string_view::npos) return LogicID::LOGIC_1;
            if (sname.find("Logic2") != std::string_view::npos) return LogicID::LOGIC_2;
            if (sname.find("Logic3") != std::string_view::npos) return LogicID::LOGIC_3;
            if (sname.find("Logic4") != std::string_view::npos) return LogicID::LOGIC_4;
        }
    }
    return LogicID::LOGIC_UNKNOWN;
}

// SIGSEGV 信号拦截器
static void SigsegvHandler(int sig, siginfo_t *info, void *ucontext) {
    auto fault_addr = reinterpret_cast<uintptr_t>(info->si_addr);
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
        
        mprotect(reinterpret_cast<void*>(page_base), block.size, PROT_READ | PROT_WRITE);
        return;
    }
    // 非隔离页，交给系统处理
    if (g_old_sa.sa_flags & SA_SIGINFO) g_old_sa.sa_sigaction(sig, info, ucontext);
    else if (g_old_sa.sa_handler != SIG_DFL && g_old_sa.sa_handler != SIG_IGN) g_old_sa.sa_handler(sig);
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
                WriteLog(AllocType::MALLOC, result, size, backtrace);
            }
        }

    }
    
    if (!need_hook) {
        result = g_orig.malloc(size);
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
        WriteLog(AllocType::FREE, ptr, 0, nullptr);
        LOG("释放自定义受控隔离页: %p", ptr);
    } else {
        g_orig.free(ptr);
        // WriteLog(AllocType::FREE, ptr, 0, nullptr);
    }
}

static void* MyRealloc(void* ptr, size_t size) {
    if (!ptr) return MyMalloc(size); 
    if (size == 0) {
        MyFree(ptr);
        return nullptr;
    }

    MonitorBlock old_block;
    if (MonitorManager::GetInstance().GetMonitorBlock((uintptr_t)ptr, old_block)) {
        
        mprotect(ptr, old_block.size, PROT_READ | PROT_WRITE);
        void* new_ptr = MyMalloc(size);
        char backtrace[1024]; GetBackTrace(backtrace, sizeof(backtrace));
        WriteLog(AllocType::REALLOC, new_ptr, size, backtrace);
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
    
    void* address = g_orig.realloc(ptr, size);
    char backtrace[1024]; GetBackTrace(backtrace, sizeof(backtrace));
    WriteLog(AllocType::REALLOC, address, size, backtrace);
    return address;
}

static void* MyCalloc(size_t size, size_t per_size) {
    uint64_t ts = GetTimeStamp();
    void *address = g_orig.calloc(size, per_size);
    char backtrace[1024];
    GetBackTrace(backtrace, sizeof(backtrace));
    size_t total = size * per_size;
    WriteLog(AllocType::CALLOC, address, total, backtrace);
    return address;
}

static void* MyMmap(void* address, size_t length, int prot, int flags, int fd, off_t offset) {
    uint64_t ts = GetTimeStamp();
    void* address_res = g_orig.mmap(address, length, prot, flags, fd, offset);
    char backtrace[1024];
    GetBackTrace(backtrace, sizeof(backtrace));
    WriteLog(AllocType::MMAP, address_res, length, backtrace);
    return address_res;
}

static int MyMunmap(void* address, size_t length) {
    uint64_t ts = GetTimeStamp();
    int res = g_orig.munmap(address, length);
    WriteLog(AllocType::MUNMAP, address, 0, nullptr);
    return res;
}

// 钩子注册与生命周期管理
static void OnHooked(bytehook_stub_t stub, int status, const char* caller, const char* sym, void* new_func, void* orig_func, void* arg) {
    if (status == BYTEHOOK_STATUS_CODE_ORIG_ADDR) {
        std::string_view symbol(sym);
        if (symbol == "malloc") g_orig.malloc = reinterpret_cast<OrigMalloc>(orig_func);
        else if (symbol == "realloc") g_orig.realloc = reinterpret_cast<OrigRealloc>(orig_func);
        else if (symbol == "calloc") g_orig.calloc = reinterpret_cast<OrigCalloc>(orig_func);
        else if (symbol == "free") g_orig.free = reinterpret_cast<OrigFree>(orig_func);
        else if (symbol == "mmap") g_orig.mmap = reinterpret_cast<OrigMmap>(orig_func);
        else if (symbol == "munmap") g_orig.munmap = reinterpret_cast<OrigMunmap>(orig_func);
        LOG("获取原函数地址成功: %s", sym);
    }
}

// 后台持续刷新页面权限
static void StartMonitor() {
    bool expected = false;
    // 保证线程只启动一次
    if (!g_kernel_refresh.compare_exchange_strong(expected, true)) return;

    std::thread([]() {
        LOG("页面刷新线程已启动");
        while (g_kernel_refresh) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // 每 100ms 采样一次
            MonitorManager::GetInstance().ReprotectAllBlocks();
        }
        LOG("页面刷新线程已停止");
    }).detach();
}

extern "C" int StartHook() {
    struct sigaction sa{};
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = SigsegvHandler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, &g_old_sa);
    StartMonitor();
    StartIdleMonitor();

    ElfReader::Analyze("libsample.so");
    bytehook_init(BYTEHOOK_MODE_MANUAL, true);

    const std::array<const char*, 6> symbols = {"malloc", "realloc", "calloc", "free", "mmap", "munmap"};
    const std::array<void*, 6> functions = {
            reinterpret_cast<void*>(MyMalloc), reinterpret_cast<void*>(MyRealloc),
            reinterpret_cast<void*>(MyCalloc), reinterpret_cast<void*>(MyFree),
            reinterpret_cast<void*>(MyMmap),   reinterpret_cast<void*>(MyMunmap)
    };

    for (int i = 0; i < 6; i++) {
        bytehook_stub_t stub = bytehook_hook_single("libsample.so", "libc.so", symbols[i], functions[i], OnHooked, nullptr);
        if (stub && g_hook_count < MAX_HOOK_COUNT) {
            g_hook_stubs[g_hook_count++] = stub;
        }
    }
    return 0;
}

extern "C" int StopHook() {
    g_kernel_monitor = false;
    for (int i = 0; i < g_hook_count; i++) {
        if (g_hook_stubs[i]) {
            bytehook_unhook(g_hook_stubs[i]);
            g_hook_stubs[i] = nullptr;
        }
    }
    g_hook_count = 0;
    g_orig = OrigFunction{};
    LOG("Hook 卸载完成！");
    return 0;
}
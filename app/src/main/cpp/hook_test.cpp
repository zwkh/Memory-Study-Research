#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <android/log.h>
#include <sys/time.h>
#include <unwind.h>
#include "bytehook.h"
#include <unwind.h>
#include <pthread.h>
#include <cerrno>

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "bytehook_hook", __VA_ARGS__)

#define TYPE_MALLOC 1
#define TYPE_REALLOC 2
#define TYPE_CALLOC 3
#define TYPE_FREE 4
#define TYPE_MMAP 5
#define TYPE_MUNMAP 6

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

// log保存路径
#define LOG_FILE_PATH "/storage/emulated/0/Android/data/com.example.application/files/mem_reg.log"
// 日志缓冲区
#define LOG_BUF_SIZE 4096

// 获取时间戳
static uint64_t get_current_time_ms() {
    timeval tv{};
    gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// 参数：操作类型，内存地址，申请大小，栈调用地址
void write_memory_log(int type, void* address, size_t size, const char* stack) {

    uint64_t ts = get_current_time_ms();
    char log_buf[LOG_BUF_SIZE] = {0};
    // 日志格式：时间,类型,地址,大小,栈调用地址
    snprintf(log_buf, sizeof(log_buf),
             "%" PRIu64 ",%d,%p,%zu, %s\n",
             ts, type, address, size, stack);

    // 写入LOG
    FILE* fp = fopen(LOG_FILE_PATH, "a+");
    if (fp != nullptr) {
        fwrite(log_buf, 1, strlen(log_buf), fp);
        fflush(fp);
        fclose(fp);
    } else {
        LOG("打开日志文件失败: %s, 路径: %s", strerror(errno), LOG_FILE_PATH);
    }

}

// 栈回溯地址结构体
struct BacktraceContext {
    uintptr_t* frames;   // 栈帧地址数组
    size_t count;        // 当前已获取的栈帧数
    size_t max_count;    // 最大栈帧数
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

// 获取栈调用地址
static void get_backtrace(char* buf, size_t buf_size) {
    if (!buf || buf_size == 0) {
        buf[0] = '\0';
        return;
    }
    uintptr_t frames[MAX_BACKTRACE_DEPTH];
    BacktraceContext context = {
            .frames = frames,
            .count = 0,
            .max_count = MAX_BACKTRACE_DEPTH
    };

    // 执行系统栈回溯
    _Unwind_Backtrace(unwind_callback, &context);

    size_t offset = 0;
    for (size_t i = 0; i < context.count; i++) {
        if (offset >= buf_size - 30) break;
        int len = snprintf(buf + offset, buf_size - offset,
                           "0x%" PRIxPTR "%s",
                           frames[i],
                           (i < context.count - 1) ? "," : "");
        offset += len;
    }
    buf[offset] = '\0';
}

// hook 函数部分
void* my_malloc(size_t size) {
    uint64_t ts = get_current_time_ms();
    void* address = g_orig_malloc(size);
    char backtrace[1024];
    get_backtrace(backtrace, sizeof(backtrace));
    write_memory_log(TYPE_MALLOC, address, size, backtrace);
    LOG("%" PRIu64 ",%d,%p,%zu,%s", ts, TYPE_MALLOC, address,size, backtrace);
    return address;
}

void* my_realloc(void* ptr, size_t size) {
    uint64_t ts = get_current_time_ms();
    void* address = g_orig_realloc(ptr, size);
    char backtrace[1024];
    get_backtrace(backtrace, sizeof(backtrace));
    write_memory_log(TYPE_REALLOC, address, size, backtrace);
    LOG("%" PRIu64 ",%d,%p,%zu,%s", ts, TYPE_REALLOC, address, size, backtrace);
    return address;
}

void* my_calloc(size_t size, size_t per_size) {
    uint64_t ts = get_current_time_ms();
    void* address = g_orig_calloc(size, per_size);
    char backtrace[1024];
    get_backtrace(backtrace, sizeof(backtrace));
    size_t total = size * per_size;
    write_memory_log(TYPE_CALLOC, address, total, backtrace);
    LOG("%" PRIu64 ",%d,%p,%zu,%s", ts, TYPE_CALLOC, address, total, backtrace);
    return address;
}

void my_free(void* ptr) {
    uint64_t ts = get_current_time_ms();
    g_orig_free(ptr);
    write_memory_log(TYPE_FREE, ptr, 0, nullptr);
    LOG("%" PRIu64 ",%d,%p", ts, TYPE_FREE, ptr);
}

void* my_mmap(void* address, size_t length, int prot, int flags, int fd, off_t offset) {
    uint64_t ts = get_current_time_ms();
    void* address_res = g_orig_mmap(address, length, prot, flags, fd, offset);
    char backtrace[1024];
    get_backtrace(backtrace, sizeof(backtrace));
    write_memory_log(TYPE_MMAP, address, length, backtrace);
    LOG("%" PRIu64 ",%d,%p,%zu,%s", ts, TYPE_MMAP, address, length, backtrace);
    return address;
}

int my_munmap(void* address, size_t length) {
    uint64_t ts = get_current_time_ms();
    int res = g_orig_munmap(address, length);
    write_memory_log(TYPE_MUNMAP, address, 0, nullptr);
    LOG("%" PRIu64 ",%d,%p", ts, TYPE_MMAP, address);
    return res;
}

// Hook回调
static void on_hooked(bytehook_stub_t stub, int status,
                      const char* caller, const char* sym,
                      void* new_func, void* orig_func, void* arg) {
    if (status == BYTEHOOK_STATUS_CODE_ORIG_ADDR) {
        if (strcmp(sym, "malloc") == 0) g_orig_malloc = (orig_malloc_t)orig_func;
        else if (strcmp(sym, "realloc") == 0) g_orig_realloc = (orig_realloc_t)orig_func;
        else if (strcmp(sym, "calloc") == 0) g_orig_calloc = (orig_calloc_t)orig_func;
        else if (strcmp(sym, "free") == 0) g_orig_free = (orig_free_t)orig_func;
        else if (strcmp(sym, "mmap") == 0) g_orig_mmap = (orig_mmap_t)orig_func;
        else if (strcmp(sym, "munmap") == 0) g_orig_munmap = (orig_munmap_t)orig_func;
        LOG("获取原函数地址: %s", sym);
    }
    LOG("Hook状态: %d, 符号: %s", status, sym);
}

// 启动Hook
extern "C" int start_hook() {
    bytehook_init(BYTEHOOK_MODE_MANUAL, true);

    const char* symbols[] = {"malloc", "realloc", "calloc", "free", "mmap", "munmap"};
    void* new_func[] = {(void*)my_malloc, (void*)my_realloc, (void*)my_calloc,
                         (void*)my_free, (void*)my_mmap, (void*)my_munmap};
    int count = sizeof(symbols)/sizeof(symbols[0]);

    for (int i = 0; i < count; i++) {
        bytehook_stub_t stub = bytehook_hook_single(
                "libsample.so",
                "libc.so",
                symbols[i],
                new_func[i],
                on_hooked,
                nullptr
        );
        if (!stub) {
            LOG("Hook %s 失败", symbols[i]);
            return -1;
        }
        if (g_hook_count < MAX_HOOK_COUNT) {
            g_hook_stubs[g_hook_count++] = stub;
        }
        LOG("Hook %s 成功", symbols[i]);
    }
    LOG("Hook启动完成！");
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
    g_orig_malloc = nullptr;
    g_orig_realloc = nullptr;
    g_orig_calloc = nullptr;
    g_orig_free = nullptr;
    g_orig_mmap = nullptr;
    g_orig_munmap = nullptr;
    LOG("Hook卸载完成！");
    return 0;
}
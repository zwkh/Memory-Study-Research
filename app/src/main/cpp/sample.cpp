#include "sample.h"
#include <android/log.h>
#include <cstring>
#include <malloc.h>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>
#include <dlfcn.h>
#include "monitor.h"

#define TAG "bytehook_sample"

#pragma clang optimize off

struct TestStruct {
    char name[16];
    int id;
    char data[1004];
};

//extern "C" void test_malloc() {
//    __android_log_print(ANDROID_LOG_INFO, TAG, "test malloc");
//    size_t size = 1024;
//    TestStruct* address = (TestStruct*) malloc(sizeof(TestStruct));
//    __android_log_print(ANDROID_LOG_INFO, TAG, "test malloc：%p", address);
//    address->id = 100;
//    free(address);
//    __android_log_print(ANDROID_LOG_INFO, TAG, "test free: %p", address);
//}

// ==========================================
// 4 个不同逻辑的线程
// ==========================================
extern "C" void logic_1_process(void* mem) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    __android_log_print(ANDROID_LOG_INFO, TAG, "逻辑 1 执行：访问 name");
    ((TestStruct*)mem)->name[0] = 'A';
}

extern "C" void logic_2_process(void* mem) {
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    __android_log_print(ANDROID_LOG_INFO, TAG, "逻辑 2 执行：访问 id");
    ((TestStruct*)mem)->id = 100;
}

extern "C" void logic_3_process(void* mem) {
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    __android_log_print(ANDROID_LOG_INFO, TAG, "逻辑 3 执行：访问 data");
    ((TestStruct*)mem)->data[0] = 'X';
}

extern "C" void logic_4_process(void* mem) {
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    __android_log_print(ANDROID_LOG_INFO, TAG, "逻辑 4 执行：我只打酱油，绝不碰共享内存！");
    // 什么都不做
}

// ==========================================
// 触发总入口
// ==========================================
extern "C" void test_all_features() {
    __android_log_print(ANDROID_LOG_INFO, TAG, "--- 开始终极双开监控测试 (MEMBER + SHARE) ---");

    StructMeta test_meta = {
            "TestStruct", sizeof(TestStruct), {
                    {"name", 0, 15, false},
                    {"id", 16, 19, false},
                    {"data", 20, 1023, false}
            }
    };

    // 【一键双开】：同时开启 MEMBER 和 SHARE 监控！
    // APM_API::MarkNextAlloc(MonitorType::BOTH, LogicID::LOGIC_UNKNOWN, test_meta);
    void* handle = dlopen("libhacker.so", RTLD_NOW);
    if (handle) {
        // 定义函数指针类型
        typedef void (*RegisterFunc)(const StructMeta*);
        // 找到我们刚才导出的那个大门函数
        RegisterFunc reg_func = (RegisterFunc)dlsym(handle, "RegisterMonitorStruct");

        if (reg_func) {
            // 把数据传过去！
            reg_func(&test_meta);
        } else {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "找不到 RegisterMonitorStruct 符号");
        }
        dlclose(handle);
    }
    // 分配内存
    TestStruct* shared_obj = (TestStruct*) malloc(sizeof(TestStruct));

    // 启动 4 个线程，把这个对象扔给它们共享
    std::thread t1(logic_1_process, shared_obj);
    std::thread t2(logic_2_process, shared_obj);
    std::thread t3(logic_3_process, shared_obj);
    std::thread t4(logic_4_process, shared_obj);

    t1.join();
    t2.join();
    t3.join();
    t4.join();

    free(shared_obj);
    __android_log_print(ANDROID_LOG_INFO, TAG, "--- 测试结束 ---");
}

extern "C" void test_calloc() {
    __android_log_print(ANDROID_LOG_INFO, TAG, "test calloc");
    size_t size = 24;
    void* address = calloc(size, sizeof(int));
    __android_log_print(ANDROID_LOG_INFO, TAG, "calloc address: %p", address);
    free(address);
    __android_log_print(ANDROID_LOG_INFO, TAG, "test free: %p", address);
}

extern "C" void test_realloc() {
    __android_log_print(ANDROID_LOG_INFO, TAG, "test realloc");
    int* address = (int*)malloc(2 * sizeof(int));
    int* new_address = (int*)realloc(address, 5 * sizeof(int));
    __android_log_print(ANDROID_LOG_INFO, TAG, "test realloc：%p", new_address);
    free(new_address);
    __android_log_print(ANDROID_LOG_INFO, TAG, "test free: %p", new_address);
}

extern "C" void test_mmap() {
    __android_log_print(ANDROID_LOG_INFO, TAG, "test mmap");
    size_t size = 512;
    void* address = mmap(nullptr, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (address != MAP_FAILED) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "test mmap address: %p", address);
    }
    munmap(address, size);
    __android_log_print(ANDROID_LOG_INFO, TAG, "test munmap address: %p", address);
}

extern "C" void test_sample(){
    // test_malloc();
    test_all_features();
    test_calloc();
    test_realloc();
    test_mmap();
}

#pragma clang optimize on
#include "sample.h"
#include <android/log.h>
#include <cstring>
#include <malloc.h>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>
#include <dlfcn.h>
#include "monitor.h"

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "hook_sample", __VA_ARGS__)

#pragma clang optimize off

struct TestStruct {
    char name[16];
    int id;
    char data[1004];
};

extern "C" void TestMalloc() {
    LOG("test malloc");
    size_t size = 512;
    void* address = malloc(size);
    LOG("test malloc：%p", address);
    free(address);
    LOG("test free: %p", address);
}

// 4个逻辑
extern "C" void Logic1(void* mem) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    LOG("逻辑 1 执行：访问 name");
    ((TestStruct*)mem)->name[0] = 'A';
}

extern "C" void Logic2(void* mem) {
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    LOG("逻辑 2 执行：访问 id");
    ((TestStruct*)mem)->id = 100;
}

extern "C" void Logic3(void* mem) {
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    LOG("逻辑 3 执行：访问 data");
    ((TestStruct*)mem)->data[0] = 'X';
}

extern "C" void Logic4(void* mem) {
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    LOG("逻辑 4 执行：不访问内存");
}

// 
extern "C" void TestStructVisit() {
    LOG("开启监控测试 (MEMBER + SHARE)");
    StructMeta test_meta = {
            "TestStruct", sizeof(TestStruct), {
                    {"name", 0, 15, false},
                    {"id", 16, 19, false},
                    {"data", 20, 1023, false}
            }
    };
    
    // 动态注入监控信息
    void* handle = dlopen("libhacker.so", RTLD_NOW);
    if (handle) {
        typedef void (*RegisterFunc)(const StructMeta*);
        auto reg_func = reinterpret_cast<RegisterFunc>(dlsym(handle, "RegisterMonitorStruct"));
        if (reg_func) {
            reg_func(&test_meta);
        } else {
            LOG("找不到 RegisterMonitorStruct 符号");
        }
        dlclose(handle);
    }
    auto* test_demo = static_cast<TestStruct*>(malloc(sizeof(TestStruct)));
    std::array<TestStruct*, 4> test{};
    for (int i=0; i<4; ++i){
        auto* test_demo_t = static_cast<TestStruct*>(malloc(sizeof(TestStruct)));
        test[i] = test_demo_t;
    }
    // 启动 4 个线程，访问结构成员
    std::thread t1(Logic1, test_demo);
    std::thread t2(Logic2, test_demo);
    std::thread t3(Logic3, test_demo);
    std::thread t4(Logic4, test_demo);

    t1.join();
    t2.join();
    t3.join();
    t4.join();
    free(test_demo);
    for (auto & i : test){
        free(reinterpret_cast<void*>(i));
    }
}

extern "C" void TestCalloc() {
    LOG("test calloc");
    size_t size = 24;
    void* address = calloc(size, sizeof(int));
    LOG("calloc address: %p", address);
    free(address);
    LOG("test free: %p", address);
}

extern "C" void TestRealloc() {
    LOG("test realloc");
    int* address = (int*)malloc(2 * sizeof(int));
    int* new_address = (int*)realloc(address, 5 * sizeof(int));
    LOG("test realloc：%p", new_address);
    free(new_address);
    LOG("test free: %p", new_address);
}

extern "C" void TestMmap() {
    LOG("test mmap");
    size_t size = 512;
    void* address = mmap(nullptr, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (address != MAP_FAILED) {
        LOG("test mmap address: %p", address);
    }
    munmap(address, size);
    LOG("test munmap address: %p", address);
}

extern "C" void TestSample(){
    TestMalloc();
    TestStructVisit();
    TestCalloc();
    TestRealloc();
    TestMmap();
}

#pragma clang optimize on
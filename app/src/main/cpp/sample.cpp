#include "sample.h"
#include <android/log.h>
#include <cstring>
#include <malloc.h>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>

#define TAG "bytehook_sample"

#pragma clang optimize off

struct TestStruct {
    char name[16];
    int id;
    char data[1004];
};

//extern "C" void test_malloc() {
//    __android_log_print(ANDROID_LOG_INFO, TAG, "test malloc");
//    // size_t size = 1024;
//    TestStruct* address = (TestStruct*) malloc(sizeof(TestStruct));
//    __android_log_print(ANDROID_LOG_INFO, TAG, "test malloc：%p", address);
//    address->id = 100;
//    free(address);
//    __android_log_print(ANDROID_LOG_INFO, TAG, "test free: %p", address);
//}

// ==========================================
// 模拟业务逻辑函数
// ==========================================
extern "C" void logic_A_process(void* shared_mem) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "逻辑A开始执行 (预期不访问共享内存)");
    // 逻辑 A 假装自己很忙，但就是不碰 shared_mem
    usleep(500000);
}

extern "C" void logic_B_process(void* shared_mem) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "逻辑B开始执行 (预期访问共享内存)");
    // 逻辑 B 访问了共享内存！
    int* ptr = (int*)shared_mem;
    int val = ptr[0]; // 触发读操作
    usleep(500000);
}

// ==========================================
// 触发所有测试的入口函数
// ==========================================
extern "C" void test_all_features() {
    // ---------------------------------------------------
    // 场景一：结构体成员精细化监控 (需求 1 & 2)
    // ---------------------------------------------------
    __android_log_print(ANDROID_LOG_INFO, TAG, "--- 开始测试结构体成员监控 ---");
    // 这里调用 malloc，实际上会跑到我们的 my_malloc 里去
    TestStruct* address = (TestStruct*) malloc(sizeof(TestStruct));

    // 业务代码给 id 赋值。注意：id 的偏移量是 16。
    // 这行代码在 CPU 执行时，会因为没有权限直接触发 SIGSEGV！
    address->id = 100;

    sleep(1);
    // 业务代码给 data 赋值。偏移量是 20。
    address->data[0] = 'X';

    free(address);

    // ---------------------------------------------------
    // 场景二：多逻辑共享内存监控 (需求 3)
    // ---------------------------------------------------
    __android_log_print(ANDROID_LOG_INFO, TAG, "--- 开始测试共享页逻辑归属 ---");
    // 假设申请一页 4096 字节当共享内存
    void* shared_page = malloc(4096);

    // 丢给两个线程去跑
    std::thread t1(logic_A_process, shared_page);
    std::thread t2(logic_B_process, shared_page);

    t1.join();
    t2.join();

    free(shared_page);
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
    size_t size = 1024;
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
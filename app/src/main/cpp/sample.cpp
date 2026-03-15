#include "sample.h"
#include <android/log.h>
#include <cstring>
#include <malloc.h>
#include <sys/mman.h>

#define TAG "bytehook_sample"

#pragma clang optimize off
extern "C" void test_malloc() {
    __android_log_print(ANDROID_LOG_INFO, TAG, "test malloc");
    size_t size = 1024;
    void* address = malloc(size);
    __android_log_print(ANDROID_LOG_INFO, TAG, "test malloc：%p", address);
    free(address);
    __android_log_print(ANDROID_LOG_INFO, TAG, "test free: %p", address);
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
    test_malloc();
    test_calloc();
    test_realloc();
    test_mmap();
}

#pragma clang optimize on
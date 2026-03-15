#include <jni.h>
#include "hook_test.h"
#include <dlfcn.h>

#define JNI_VERSION JNI_VERSION_1_6
#define JNI_CLASS "com/example/application/NativeHacker"

static jint nativeStartHook(JNIEnv *env, jobject thiz) {
    return start_hook();
}

static jint nativeStopHook(JNIEnv *env, jobject thiz) {
    return stop_hook();
}

static void* libsample_handle = nullptr;
typedef void (*test_sample_t)();
static test_sample_t test_sample = nullptr;

static void hacker_jni_do_dlopen(JNIEnv* env, jobject thiz) {
    (void)env;
    (void)thiz;

    if (libsample_handle == nullptr) {
        libsample_handle = dlopen("libsample.so", RTLD_NOW);
        if (libsample_handle != nullptr) {
            // 动态加载，去除编译依赖
            test_sample = (test_sample_t)dlsym(libsample_handle, "test_sample");
        }
    }
}

static void hacker_jni_do_run(JNIEnv* env, jobject thiz) {
    (void)env;
    (void)thiz;

    if (test_sample != nullptr) {
        test_sample();
    }
}

static void hacker_jni_do_dlclose(JNIEnv* env, jobject thiz) {
    (void)env;
    (void)thiz;

    if (libsample_handle != nullptr) {
       test_sample = nullptr;
        dlclose(libsample_handle);
        libsample_handle = nullptr;
    }
}


// JNI 方法注册
static JNINativeMethod g_methods[] = {
        {"startHook", "()I", (void*)nativeStartHook},
        {"stopHook", "()I", (void*)nativeStopHook},
        {"nativeDoDlopen",     "()V",  (void*)hacker_jni_do_dlopen},        // 加载sample
        {"nativeDoRun",        "()V",  (void*)hacker_jni_do_run},           // 运行测试
        {"nativeDoDlclose",    "()V",  (void*)hacker_jni_do_dlclose}        // 卸载sample
};

// JNI 入口
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = nullptr;

    jint result = vm->GetEnv((void **)&env, JNI_VERSION);
    if (result != JNI_OK || env == nullptr) {
        return JNI_ERR;
    }

    jclass cls = env->FindClass(JNI_CLASS);
    if (cls == nullptr) {
        return JNI_ERR;
    }

    jint method_count = sizeof(g_methods) / sizeof(g_methods[0]);
    if (env->RegisterNatives(cls, g_methods, method_count) != JNI_OK) {
        return JNI_ERR;
    }

    return JNI_VERSION;
}



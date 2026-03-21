#include <jni.h>
#include "hook_test.h"
#include <dlfcn.h>

#define JNI_VERSION JNI_VERSION_1_6
#define JNI_CLASS "com/example/application/NativeHacker"

static jint NativeStartHook(JNIEnv *env, jobject thiz) {
    return StartHook();
}

static jint NativeStopHook(JNIEnv *env, jobject thiz) {
    return StopHook();
}

static void* g_sample_handle = nullptr;
typedef void (*test_sample_t)();
static test_sample_t g_test_sample = nullptr;

static void HackerDlopen(JNIEnv* env, jobject thiz) {
    (void) env;
    (void) thiz;

    if (g_sample_handle == nullptr) {
        g_sample_handle = dlopen("libsample.so", RTLD_NOW);
        if (g_sample_handle != nullptr) {
            // 动态加载，去除编译依赖
            g_test_sample = (test_sample_t) dlsym(g_sample_handle, "TestSample");
        }
    }
}

static void HackerRun(JNIEnv* env, jobject thiz) {
    (void)env;
    (void)thiz;

    if (g_test_sample != nullptr) {
        g_test_sample();
    }
}

static void HackerDlclose(JNIEnv* env, jobject thiz) {
    (void)env;
    (void)thiz;

    if (g_sample_handle != nullptr) {
       g_test_sample = nullptr;
        dlclose(g_sample_handle);
        g_sample_handle = nullptr;
    }
}


// JNI 方法注册
static JNINativeMethod g_methods[] = {
        {"startHook", "()I", (void*)NativeStartHook},
        {"stopHook", "()I", (void*)NativeStopHook},
        {"nativeDoDlopen",     "()V",  (void*)HackerDlopen},        // 加载sample
        {"nativeDoRun",        "()V",  (void*)HackerRun},           // 运行测试
        {"nativeDoDlclose",    "()V",  (void*)HackerDlclose}        // 卸载sample
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



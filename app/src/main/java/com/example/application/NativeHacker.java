package com.example.application;

public class NativeHacker {
    static {
        System.loadLibrary("hacker");
        System.loadLibrary("sample");
    }
    public native int startHook();
    public native int stopHook();
    public native void nativeDoDlopen();
    public native void nativeDoRun();
    public native void nativeDoDlclose();
}

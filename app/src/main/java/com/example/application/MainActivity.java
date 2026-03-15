package com.example.application;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import com.example.application.databinding.ActivityMainBinding;

import java.io.File;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "ByteHookDemo";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 私有路径
//        File filesDir = getFilesDir();
//        Log.d(TAG, "files 目录已创建: " + filesDir.getAbsolutePath());
        // 外部路径
        File externalFilesDir = getExternalFilesDir(null);
        // 路径/storage/emulated/0/Android/data/com.example.application/files/
        if (externalFilesDir != null) {
            Log.d(TAG, "外部 files 目录已创建: " + externalFilesDir.getAbsolutePath());
        }

        NativeHacker hacker = new NativeHacker();
        Log.d(TAG, "Step 1：加载 libsample.so");
        hacker.nativeDoDlopen();

        Log.d(TAG, "Step 2：执行 Hook");
        int hookRet = hacker.startHook();
        Log.d(TAG, "Hook 结果: " + (hookRet == 0 ? "成功" : "失败"));

        Log.d(TAG, "Step 3：测试调用 test_sample");
        hacker.nativeDoRun();

        Log.d(TAG, "Step 4：卸载 Hook");
        int unhookRet = hacker.stopHook();
        Log.d(TAG, "Unhook 结果: " + (unhookRet == 0 ? "成功" : "失败"));

        Log.d(TAG, "Step 5：卸载 libsample.so");
        hacker.nativeDoDlclose();
    }
}
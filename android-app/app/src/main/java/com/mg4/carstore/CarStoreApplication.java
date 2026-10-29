package com.mg4.carstore;

import android.app.Application;
import android.os.Handler;
import android.os.Looper;
import android.widget.Toast;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * 全局 Application: 安装「未捕获异常兜底处理器」。
 *
 * 目的: 把任何散落的崩溃 (包括主线程上的) 从「静默闪退」变成
 *   - 写一份 crash.log 到 getExternalFilesDir (方便导出/查看真实堆栈)
 *   - 通过 LogBus 显示到界面日志
 *   - 主线程异常弹 Toast 提示, 且**不让进程直接消失**
 *
 * 这样符合用户诉求: 报错而不是闪退; 同时也为下一轮精确修复保留堆栈。
 */
public class CarStoreApplication extends Application {

    /** 崩溃日志文件名 (在应用私有外部目录下)。 */
    public static final String CRASH_FILE = "crash.log";

    @Override
    public void onCreate() {
        super.onCreate();
        installCrashHandler();
    }

    private void installCrashHandler() {
        final Thread.UncaughtExceptionHandler previous =
                Thread.getDefaultUncaughtExceptionHandler();

        Thread.setDefaultUncaughtExceptionHandler((thread, ex) -> {
            String stack = stackToString(ex);
            // 1) 落盘 —— 即便进程随后退出, 文件也在, 下次可读取
            writeCrashLog(thread, stack);
            // 2) 进日志总线
            LogBus.log("[crash] 线程 " + thread.getName() + " 未捕获异常: " + stack, "ERROR");

            boolean isMain = (Looper.getMainLooper().getThread() == thread);
            if (isMain) {
                // 主线程: 弹提示并**不让进程消失** (用户要的是报错而非闪退)。
                // 不调用 previous.uncaughtException, 否则系统仍会杀进程。
                new Handler(Looper.getMainLooper()).post(() ->
                        Toast.makeText(this,
                                "运行异常: " + firstLine(ex),
                                Toast.LENGTH_LONG).show());
            } else {
                // 子线程: 仅记录, 不阻断进程 (子线程异常本就不该杀进程)
                if (previous != null) {
                    try {
                        previous.uncaughtException(thread, ex);
                    } catch (Throwable ignored) {
                    }
                }
            }
        });
    }

    /** 把本次崩溃写进 crash.log (追加)。外部、内部各写一份, 确保总能找到。 */
    private void writeCrashLog(Thread thread, String stack) {
        String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss",
                Locale.ROOT).format(new Date());
        StringBuilder header = new StringBuilder();
        header.append("==== crash @ ").append(ts).append(" on ")
                .append(thread.getName()).append(" ====\n");
        String content = header.toString() + stack + "\n";
        // 1) 外部存储 (方便用文件管理器直接看): /sdcard/Android/data/com.mg4.carstore/files/
        appendCrash(getExternalFilesDir(null), content);
        // 2) 内部存储 (兜底, 一定可写): /data/data/com.mg4.carstore/files/
        //    取不到时用 adb: run-as com.mg4.carstore cat files/crash.log
        appendCrash(getFilesDir(), content);
    }

    private void appendCrash(File dir, String content) {
        if (dir == null) return;
        try {
            // 某些 ROM 上 getExternalFilesDir 返回的目录尚未创建, 显式 mkdirs 一下
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
            File f = new File(dir, CRASH_FILE);
            try (FileWriter w = new FileWriter(f, true)) {
                w.write(content);
            }
        } catch (Throwable ignored) {
        }
    }

    private static String stackToString(Throwable ex) {
        StringWriter sw = new StringWriter();
        try (PrintWriter pw = new PrintWriter(sw)) {
            ex.printStackTrace(pw);
        }
        return sw.toString();
    }

    private static String firstLine(Throwable ex) {
        String m = ex.getMessage();
        if (m != null && !m.isEmpty()) return m;
        return ex.getClass().getSimpleName();
    }
}

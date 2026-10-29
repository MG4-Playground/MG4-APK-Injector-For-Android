package com.mg4.carstore;

import java.util.ArrayList;
import java.util.List;

/** 全局日志总线: 后台线程写, UI 线程读。 */
public final class LogBus {
    public interface Listener {
        void onLog(String line);
    }

    private static final int MAX = 500;
    private static final List<String> LINES = new ArrayList<>();
    private static Listener listener;

    private LogBus() {}

    public static synchronized void setListener(Listener l) {
        listener = l;
    }

    public static synchronized void log(String msg) {
        log(msg, "INFO");
    }

    /** 带级别前缀的日志 (ERROR / WARN / INFO)。 */
    public static synchronized void log(String msg, String level) {
        String line = ("WARN".equals(level) || "ERROR".equals(level))
                ? "[" + level + "] " + msg
                : msg;
        LINES.add(line);
        while (LINES.size() > MAX) LINES.remove(0);
        Listener l = listener;
        if (l != null) {
            try {
                l.onLog(line);
            } catch (Throwable ignored) {
            }
        }
    }

    public static synchronized List<String> snapshot() {
        return new ArrayList<>(LINES);
    }

    public static synchronized void clear() {
        LINES.clear();
    }
}

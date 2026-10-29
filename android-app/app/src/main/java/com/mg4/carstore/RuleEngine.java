package com.mg4.carstore;

import android.content.Context;
import android.net.Uri;

import org.json.JSONObject;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** 全局单例: 规则 + 目标 APK。 */
public final class RuleEngine {

    private static RuleEngine instance;

    public final RuleStore rules = new RuleStore();
    public volatile java.io.File apkFile;
    public volatile String apkPathLabel = "";

    private RuleEngine() {}

    public static synchronized RuleEngine current() {
        if (instance == null) instance = new RuleEngine();
        return instance;
    }

    /** 从 assets 加载 store_rules.json。 */
    public void loadRules(Context ctx) throws Exception {
        try (InputStream in = ctx.getAssets().open("store_rules.json")) {
            byte[] b = HttpsService.readAll(in);
            JSONObject root = new JSONObject(new String(b, StandardCharsets.UTF_8));
            rules.load(root);
        }
    }

    /** 按 APK 实际信息重算 patch 字段 (体积/包名/应用名)。 */
    public void applyApkInfo(String appName, String packageName, long sizeBytes) {
        if (rules.patch.isEmpty()) return;
        RuleStore.PatchRule r = rules.patch.get(0);
        if (r.set == null) return;
        try {
            long kb = sizeBytes / 1024;
            long mb = sizeBytes / 1048576;
            r.set.put("data.appActualSize", String.valueOf(kb));
            r.set.put("data.appDisplaySize", mb + "M");
            if (appName != null) r.set.put("data.appName", appName);
            if (packageName != null) r.set.put("data.appPackage", packageName);
        } catch (Exception e) {
            LogBus.log("[rules] 更新 APK 信息失败: " + e);
        }
    }

    /** 规则里声明的 APK 路径 -> 实际文件。 */
    public java.io.File resolveApkFile(Context ctx) {
        if (rules.serve.isEmpty()) return null;
        String f = rules.serve.get(0).file;
        if (f == null) return null;
        java.io.File file = new java.io.File(f);
        if (file.isAbsolute() && file.exists()) return file;
        // assets 里的 apk/xxx.apk
        String name = f.startsWith("apk/") ? f.substring(4) : f;
        try (InputStream in = ctx.getAssets().open("apk/" + name)) {
            java.io.File out = new java.io.File(ctx.getFilesDir(), name);
            java.io.FileOutputStream fos = new java.io.FileOutputStream(out);
            byte[] buf = new byte[16384];
            int n;
            while ((n = in.read(buf)) > 0) fos.write(buf, 0, n);
            fos.close();
            return out;
        } catch (Exception e) {
            return null;
        }
    }
}

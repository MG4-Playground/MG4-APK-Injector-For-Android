package com.mg4.carstore;

import android.Manifest;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.List;

/**
 * 主界面。
 *
 * 使用步骤:
 *   1. 手机 root (Magisk 等) —— Android 上劫持车机流量必须有 root
 *   2. 打开手机『移动热点』
 *   3. 车机连接该热点
 *   4. 在本应用选择要安装的 APK
 *   5. 点『启动劫持』, 授权 VPN
 *   6. 在车机上打开应用商店 -> 进入某个应用详情页 -> 应显示你填的名字/体积 -> 点安装
 *
 * 关于 IP 地址:
 *   热点 IP 与 VPN IP 由应用自动探测 (各机型网段不同, 不能写死)。
 *   界面会显示探测结果, 探测不准时可手动覆盖。
 */
public class MainActivity extends AppCompatActivity {

    private static final int REQ_VPN = 1001;

    private Button btnToggle;
    private Button btnPick;
    private Button btnDetect;
    private TextView tvStatus;
    private TextView tvLog;
    private TextView tvNet;
    private EditText etApkName;
    private EditText etHotspotIp;
    private EditText etVpnIp;
    private ScrollView svLog;

    /** 监听服务启动失败广播, 复位按钮并展示错误。 */
    private BroadcastReceiver startFailedReceiver;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private boolean serviceRunning = false;

    private ActivityResultLauncher<String[]> pickLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        btnToggle = findViewById(R.id.btnToggle);
        btnPick = findViewById(R.id.btnPick);
        btnDetect = findViewById(R.id.btnDetect);
        tvStatus = findViewById(R.id.tvStatus);
        tvLog = findViewById(R.id.tvLog);
        tvNet = findViewById(R.id.tvNet);
        etApkName = findViewById(R.id.etApkName);
        etHotspotIp = findViewById(R.id.etHotspotIp);
        etVpnIp = findViewById(R.id.etVpnIp);
        svLog = findViewById(R.id.svLog);

        // APK 文件选择器
        pickLauncher = registerForActivityResult(
                new ActivityResultContracts.OpenDocument(), uri -> {
                    if (uri != null) onApkPicked(uri);
                });
        // 日志总线
        LogBus.setListener(line -> ui.post(() -> {
            tvLog.append(line + "\n");
            svLog.post(() -> svLog.fullScroll(ScrollView.FOCUS_DOWN));
        }));

        // 若上一次运行发生过崩溃, 把 crash.log 里最近的记录显示出来
        showLastCrash();

        // 监听服务启动失败广播 (热点未开启等场景), 把按钮复位并展示错误
        startFailedReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                String err = intent != null ? intent.getStringExtra(
                        CarStoreVpnService.EXTRA_ERROR) : null;
                ui.post(() -> {
                    serviceRunning = false;
                    btnToggle.setText("启动劫持");
                    tvStatus.setText("启动失败: " + (err == null ? "" : err));
                });
            }
        };
        // 注意: Android 13+ (API 33+) 注册非系统广播必须显式声明导出标志,
        // 否则会抛 SecurityException 导致 Activity 无法启动(表现为应用一打开就闪退)。
        registerReceiver(startFailedReceiver,
                new IntentFilter(CarStoreVpnService.ACTION_START_FAILED),
                Context.RECEIVER_NOT_EXPORTED);

        btnPick.setOnClickListener(v ->
                pickLauncher.launch(new String[]{"application/vnd.android.package-archive"}));

        btnDetect.setOnClickListener(v -> detectNetwork());

        btnToggle.setOnClickListener(v -> {
            if (serviceRunning) {
                stopService();
            } else {
                requestVpnAndStart();
            }
        });

        try {
            RuleEngine.current().loadRules(this);
            File def = RuleEngine.current().resolveApkFile(this);
            if (def != null) {
                RuleEngine.current().apkFile = def;
                etApkName.setText(def.getName() + "  (" + def.length() + " bytes)");
            }
        } catch (Exception e) {
            LogBus.log("[ui] 加载规则失败: " + e);
        }

        detectNetwork();
        LogBus.log("[ui] 应用就绪 —— 请先打开手机『移动热点』");
    }

    /** 读取上一次运行写下的 crash.log, 把最近一次崩溃堆栈显示出来。 */
    private void showLastCrash() {
        try {
            java.io.File dir = getExternalFilesDir(null);
            if (dir == null) dir = getFilesDir();
            java.io.File f = new java.io.File(dir, CarStoreApplication.CRASH_FILE);
            if (!f.exists() || f.length() == 0) return;
            // 只读最后 4000 字节, 避免界面刷屏
            long len = f.length();
            long from = Math.max(0, len - 4000);
            try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(f, "r")) {
                raf.seek(from);
                byte[] buf = new byte[(int) (len - from)];
                int n = raf.read(buf);
                if (n > 0) {
                    String tail = new String(buf, 0, n, java.nio.charset.StandardCharsets.UTF_8);
                    LogBus.log("[上次崩溃] 检测到上一次运行异常, 摘要如下:", "ERROR");
                    for (String line : tail.split("\n")) {
                        if (!line.trim().isEmpty()) LogBus.log("    " + line, "ERROR");
                    }
                    LogBus.log("[上次崩溃] 完整堆栈见 " + f.getAbsolutePath(), "ERROR");
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /** 探测本机网络, 把结果填进界面。 */
    private void detectNetwork() {
        try {
            NetInfo net = NetInfo.detect(this);
            // 所有字段一律走 nz() —— 探测链路上的反射调用可能返回 null,
            // 直接 .isEmpty() 会 NPE (真机踩过)。
            String hotspotIp = NetInfo.nz(net.hotspotIp);
            String hotspotIface = NetInfo.nz(net.hotspotIface);
            String upstream = NetInfo.nz(net.upstreamIface);
            String vpnIp = NetInfo.nz(net.vpnIp);

            StringBuilder sb = new StringBuilder();
            sb.append("热点开关: ").append(net.apEnabled ? "已开启" : "**未开启**")
                    .append("    root: ")
                    .append(RootTools.hasRoot() ? "已获得" : "未获得")
                    .append("\n");
            sb.append("热点地址: ").append(hotspotIp.isEmpty() ? "未探测到" : hotspotIp)
                    .append("    接口: ").append(hotspotIface.isEmpty() ? "?" : hotspotIface)
                    .append("\n");
            sb.append("VPN 地址: ").append(vpnIp)
                    .append("    上行接口: ").append(upstream.isEmpty() ? "?" : upstream);
            tvNet.setText(sb.toString());

            // 只在用户没手动改过时才回填
            if (etHotspotIp.getText().length() == 0) {
                etHotspotIp.setText(hotspotIp);
                etHotspotIp.setHint("热点 IP (自动探测, 可手动改)");
            }
            if (etVpnIp.getText().length() == 0) {
                etVpnIp.setText(vpnIp);
                etVpnIp.setHint("VPN IP (自动选取, 可手动改)");
            }
            LogBus.log("[ui] 探测: " + net.describe());
        } catch (Exception e) {
            LogBus.log("[ui] 网络探测失败: " + e);
            // 探测失败也要让界面显示得出来, 否则用户只看到一片空白
            tvNet.setText("探测失败: " + e
                    + "\n请确认已开启『移动热点』, 也可手动填写上方 IP");
        }
    }

    private void onApkPicked(android.net.Uri uri) {
        try {
            String name = "target.apk";
            try (InputStream in = getContentResolver().openInputStream(uri)) {
                File out = new File(getFilesDir(), name);
                try (FileOutputStream fos = new FileOutputStream(out)) {
                    byte[] buf = new byte[16384];
                    int n;
                    while ((n = in.read(buf)) > 0) fos.write(buf, 0, n);
                }
            }
            File f = new File(getFilesDir(), name);
            RuleEngine.current().apkFile = f;

            // 从 APK 里读出真实包名/应用名, 回填 patch 规则
            String pkg = null, label = null;
            try {
                android.content.pm.PackageManager pm = getPackageManager();
                android.content.pm.PackageInfo pi =
                        pm.getPackageArchiveInfo(f.getAbsolutePath(), 0);
                if (pi != null) {
                    pkg = pi.packageName;
                    android.content.pm.ApplicationInfo ai = pi.applicationInfo;
                    ai.sourceDir = f.getAbsolutePath();
                    ai.publicSourceDir = f.getAbsolutePath();
                    label = ai.loadLabel(pm).toString();
                }
            } catch (Exception ignored) {
            }
            RuleEngine.current().applyApkInfo(label, pkg, f.length());
            etApkName.setText(f.getName() + "  (" + f.length() + " bytes)"
                    + (pkg != null ? "  " + pkg : ""));
            LogBus.log("[ui] 已选择 APK: " + f.getName() + " pkg=" + pkg
                    + " name=" + label + " size=" + f.length());
            toast("已选择 APK");
        } catch (Exception e) {
            LogBus.log("[ui] 选择 APK 失败: " + e);
            toast("选择失败: " + e.getMessage());
        }
    }

    private void requestVpnAndStart() {
        Intent intent = VpnService.prepare(this);
        if (intent != null) {
            startActivityForResult(intent, REQ_VPN);
        } else {
            startService();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) {
                startService();
            } else {
                LogBus.log("[ui] 用户拒绝了 VPN 授权");
                toast("需要授予 VPN 权限");
            }
        }
    }

    private void startService() {
        // 启动前预检: 热点未开启且用户未手动填写热点 IP -> 直接报错、不启动服务。
        // 这样既给出明确反馈, 也避免服务因 startForegroundService 时限未满足被系统杀(闪退)。
        try {
            NetInfo net = NetInfo.detect(this);
            String manualHotspot = etHotspotIp.getText().toString().trim();
            if (!net.apEnabled && manualHotspot.isEmpty()) {
                String msg = "请先打开手机『移动热点』，再点启动劫持";
                LogBus.log("[ui] " + msg);
                toast(msg);
                return;
            }
        } catch (Throwable t) {
            // 探测异常不要阻断启动, 交给服务内部再判断
            LogBus.log("[ui] 启动前预检异常(忽略): " + t);
        }
        try {
            Intent i = new Intent(this, CarStoreVpnService.class);
            // 把界面上的 IP 设置传给服务 (留空 = 服务端自动探测)
            String hotspot = etHotspotIp.getText().toString().trim();
            String vpn = etVpnIp.getText().toString().trim();
            if (!hotspot.isEmpty()) {
                i.putExtra(CarStoreVpnService.EXTRA_HOTSPOT_IP, hotspot);
            }
            if (!vpn.isEmpty()) {
                i.putExtra(CarStoreVpnService.EXTRA_VPN_IP, vpn);
            }
            startForegroundService(i);
            serviceRunning = true;
            btnToggle.setText("停止劫持");
            tvStatus.setText("运行中 —— 车机连上热点后生效");
            LogBus.log("[ui] 已启动服务");
        } catch (Exception e) {
            LogBus.log("[ui] 启动失败: " + e);
            toast("启动失败: " + e.getMessage());
            serviceRunning = false;
            btnToggle.setText("启动劫持");
        }
    }

    private void stopService() {
        try {
            Intent i = new Intent(this, CarStoreVpnService.class);
            i.putExtra("stop", true);
            startService(i);
            serviceRunning = false;
            btnToggle.setText("启动劫持");
            tvStatus.setText("已停止");
        } catch (Exception e) {
            LogBus.log("[ui] 停止失败: " + e);
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (startFailedReceiver != null) {
            try {
                unregisterReceiver(startFailedReceiver);
            } catch (Throwable ignored) {
            }
            startFailedReceiver = null;
        }
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }
}

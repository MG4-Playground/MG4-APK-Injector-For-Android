package com.mg4.carstore;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 核心服务 (免 root 优先, 但 Android 上实际需要 root 才能劫持车机流量)。
 *
 * 工作原理
 * --------
 * 1. 探测本机真实网络 (NetInfo):
 *      - 热点(tethering)接口名与 IPv4 —— 各机型不同
 *        (ap0 / wlan1 / swlan0 / rndis0 / ccmni0 ..., Android 10+ 还会随机换网段)
 *      - 上行(联网)接口 —— 用来排除, 避免把劫持目标指向错误的网卡
 *      - VPN 虚拟地址 —— 动态选取, 避开与本机任何网段冲突
 *
 * 2. 建立一个**只承载 DNS 的 VPN 隧道** (不抢任何路由):
 *      Android 的 tethering 会把热点客户端的 DNS 查询交给 VPN 的 DNS 服务器
 *      (取决于 ROM 版本), 这样车机的域名解析就走到我们手里。
 *
 * 3. root 模式下用 iptables REDIRECT 把车机的 53/443 重定向到我们的高位端口:
 *      - 必须这样做的原因: Android 内核 ip_unprivileged_port_start = 1024,
 *        普通 App **无法 bind 53/443** (EACCES, INTERNET 权限也绕不过);
 *        而车机的应用商店是硬编码 https (443)、DNS 是 53。
 *      - 另外 Android 上热点客户端流量**不经过 VpnService 的 TUN**
 *        (tethering 走内核转发, VpnService 只按本机 UID 分流),
 *        所以「靠 VPN 隧道截车机流量」在 Android 上不成立, 必须靠 iptables。
 *
 * 4. 无论 root 与否, 我们的 DNS / HTTPS 服务都监听 0.0.0.0 的高位端口,
 *    并把劫持域名解析到**热点本机地址** —— 车机因此连到我们这里。
 */
public class CarStoreVpnService extends VpnService {

    private static final String TAG = "CarStoreVpn";
    private static final String CHANNEL_ID = "carstore_vpn";

    /** 用户在界面上手动指定的热点 IP (留空 = 自动探测)。 */
    public static final String EXTRA_HOTSPOT_IP = "hotspot_ip";
    /** 用户在界面上手动指定的 VPN 地址 (留空 = 自动选取)。 */
    public static final String EXTRA_VPN_IP = "vpn_ip";

    /** 启动失败广播: 让界面复位按钮并展示错误(例如热点未开启)。 */
    public static final String ACTION_START_FAILED = "com.mg4.carstore.ACTION_START_FAILED";
    /** 广播附带的错误信息 extra。 */
    public static final String EXTRA_ERROR = "error";

    private ParcelFileDescriptor pfd;
    private DnsServer dnsServer;
    private HttpsService httpsService;
    private NetInfo net;
    private volatile boolean running = true;

    /** 已安装 iptables 规则时用的接口名, 停服时按它清理。 */
    private volatile String rulesIface = "";

    /**
     * 后台线程池, 专用于「停止 / 清理」。
     *
     * 关键: 清理路径里包含 root 的 iptables 操作 (RootTools.removeRedirect ->
     * execSu), 而 Service 的 onStartCommand / onDestroy 都跑在**主线程**上。
     * 一旦 su 因为交互式 shell / 授权等待等原因卡住, 主线程被 p.waitFor() 阻塞
     * 超过 5 秒就会触发 ANR, 表现为「点停止劫持卡死闪退」。
     * 所以所有清理都必须丢到这个后台线程执行。
     */
    private final ExecutorService bgExecutor =
            Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "carstore-teardown");
                t.setDaemon(true);
                return t;
            });

    /** 防止清理被重复执行 (停止意图 + onDestroy 可能各触发一次)。 */
    private final AtomicBoolean tornDown = new AtomicBoolean(false);

    /** 防止启动流程(startEverything)被并发拉起多次。 */
    private final AtomicBoolean started = new AtomicBoolean(false);

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && intent.getBooleanExtra("stop", false)) {
            requestStop();
            return START_NOT_STICKY;
        }
        if (pfd != null) {
            return START_STICKY;
        }
        // 关键: 立即(在主线程)调用 startForeground, 满足系统对 startForegroundService
        // 的时限要求。这一步必须同步、尽早完成 —— 否则系统判定「未在时限内成为前台
        // 服务」, 会直接抛 ForegroundServiceDidNotStartInTimeException 并杀进程(闪退)。
        // startForegroundCompat 内部即便 startForeground 抛异常也绝不能让它逃逸。
        try {
            startForegroundCompat();
        } catch (Throwable t) {
            Log.e(TAG, "startForegroundCompat 失败", t);
        }
        // 把真正的重活(网络探测 / VPN 建立 / su 装 iptables)丢到后台线程执行,
        // 让 onStartCommand 立刻返回, 主线程不被阻塞 -> 不会触发前台服务时限超时。
        // 用 started 去重, 避免同一时刻多次拉起 startEverything。
        if (!started.compareAndSet(false, true)) {
            return START_STICKY; // 已在启动流程中
        }
        tornDown.set(false); // 新一轮启动, 允许之后正常停止
        final Intent startIntent = intent;
        bgExecutor.execute(() -> {
            try {
                startEverything(startIntent);
            } catch (Throwable e) {
                Log.e(TAG, "启动失败", e);
                String detail = (e.getMessage() == null ? e.toString() : e.getMessage());
                LogBus.log("[vpn] 启动失败: " + detail, "ERROR");
                sendStartFailed(detail);
                requestStop();   // 后台线程完整收尾(关服务/清规则), 不阻塞主线程
            }
        });
        return START_STICKY;
    }

    /** 请求停止服务: 只执行一次, 实际清理在后台线程完成, 不阻塞主线程。 */
    private void requestStop() {
        if (tornDown.compareAndSet(false, true)) {
            LogBus.log("[vpn] 正在停止 (后台清理中)...");
            bgExecutor.execute(this::stopEverything);
        }
    }

    private void startEverything(Intent intent) throws Exception {
        RuleEngine eng = RuleEngine.current();
        LogBus.log("[vpn] 正在探测本机网络...");

        // ------------------------------------------------ 1) 动态网络探测
        net = NetInfo.detect(this);

        // 用户可手动覆盖 (自动探测偶尔会认错接口, 例如某些 ROM 上热点与
        // 上行共用 wlan0)
        String manualHotspot = intent == null ? null
                : intent.getStringExtra(EXTRA_HOTSPOT_IP);
        if (manualHotspot != null && !manualHotspot.trim().isEmpty()) {
            net.hotspotIp = manualHotspot.trim();
            LogBus.log("[vpn] 使用手动指定的热点地址: " + net.hotspotIp);
        }
        String manualVpn = intent == null ? null
                : intent.getStringExtra(EXTRA_VPN_IP);
        if (manualVpn != null && !manualVpn.trim().isEmpty()) {
            net.vpnIp = manualVpn.trim();
            LogBus.log("[vpn] 使用手动指定的 VPN 地址: " + net.vpnIp);
        }

        LogBus.log("[vpn] 网络探测结果: " + net.describe());
        for (NetInfo.Iface f : net.ifaces) {
            LogBus.log("[vpn]   接口 " + f);
        }

        if (net.hotspotIp == null || net.hotspotIp.isEmpty()) {
            throw new IllegalStateException(
                    "未能确定热点地址。请确认手机『移动热点』已开启, "
                    + "或在界面上手动填写热点 IP。");
        }
        if (!net.apEnabled && (intent == null
                || intent.getStringExtra(EXTRA_HOTSPOT_IP) == null
                || intent.getStringExtra(EXTRA_HOTSPOT_IP).trim().isEmpty())) {
            // 没开热点就没有热点接口, 此时探测到的多半是「连着的 WiFi」的地址,
            // 用它当热点网关会让车机连不上。明确拦下来。
            throw new IllegalStateException(
                    "移动热点未开启 —— 无法确定热点网关地址。"
                    + "请先在手机设置里打开『移动热点』, 再启动本服务。");
        }
        // VPN 地址兜底: addAddress(null/空) 会直接抛异常
        if (net.vpnIp == null || net.vpnIp.isEmpty()) {
            net.vpnIp = "10.7.7.1";
            LogBus.log("[vpn] VPN 地址为空, 使用兜底值 " + net.vpnIp, "WARN");
        }
        // 手动指定的热点地址也要做合法性检查 (空串 / 非 IP 格式)
        if (!isValidIpv4(net.hotspotIp)) {
            throw new IllegalStateException(
                    "热点地址格式不对: '" + net.hotspotIp + "'。"
                    + "请填写车机「网关」里看到的 IPv4 地址。");
        }

        // 注: startForeground 已在 onStartCommand 启动分支最开头同步调用过,
        // 这里无需再调; 后台线程也不应再触碰前台状态。

        // ------------------------------------------ 2) 建立 DNS 承载用 VPN
        Builder b = new Builder();
        b.setSession("CarStoreInjector");
        b.setMtu(1500);
        b.addAddress(net.vpnIp, 32);
        // VPN 的 DNS 服务器 = 我们自己的 DNS。
        //
        // 关键: **不添加任何路由**。
        //   - 加了商店网段路由, 手机自身回源会被导进隧道形成黑洞,
        //     patch 将永远拿不到真实响应;
        //   - 且 Android 上热点客户端流量本来就不经过 TUN, 加路由也没用。
        //   路由不加, 只挂 DNS。
        b.addDnsServer(net.vpnIp);

        pfd = b.establish();
        if (pfd == null) {
            throw new IllegalStateException("VPN 建立失败 (用户可能拒绝了授权)");
        }
        LogBus.log("[vpn] VPN 隧道已建立, 虚拟地址 " + net.vpnIp + " (仅承载 DNS, 不抢路由)");

        // ------------------------------------------------ 3) DNS 劫持服务
        MiniDns.setProtector(this);
        dnsServer = new DnsServer(net.vpnIp, net.hotspotIp, eng.rules.hijackDomains);
        dnsServer.setProtector(this);
        // 只绑 **0.0.0.0** —— 一个 socket 就覆盖 VPN 地址 / 热点地址 /
        // iptables REDIRECT 后的目标地址。绑多个地址会因端口冲突而不一致。
        dnsServer.listenOn("0.0.0.0");
        dnsServer.start();

        // ------------------------------------------------ 4) HTTPS 劫持服务
        File apk = eng.apkFile;
        httpsService = new HttpsService(eng.rules, apk,
                readAsset("chain.pem"), readAsset("leaf.key.pem"));
        httpsService.setProtector(this);
        // 主监听已绑 0.0.0.0, 覆盖所有本地地址, 不需要再绑具体地址
        // (绑了必然 EADDRINUSE —— 0.0.0.0 与具体地址同端口冲突)
        httpsService.start("0.0.0.0");

        // ------------------------------------------- 5) iptables 重定向
        setupRedirect();

        LogBus.log("[vpn] ===== 服务就绪 =====");
        LogBus.log("[vpn] 车机连上本机热点后, 商店请求会被劫持到 "
                + net.hotspotIp + " (内部端口 " + DnsServer.DNS_PORT + "/"
                + HttpsService.HTTPS_PORT + ")");
        LogBus.log("[vpn] 若车机详情页无变化, 看是否有 '[dns] 劫持' 日志 —— "
                + "没有说明车机 DNS 查询没走到本机。");
    }

    /**
     * 安装 iptables 重定向规则 (需要 root)。
     *
     * 车机 -> 本机:53  ->  本机:5353  (我们的 DNS)
     * 车机 -> 本机:443 ->  本机:8443  (我们的 HTTPS)
     *
     * 用 REDIRECT 而非 DNAT: 目标地址变成本机, 而**源地址保持车机的 IP**,
     * 这样我们的服务拿到的连接来源仍是车机, Host / SNI 都能正常解析。
     */
    private void setupRedirect() {
        if (!RootTools.hasRoot()) {
            LogBus.log("[root] 未检测到 root —— 无法安装 iptables 重定向规则。", "WARN");
            LogBus.log("[root] Android 上车机流量不经过 VpnService 隧道, "
                    + "且普通 App 不能绑定 53/443 特权端口, "
                    + "因此**必须 root**(Magisk 等) 才能劫持车机。", "WARN");
            LogBus.log("[root] 本机服务仍已启动在 "
                    + DnsServer.DNS_PORT + "/" + HttpsService.HTTPS_PORT
                    + ", 若你的 ROM 会把热点 DNS 交给 VPN, 仍可能命中。", "WARN");
            return;
        }

        String iface = net.hotspotIface;
        if (iface == null || iface.isEmpty()) {
            // 接口名探测失败时, 试所有看起来像热点的接口
            for (NetInfo.Iface f : net.ifaces) {
                if (f.apLike && !f.vpnLike) {
                    iface = f.name;
                    break;
                }
            }
        }
        if (iface == null || iface.isEmpty()) {
            LogBus.log("[root] 未能确定热点接口名, 跳过 iptables 安装", "ERROR");
            return;
        }

        RootTools.setLastInterface(iface);
        // 用**实际绑定端口**, 不是常量 —— 端口被占时服务会自动顺延,
        // 而 iptables 规则必须指向真正在监听的那个端口。
        int dnsPort = dnsServer != null ? dnsServer.getBoundPort() : DnsServer.DNS_PORT;
        int httpsPort = httpsService != null ? httpsService.getBoundPort() : HttpsService.HTTPS_PORT;
        RootTools.setLastPorts(dnsPort, httpsPort);
        // 443 按端口全部重定向 (不限目的地址): 商店 App 多走 HTTPDNS,
        // 详情/下载接口解析到真实 IP 也能被这里拦下做 MITM; 这是 v7.2 能劫持
        // 详情页、而 v7.3 加 -d 限制后反而失效的原因。
        boolean ok = RootTools.installRedirect(iface, dnsPort, httpsPort);
        if (ok) {
            rulesIface = iface;
            LogBus.log("[root] 重定向已生效 —— 车机的 53/443 会被转到 "
                    + dnsPort + "/" + httpsPort);
        } else {
            LogBus.log("[root] 重定向安装失败, 车机流量不会到达本服务", "ERROR");
        }
    }

    /** VpnService 必须以前台服务运行, 否则系统会回收。 */
    private void startForegroundCompat() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && nm != null) {
            NotificationChannel ch = new NotificationChannel(CHANNEL_ID,
                    "车机劫持服务", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            nm.createNotificationChannel(ch);
        }
        Intent pi = new Intent(this, MainActivity.class);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT
                | (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
                ? PendingIntent.FLAG_IMMUTABLE : 0);
        PendingIntent ppi = PendingIntent.getActivity(this, 0, pi, flags);
        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            b = new Notification.Builder(this, CHANNEL_ID);
        } else {
            b = new Notification.Builder(this);
        }
        Notification n = b.setContentTitle("车机APK注入")
                .setContentText("运行中 —— 车机连接本机热点后生效")
                .setSmallIcon(android.R.drawable.ic_menu_upload)
                .setContentIntent(ppi)
                .setOngoing(true)
                .build();
        try {
            startForeground(1001, n);
        } catch (Exception e) {
            Log.w(TAG, "startForeground 失败", e);
        }
    }

    /** 通知界面: 服务启动失败, 让它把按钮复位并展示错误。 */
    private void sendStartFailed(String detail) {
        try {
            Intent i = new Intent(ACTION_START_FAILED);
            i.putExtra(EXTRA_ERROR, detail == null ? "" : detail);
            sendBroadcast(i);
        } catch (Throwable ignored) {
        }
    }

    private String readAsset(String name) throws Exception {
        try (InputStream in = getAssets().open(name)) {
            byte[] b = HttpsService.readAll(in);
            return new String(b, StandardCharsets.UTF_8);
        }
    }

    /** 简单的 IPv4 格式校验 (四段十进制, 每段 0-255)。 */
    private static boolean isValidIpv4(String ip) {
        if (ip == null) return false;
        String[] a = ip.trim().split("\\.");
        if (a.length != 4) return false;
        for (String s : a) {
            if (s.isEmpty() || s.length() > 3) return false;
            int v;
            try {
                v = Integer.parseInt(s);
            } catch (NumberFormatException e) {
                return false;
            }
            if (v < 0 || v > 255) return false;
        }
        return true;
    }

    private void stopEverything() {
        started.set(false); // 允许下次重新启动
        running = false;
        if (dnsServer != null) {
            dnsServer.stop();
            dnsServer = null;
        }
        if (httpsService != null) {
            httpsService.stop();
            httpsService = null;
        }
        // 清理 iptables 规则 (不清理的话, 车机会一直往已关闭的端口发包)
        // removeRedirect 内部已做幂等, 这里即便没有规则也不会出错。
        if (!rulesIface.isEmpty() || RootTools.hasRoot()) {
            RootTools.removeRedirect();
            LogBus.log("[root] iptables 规则已清理");
        }
        rulesIface = "";
        if (pfd != null) {
            try {
                pfd.close();
            } catch (Exception ignored) {
            }
            pfd = null;
        }
        LogBus.log("[vpn] 服务已停止");
        stopForeground(true);
        stopSelf();
    }

    @Override
    public void onDestroy() {
        // 若系统因内存/ VPN 撤销等原因直接销毁服务, 也要保证清理只跑一次
        // (requestStop 内部用 tornDown 去重, 不会重复执行)。
        // 注意: 不要在这里 shutdownNow 线程池, 否则会打断正在执行的清理任务。
        requestStop();
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        LogBus.log("[vpn] 权限被撤销");
        try {
            stopEverything();
        } catch (Throwable t) {
            Log.e(TAG, "onRevoke 收尾异常", t);
        }
        super.onRevoke();
    }
}

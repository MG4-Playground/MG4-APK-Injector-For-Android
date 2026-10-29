package com.mg4.carstore;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * root 辅助: 检测 su、执行 root 命令、管理 iptables 规则。
 *
 * 为什么安卓端需要 root:
 *
 *   1. Android 内核 net.ipv4.ip_unprivileged_port_start = 1024,
 *      **普通 App 无法 bind 53 / 443** (EACCES), INTERNET 权限也绕不过。
 *      而车机的应用商店是硬编码 https://... (443), DNS 也是 53 —— 无 root 就没端口可用。
 *
 *   2. Android 的 tethering (热点) 走**内核转发**, 车机流量**不经过 VpnService 的 TUN**
 *      (VpnService 只按本机 UID 分流)。所以「建个 VPN 隧道劫持车机」在 Android 上不成立。
 *
 *   3. root 之后用 iptables 把车机的 53/443 **重定向**到我们的高位端口
 *      (5353 / 8443), 既避开特权端口限制, 又让车机流量真正落到我们手上。
 *
 * 没有 root 时 App 仍可启动, 只是无法劫持 —— UI 会明确提示。
 */
public final class RootTools {

    private RootTools() {}

    /** iptables 链名 (自定义链, 便于整体清理)。 */
    public static final String CHAIN = "CARSTORE";

    /**
     * 单条 su 命令的最长等待 (毫秒)。
     *
     * 之前 execSu 直接 p.waitFor() 没有超时: 一旦 su 落到交互式 shell /
     * 授权弹窗 / ROM 上卡住, 等待线程会被永久阻塞。如果这条调用发生在
     * 服务主线程 (停止劫持的 onStartCommand), 就会触发 ANR -> 应用卡死闪退。
     * 这里加一个看门狗, 超时直接销毁进程, 任何调用方都不会再被卡死。
     */
    private static final long SU_TIMEOUT_MS = 4000;

    private static Boolean rootCache;

    // ------------------------------------------------------------ root 检测

    /** 是否具备 root (su 可用)。 */
    public static synchronized boolean hasRoot() {
        if (rootCache != null) return rootCache;
        boolean ok = false;
        try {
            // 1) 直接执行 su -c id
            String out = execSu("id");
            ok = out != null && out.contains("uid=0");
        } catch (Throwable ignored) {
        }
        if (!ok) {
            // 2) 找 su 文件
            for (String p : new String[]{
                    "/system/bin/su", "/system/xbin/su", "/sbin/su",
                    "/su/bin/su", "/system/sbin/su", "/debug_ramdisk/su",
                    "/data/adb/ksu/bin/su", "/data/adb/magisk/su"}) {
                try {
                    if (new java.io.File(p).exists()) { ok = true; break; }
                } catch (Throwable ignored) {
                }
            }
        }
        rootCache = ok;
        return ok;
    }

    /** 以 root 执行一条命令, 返回 stdout+stderr 合并输出; 失败返回 null。 */
    public static String execSu(String cmd) {
        String[] variants = {
                "su -c '" + cmd.replace("'", "'\\''") + "'",
                "su 0 sh -c '" + cmd.replace("'", "'\\''") + "'",
                "/system/xbin/su -c '" + cmd.replace("'", "'\\''") + "'",
        };
        for (String v : variants) {
            try {
                ProcessBuilder pb = new ProcessBuilder("sh", "-c", v);
                pb.redirectErrorStream(true);
                Process p = pb.start();

                final StringBuilder sb = new StringBuilder();
                final boolean[] done = {false};
                // 独立线程读取 stdout, 避免进程迟迟不关闭输出流时本线程被 readLine 卡住
                Thread reader = new Thread(() -> {
                    try (BufferedReader br = new BufferedReader(
                            new InputStreamReader(p.getInputStream()))) {
                        String line;
                        while ((line = br.readLine()) != null) sb.append(line).append('\n');
                    } catch (Throwable ignored) {
                    }
                });
                reader.setDaemon(true);
                reader.start();

                // 看门狗: 超时 (su 卡在交互式 shell / 授权等待) 直接销毁进程,
                // 解除 p.waitFor 的永久阻塞 —— 这是「停止劫持卡死」的直接根因。
                Thread watchdog = new Thread(() -> {
                    try {
                        Thread.sleep(SU_TIMEOUT_MS);
                    } catch (InterruptedException ignored) {
                    }
                    if (!done[0]) {
                        try {
                            p.destroy();
                        } catch (Throwable ignored) {
                        }
                    }
                });
                watchdog.setDaemon(true);
                watchdog.start();

                try {
                    p.waitFor();
                } catch (InterruptedException e) {
                    try {
                        p.destroy();
                    } catch (Throwable ignored) {
                    }
                }
                done[0] = true;
                try {
                    reader.join(1000);
                } catch (InterruptedException ignored) {
                }

                String s = sb.toString().trim();
                if (!s.isEmpty()) return s;
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    /**
     * 一次性执行多条命令 (共用一条 su 会话)。
     *
     * 把原本要 N 次 fork su 的操作合并成 1 次, 既能显著缩短停止劫持时的耗时,
     * 也减少了每次 su 等待可能引入的卡顿面。命令之间用 ';' 连接, 单条失败
     * (如规则不存在) 不影响其余命令; 需要忽略报错的地方自行加 2>/dev/null。
     */
    public static void execSuMulti(String[] cmds) {
        if (cmds == null || cmds.length == 0) return;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < cmds.length; i++) {
            if (i > 0) sb.append(" ; ");
            sb.append(cmds[i]);
        }
        execSu(sb.toString());
    }

    // --------------------------------------------------------- iptables 管理

    /**
     * 初始化 iptables 链并装上重定向规则。
     *
     * @param hotspotIface 热点接口名 (如 wlan1 / ap0 / rndis0)
     * @param dnsPort      我们的 DNS 端口
     * @param httpsPort    我们的 HTTPS 端口
     */
    public static boolean installRedirect(String hotspotIface, int dnsPort,
                                           int httpsPort) {
        if (hotspotIface == null || hotspotIface.isEmpty()) {
            LogBus.log("[root] 未知的热点接口名, 无法安装重定向规则");
            return false;
        }
        // 清掉旧的再建, 避免重复 (一条 su 会话完成)
        removeRedirect();

        // 全部合并到一次 su 调用, 减少 fork su 的次数与等待。
        // 顺序关键: **先建链/加引用, 最后才 -F/-X 清理** 的语义只用在 remove 里;
        // 这里只负责安装。
        String[] cmds = {
                // 1) 建链 (已存在则忽略)
                "iptables -t nat -N " + CHAIN + " 2>/dev/null",
                // 2) 清空链内旧规则
                "iptables -t nat -F " + CHAIN,
                // 3) PREROUTING 跳到自定义链 (只针对热点进来的包)
                "iptables -t nat -I PREROUTING -i " + hotspotIface + " -j " + CHAIN,
                // 4) 车机的 DNS (udp/53) -> 我们的 dnsPort (全部域名都要过我们,
                //    以便劫持商店域名; 非商店域名会被转发到真实 DNS)
                "iptables -t nat -A " + CHAIN + " -p udp --dport 53 "
                        + "-j REDIRECT --to-ports " + dnsPort,
                // 5) 车机的 HTTPS (tcp/443) -> 我们的 httpsPort。
                //    **按端口重定向 (不限目的地址)**: 商店 App 很可能走 HTTPDNS,
                //    把详情/下载接口解析到真实 IP 而绕过我们的 DNS 劫持; 只要还走
                //    443, 这里就能拦下来做 MITM 并改写。用 REDIRECT 而非 DNAT:
                //    目标变成本机, 源地址保持车机 IP, 便于我们拿到 Host / SNI。
                "iptables -t nat -A " + CHAIN + " -p tcp --dport 443 "
                        + "-j REDIRECT --to-ports " + httpsPort,
                // 6) 允许重定向后的流量进入 (转发链放行)
                "iptables -I INPUT -i " + hotspotIface + " -p udp --dport "
                        + dnsPort + " -j ACCEPT",
                "iptables -I INPUT -i " + hotspotIface + " -p tcp --dport "
                        + httpsPort + " -j ACCEPT",
        };
        execSuMulti(cmds);

        // 校验规则是否真的装上了
        String check = execSu("iptables -t nat -L " + CHAIN + " -n");
        boolean ok = check != null && check.contains("REDIRECT");
        if (ok) {
            LogBus.log("[root] iptables 重定向已安装 (" + hotspotIface
                    + "): udp/53->" + dnsPort + ", tcp/443->" + httpsPort);
        } else {
            LogBus.log("[root] iptables 规则安装失败, 输出: " + check);
        }
        return ok;
    }

    /** 清理所有我们装的规则 (幂等, 单条 su 会话完成)。 */
    public static void removeRedirect() {
        java.util.ArrayList<String> cmds = new java.util.ArrayList<>();
        // 1) 删掉 PREROUTING 里指向我们自定义链的跳转 (用我们已知的接口名精确删除)
        if (lastIface != null && !lastIface.isEmpty()) {
            cmds.add("iptables -t nat -D PREROUTING -i " + lastIface
                    + " -j " + CHAIN + " 2>/dev/null");
            // 2) 删 INPUT 放行规则 —— 用**实际**端口 (端口会被占用顺延, 写死常量删不掉)
            if (lastDnsPort > 0) {
                cmds.add("iptables -D INPUT -i " + lastIface + " -p udp --dport "
                        + lastDnsPort + " -j ACCEPT 2>/dev/null");
            }
            if (lastHttpsPort > 0) {
                cmds.add("iptables -D INPUT -i " + lastIface + " -p tcp --dport "
                        + lastHttpsPort + " -j ACCEPT 2>/dev/null");
            }
        }
        // 3) 清空并删除自定义链 (顺序: 先 -F 再 -X)
        cmds.add("iptables -t nat -F " + CHAIN + " 2>/dev/null");
        cmds.add("iptables -t nat -X " + CHAIN + " 2>/dev/null");
        execSuMulti(cmds.toArray(new String[0]));
        lastDnsPort = 0;
        lastHttpsPort = 0;
    }

    /** 最近一次安装时用的接口名, 供清理时使用。 */
    private static String lastIface = "";
    /** 最近一次安装时用的端口 (会因占用而顺延, 清理时要用实际值)。 */
    private static int lastDnsPort = 0;
    private static int lastHttpsPort = 0;

    public static void setLastInterface(String iface) {
        lastIface = iface == null ? "" : iface;
    }

    public static void setLastPorts(int dnsPort, int httpsPort) {
        lastDnsPort = dnsPort;
        lastHttpsPort = httpsPort;
    }

    /** 当前生效的规则文本 (给日志看)。 */
    public static List<String> dumpRules() {
        List<String> out = new ArrayList<>();
        String s = execSu("iptables -t nat -L " + CHAIN + " -n 2>/dev/null");
        if (s != null && !s.trim().isEmpty()) out.add(s.trim());
        return out;
    }
}

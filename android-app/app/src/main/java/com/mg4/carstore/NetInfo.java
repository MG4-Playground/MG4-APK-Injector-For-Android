package com.mg4.carstore;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.wifi.WifiManager;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

/**
 * 探测本机真实网络信息 —— **不做任何网段/地址硬编码**。
 *
 * 为什么必须动态探测 (而不是像 PC 版那样写死 192.168.137.1):
 *
 *   1. 热点网段因机型 / ROM / 版本而异:
 *      - 早期 AOSP 固定 192.168.43.1
 *      - Android 10 起每次开热点可能随机换一个 192.168.x.0/24
 *      - USB 共享一般是 192.168.42.0/24
 *      - 某些厂商自定义为 10.x.x.1
 *      192.168.137.x 是 **Windows ICS** 的默认段, 在 Android 上根本不存在。
 *
 *   2. 上行(联网)接口名因芯片平台而异: rmnet_data0 / ccmni0 / wlan0 ...
 *      把热点接口认错成上行接口, 就会把劫持目标指向错误的 IP。
 *
 *   3. VPN 虚拟地址不能与热点网段 / 上行网段冲突, 否则会出现
 *      "路由回环" 与 "DNS 自查自" —— 表现就是商店加载不出来。
 *
 * 探测顺序 (从强信号到弱信号):
 *   a) WifiManager.getDhcpInfo().serverAddress —— 热点开着时通常就是热点网关地址
 *   b) 遍历 NetworkInterface, 按 接口名特征 + 私网地址 + 非上行接口 打分
 *   c) 兜底: 任意非回环、非 VPN 的私网 IPv4
 */
public final class NetInfo {

    /** 一个网卡的探测结果。 */
    public static final class Iface {
        public String name = "";
        public String ipv4 = "";
        public boolean up;
        public boolean loopback;
        /** 名字像热点/共享接口 (ap0 / wlan1 / rndis0 / ccmni0 ...) */
        public boolean apLike;
        /** 名字像 VPN 虚拟接口 (tun0 / ppp0 ...) */
        public boolean vpnLike;
        /** 就是当前承载外网的接口 (上行) */
        public boolean upstream;
        public int score;
        public String note = "";

        @Override
        public String toString() {
            String nm = name == null ? "" : name;
            String ip = ipv4 == null ? "" : ipv4;
            return nm + "=" + (ip.isEmpty() ? "-" : ip)
                    + (up ? " up" : " down")
                    + (apLike ? " ap-like" : "")
                    + (vpnLike ? " vpn-like" : "")
                    + (upstream ? " upstream" : "")
                    + " score=" + score
                    + (note == null || note.isEmpty() ? "" : " (" + note + ")");
        }
    }

    public final List<Iface> ifaces = new ArrayList<>();

    /** 热点(网关)本机地址 —— 车机连的就是它 */
    public String hotspotIp = "";
    /** 热点接口名 —— iptables 规则要用 */
    public String hotspotIface = "";
    /** 当前上行(联网)接口名 */
    public String upstreamIface = "";
    /** WifiManager 报告的 DHCP 服务器地址 (热点时通常 == hotspotIp) */
    public String dhcpServerIp = "";
    /** 系统 SoftApConfiguration 里配置的热点地址 (API 30+, 最权威) */
    public String softApIp = "";
    /** 移动热点是否真的开着 (反射 isWifiApEnabled) */
    public boolean apEnabled;
    /** 选定的 VPN 虚拟地址 */
    public String vpnIp = "";

    public String note = "";

    /**
     * null -> "" 的空安全转换。
     *
     * 背景: 真机踩过 NPE ——
     *   - LinkProperties.getInterfaceName() 可以返回 null
     *   - 反射调用失败时 detectSoftApAddress() 返回 null
     * 而这些字段在下游被直接 .isEmpty() 调用, 于是崩在探测阶段。
     * 所有对外暴露的字符串字段一律经过它, 从源头杜绝。
     */
    static String nz(String s) {
        return s == null ? "" : s;
    }

    // ------------------------------------------------------------------ 探测

    public static NetInfo detect(Context ctx) {
        NetInfo r = new NetInfo();
        // 顺序很重要: softApIp / dhcpServerIp 必须**先于** detectIfaces 得到,
        // 因为 score() 里要用它们打分 (softApIp +400 / dhcpServerIp +200)。
        // 之前 detectIfaces() 排在这两个前面, 导致强信号从来没生效过。
        r.apEnabled = r.detectApEnabled(ctx);
        r.detectDhcp(ctx);
        r.softApIp = nz(r.detectSoftApAddress(ctx));
        r.detectUpstream(ctx);
        r.detectIfaces();
        r.pickHotspot();
        r.vpnIp = pickVpnAddress(r.ifaces, null);
        return r;
    }

    private void detectUpstream(Context ctx) {
        try {
            ConnectivityManager cm = (ConnectivityManager)
                    ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return;
            Network net = cm.getActiveNetwork();
            if (net == null) return;
            LinkProperties lp = cm.getLinkProperties(net);
            // getInterfaceName() **可能返回 null** (某些网络类型没有接口名),
            // 真机上就因此 NPE 过。必须兜底成 ""。
            if (lp != null) upstreamIface = nz(lp.getInterfaceName());
        } catch (Throwable ignored) {
        }
    }

    private void detectIfaces() {
        try {
            Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
            while (en != null && en.hasMoreElements()) {
                NetworkInterface ni = en.nextElement();
                Iface f = new Iface();
                // getName() 理论上不会 null, 但仍走 nz() 兜底 ——
                // 下面紧接着就有 .toLowerCase(), 一旦 null 就 NPE。
                f.name = nz(ni.getName());
                f.up = ni.isUp();
                f.loopback = ni.isLoopback();
                String n = f.name.toLowerCase(Locale.ROOT);

                f.apLike = n.startsWith("ap")          // ap0 / ap1
                        || n.startsWith("swlan")      // swlan0 (高通)
                        || n.startsWith("softap")     // softap0
                        || n.startsWith("tether")     // tether0
                        || n.startsWith("rndis")      // rndis0 (USB 共享)
                        || n.startsWith("usb")        // usb0
                        || n.startsWith("ccmni")      // ccmni0 (USB 共享, 高通)
                        || n.equals("wlan1");         // 部分平台热点用 wlan1
                // 注意: **不把 wlan2 当热点信号**。
                // 真机实测: 手机连着公司 WiFi 时, wlan2 就是那个 STA 接口
                // (地址 10.11.155.218), 把它当热点会选错网卡。
                f.vpnLike = n.startsWith("tun") || n.startsWith("ppp")
                        || n.startsWith("ipsec") || n.startsWith("wg")
                        || n.startsWith("teql") || n.startsWith("ifb");
                f.upstream = f.name.equals(upstreamIface);

                InetAddress v4 = null;
                try {
                    Enumeration<InetAddress> as = ni.getInetAddresses();
                    while (as.hasMoreElements()) {
                        InetAddress a = as.nextElement();
                        if (a instanceof Inet4Address && !a.isLoopbackAddress()) {
                            v4 = a;
                            break;
                        }
                    }
                } catch (Throwable ignored) {
                }
                // getHostAddress() 也可能返回 null, 同样兜底
                if (v4 != null) f.ipv4 = nz(v4.getHostAddress());

                score(f);
                ifaces.add(f);
            }
        } catch (Throwable ignored) {
        }
    }

    private void score(Iface f) {
        int s = 0;
        StringBuilder note = new StringBuilder();
        f.ipv4 = nz(f.ipv4);
        f.name = nz(f.name);

        if (f.ipv4.isEmpty()) {
            s -= 100;
            note.append("无 IPv4 ");
        }
        if (f.loopback) {
            s -= 200;
            note.append("回环 ");
        }
        if (!f.up) {
            s -= 50;
            note.append("未启用 ");
        }
        if (f.vpnLike) {
            s -= 100;
            note.append("VPN 接口 ");
        }
        if (f.upstream) {
            s -= 80;
            note.append("上行接口 ");
        }
        if (!f.ipv4.isEmpty() && isPrivate(f.ipv4)) {
            s += 40;
            note.append("私网地址 ");
        }
        if (f.ipv4.startsWith("192.168.")) {
            s += 25;
        }
        if (f.apLike) {
            s += 30;
            note.append("热点/共享接口名 ");
        }
        // 最强信号: 系统 SoftApConfiguration 里配置的热点地址
        if (!nz(softApIp).isEmpty() && nz(softApIp).equals(nz(f.ipv4))) {
            s += 400;
            note.append("== 系统热点配置 ");
        }
        // 次强信号: 与 DHCP 服务器地址一致
        if (!nz(dhcpServerIp).isEmpty() && nz(dhcpServerIp).equals(nz(f.ipv4))) {
            s += 200;
            note.append("== DHCP 服务器 ");
        }
        f.score = s;
        f.note = note.toString().trim();
    }

    private void pickHotspot() {
        // 优先直接用系统配置的热点地址 (最权威)
        String sap = nz(softApIp);
        if (!sap.isEmpty()) {
            hotspotIp = sap;
            for (Iface f : ifaces) {
                if (sap.equals(f.ipv4)) {
                    hotspotIface = f.name;
                    break;
                }
            }
            note = "使用系统热点配置地址 " + sap;
            return;
        }

        Iface best = null;
        for (Iface f : ifaces) {
            if (nz(f.ipv4).isEmpty()) continue;
            if (best == null || f.score > best.score) best = f;
        }
        if (best != null && best.score > 0) {
            hotspotIp = nz(best.ipv4);
            hotspotIface = nz(best.name);
            note = "选中 " + best;
        } else {
            note = "未能确定热点接口, 请在界面上手动填写";
        }
    }

    private void detectDhcp(Context ctx) {
        // WifiManager.getDhcpInfo() 返回的 DhcpInfo 是 @hide API, 公开 SDK 里
        // 没有 android.net.dhcp.DhcpInfo 这个类, 所以用反射调用。
        // 取到的 serverAddress 就是 DHCP 服务器地址 —— 手机开热点时,
        // 它通常正是热点网关地址, 是很强的信号。
        try {
            WifiManager wm = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
            if (wm == null) return;
            Object dh = wm.getClass().getMethod("getDhcpInfo").invoke(wm);
            if (dh == null) return;
            java.lang.reflect.Field f = dh.getClass().getField("serverAddress");
            int v = f.getInt(dh);
            dhcpServerIp = intToIp(v);
        } catch (Throwable ignored) {
        }
    }

    /**
     * 反射调用 WifiManager.isWifiApEnabled() —— 判断移动热点是否真的开着。
     *
     * 这是 @hide API (公开 SDK 里没有), 但真机 ROM 上都存在。
     * 意义: 热点**没开**时, 根本不存在热点接口, 此时若还去猜一个地址,
     * 就会把「连着的 WiFi 上行地址」误当成热点地址 (真机踩过:
     * 探测出 10.11.155.218 其实��公司 WiFi 的地址, 而热点压根没开)。
     * 有了这个开关, 就能明确告诉用户「先打开移动热点」。
     */
    private boolean detectApEnabled(Context ctx) {
        try {
            WifiManager wm = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
            if (wm == null) return false;
            Object r = wm.getClass().getMethod("isWifiApEnabled").invoke(wm);
            return r instanceof Boolean && (Boolean) r;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * 反射读 WifiManager.getSoftApConfiguration().getApnConfig().getApnAddresses()
     * —— 这是**系统自己配置的热点网段**, 最权威的热点地址来源。
     *
     * Android 11+ (API 30) 才有 SoftApConfiguration; 该 API 需要
     * NETWORK_SETTINGS 权限, 普通 App 调用会抛 SecurityException,
     * 所以必须 try/catch 兜底。读不到就退回其它探测手段。
     *
     * 返回值**永远是 String, 不会 null** —— 读不到就返回 ""。
     */
    private String detectSoftApAddress(Context ctx) {
        try {
            WifiManager wm = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
            if (wm == null) return "";
            Object cfg = wm.getClass().getMethod("getSoftApConfiguration").invoke(wm);
            if (cfg == null) return "";
            Object apn = cfg.getClass().getMethod("getApnConfig").invoke(cfg);
            if (apn == null) return "";
            Object addrs = apn.getClass().getMethod("getApnAddresses").invoke(apn);
            if (!(addrs instanceof java.util.List)) return "";
            java.util.List<?> list = (java.util.List<?>) addrs;
            for (Object o : list) {
                if (o instanceof String) {
                    String s = ((String) o).trim();
                    if (!s.isEmpty()) return s;
                }
            }
        } catch (Throwable ignored) {
        }
        return "";
    }

    // ------------------------------------------------------- VPN 地址选取

    /**
     * 选一个不与任何本机网段冲突的 VPN 虚拟地址。
     *
     * @param preferred 用户指定的地址 (可空)
     */
    public static String pickVpnAddress(List<Iface> ifaces, String preferred) {
        if (preferred != null && !preferred.trim().isEmpty()
                && !collides(preferred.trim(), ifaces)) {
            return preferred.trim();
        }
        String[] pool = {
                "10.7.7.1", "10.66.66.1", "10.8.8.1", "10.9.9.1",
                "10.10.10.1", "10.11.11.1", "10.12.12.1",
        };
        for (String c : pool) {
            if (!collides(c, ifaces)) return c;
        }
        // 兜底: 在 10.7.x.1 里扫
        for (int i = 1; i < 255; i++) {
            String c = "10.7." + i + ".1";
            if (!collides(c, ifaces)) return c;
        }
        return "10.7.7.1";
    }

    /** 与本机任一接口的 /24 是否冲突。 */
    private static boolean collides(String ip, List<Iface> ifaces) {
        String[] a = ip.split("\\.");
        if (a.length != 4) return true;
        for (Iface f : ifaces) {
            if (f.ipv4.isEmpty()) continue;
            String[] b = f.ipv4.split("\\.");
            if (b.length != 4) continue;
            if (a[0].equals(b[0]) && a[1].equals(b[1]) && a[2].equals(b[2])) {
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------------------- 工具

    public static boolean isPrivate(String ip) {
        if (ip == null) return false;
        String[] a = ip.split("\\.");
        if (a.length != 4) return false;
        int b0, b1;
        try {
            b0 = Integer.parseInt(a[0]);
            b1 = Integer.parseInt(a[1]);
        } catch (NumberFormatException e) {
            // 地址格式异常 (某些 ROM 的接口会报出奇怪的值) -> 当作非私网
            return false;
        }
        if (b0 == 10) return true;
        if (b0 == 192 && b1 == 168) return true;
        if (b0 == 172 && b1 >= 16 && b1 <= 31) return true;
        return false;
    }

    /** Android 把 IPv4 存成小端 int, 需反转字节序。 */
    public static String intToIp(int v) {
        if (v == 0) return "";
        return String.format(Locale.ROOT, "%d.%d.%d.%d",
                v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF);
    }

    /** 多行摘要, 直接进日志。 */
    public String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append("热点开关=").append(apEnabled ? "已开启" : "**未开启**")
                .append(" 热点地址=").append(nz(hotspotIp).isEmpty() ? "?" : nz(hotspotIp))
                .append(" 接口=").append(nz(hotspotIface).isEmpty() ? "?" : nz(hotspotIface))
                .append(" | 上行=").append(nz(upstreamIface).isEmpty() ? "?" : nz(upstreamIface))
                .append(" | DHCP=").append(nz(dhcpServerIp).isEmpty() ? "-" : nz(dhcpServerIp))
                .append(" | SoftAp=").append(nz(softApIp).isEmpty() ? "-" : nz(softApIp))
                .append(" | VPN=").append(nz(vpnIp));
        return sb.toString();
    }
}

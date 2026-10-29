package com.mg4.carstore;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;

/**
 * 最小 DNS 客户端 —— **不使用系统解析器**。
 *
 * 原因: 本机开着 VPN/hosts 时, 商店域名会被解析回自己,
 * 用系统解析器回源会形成死循环。这里直接发 UDP 查询到公共 DNS,
 * 拿到真实 IP。
 */
public final class MiniDns {

    private MiniDns() {}

    /**
     * 上游 DNS 列表。
     *
     * 移动网络 (rmnet) 下部分运营商会**劫持/屏蔽**公共 DNS 的 53 端口,
     * 所以要多试几个, 并且加上运营商自己的 DNS 兜底。
     */
    private static final String[] UPSTREAM = {
            "223.5.5.5",      // 阿里
            "119.29.29.29",   // 腾讯
            "114.114.114.114", // 114
            "180.76.76.76",   // 百度
            "1.1.1.1",       // Cloudflare
            "8.8.8.8",       // Google
    };

    /** 出站 socket 需绕过 VPN 隧道, 否则上游查询会导回自己。 */
    private static android.net.VpnService protector;

    static void setProtector(android.net.VpnService p) {
        protector = p;
    }

    /** 解析 A 记录, 返回 IP 字符串; 失败返回 null。 */
    public static String resolve(String hostname) {
        StringBuilder why = new StringBuilder();
        for (String up : UPSTREAM) {
            try {
                byte[] q = buildQuery(hostname);
                DatagramSocket s = new DatagramSocket();
                s.setSoTimeout(4000);
                if (protector != null) {
                    try {
                        protector.protect(s);
                    } catch (Exception ignored) {
                    }
                }
                try {
                    s.send(new DatagramPacket(q, q.length,
                            InetAddress.getByName(up), 53));
                    byte[] buf = new byte[2048];
                    DatagramPacket rp = new DatagramPacket(buf, buf.length);
                    s.receive(rp);
                    String ip = parseA(rp.getData(), rp.getLength());
                    if (ip != null) return ip;
                    why.append(up).append("=无A记录 ");
                } catch (java.net.SocketTimeoutException e) {
                    why.append(up).append("=超时 ");
                } catch (Exception e) {
                    why.append(up).append("=").append(e.getClass().getSimpleName()).append(' ');
                } finally {
                    s.close();
                }
            } catch (Exception e) {
                why.append(up).append("=建socket失败 ");
            }
        }
        // 兜底: 用系统解析器。
        // 注意: 本 App 建立的 VPN 只挂了 DNS 服务器、没有加任何路由,
        // 所以系统解析器仍然走物理网络, 不会形成死循环。
        try {
            java.net.InetAddress[] arr = java.net.InetAddress.getAllByName(hostname);
            for (java.net.InetAddress a : arr) {
                if (a instanceof java.net.Inet4Address) {
                    LogBus.log("[dns] 自建 DNS 全部失败(" + why + "), "
                            + "系统解析器兜底 -> " + a.getHostAddress());
                    return a.getHostAddress();
                }
            }
        } catch (Exception e) {
            LogBus.log("[dns] 系统解析器也失败: " + e.getClass().getSimpleName());
        }
        LogBus.log("[dns] 解析失败 " + hostname + " (" + why + ")");
        return null;
    }

    private static byte[] buildQuery(String hostname) {
        byte[] out = new byte[512];
        int p = 0;
        out[p++] = 0x12; out[p++] = 0x34;       // id
        out[p++] = 0x01; out[p++] = 0x00;       // flags (RD)
        out[p++] = 0; out[p++] = 1;             // qdcount
        out[p++] = 0; out[p++] = 0;             // ancount
        out[p++] = 0; out[p++] = 0;             // nscount
        out[p++] = 0; out[p++] = 0;             // arcount
        for (String part : hostname.split("\\.")) {
            byte[] b = part.getBytes();
            out[p++] = (byte) b.length;
            System.arraycopy(b, 0, out, p, b.length);
            p += b.length;
        }
        out[p++] = 0;
        out[p++] = 0; out[p++] = 1;             // type A
        out[p++] = 0; out[p++] = 1;             // class IN
        return Arrays.copyOf(out, p);
    }

    private static String parseA(byte[] data, int len) {
        if (len < 12) return null;
        // **QDCOUNT 在 [4,5], 不是 [2,3]** —— [2,3] 是 FLAGS。
        // 应答的 FLAGS 通常是 0x8180 (QR=1,RD=1,RA=1,RCODE=0),
        // 当作 QDCOUNT 读会得到 33152, 于是下面的循环把整个包越界扫一遍,
        // 最终 **永远返回 null** —— 回源 100% 失败。
        // (这个坑在本项目里犯过两次: DnsServer.buildAnswer 和这里的 parseA)
        int qd = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);
        int an = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);
        int off = 12;
        for (int i = 0; i < qd; i++) {
            if (off >= len) return null;
            while (off < len && data[off] != 0) off += (data[off] & 0xFF) + 1;
            off += 5;                 // null + QTYPE(2) + QCLASS(2)
            if (off > len) return null;
        }
        for (int i = 0; i < an; i++) {
            if (off >= len) break;
            if ((data[off] & 0xC0) == 0xC0) {
                off += 2;              // 名字压缩指针
            } else {
                while (off < len && data[off] != 0) off += (data[off] & 0xFF) + 1;
                off += 1;
            }
            if (off + 10 > len) break;
            int type = ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
            int rdlen = ((data[off + 8] & 0xFF) << 8) | (data[off + 9] & 0xFF);
            off += 10;
            if (type == 1 && rdlen == 4 && off + 4 <= len) {
                return (data[off] & 0xFF) + "." + (data[off + 1] & 0xFF) + "."
                        + (data[off + 2] & 0xFF) + "." + (data[off + 3] & 0xFF);
            }
            off += rdlen;
        }
        return null;
    }
}

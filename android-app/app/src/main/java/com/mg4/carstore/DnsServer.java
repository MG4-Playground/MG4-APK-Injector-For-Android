package com.mg4.carstore;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 轻量 DNS 服务器 (UDP)。
 *
 * 只做一件事: 对**被劫持的域名**返回本机 (VPN 接口) 地址,
 * 让车机的请求落到本机上; 其余域名原样转发给上游 DNS, 保证车机其它功能正常。
 *
 * 上游查询走**自建 UDP 查询** (不走系统解析器) —— 因为本机的 hosts /
 * VPN 规则会把商店域名指回自己, 用系统解析器会形成死循环。
 *
 * 端口说明:
 *   Android 内核 net.ipv4.ip_unprivileged_port_start = 1024, 普通 App **不能
 *   bind 53** (EACCES)。所以这里用高位端口 (默认 5353), 再由 root 下的
 *   iptables REDIRECT 把车机的 udp/53 转到本端口。
 */
public class DnsServer {

    /** 转发用的上游 DNS */
    private static final String[] UPSTREAM = {"223.5.5.5", "119.29.29.29"};

    /**
     * 我们的 DNS 端口 (高位, 避开 Android 特权端口限制)。
     *
     * **不要用 5353** —— 那是 mDNS 的标准端口, Android 的 NSD/mDNS
     * Responder 一定占着, bind 会直接 EADDRINUSE (实测踩过)。
     * 15353 是 mDNS+1 的常见备用端口, 冲突概率低。
     */
    public static final int DNS_PORT = 15353;

    /** 实际绑定的端口 (端口被占时自动顺延)。 */
    private volatile int boundPort = DNS_PORT;

    private final String listenIp;
    private final String answerIp;
    private final List<String> hijackDomains;
    private final List<DatagramSocket> sockets = new ArrayList<>();
    private volatile boolean running = true;

    /**
     * @param listenIp  DNS 服务器监听的地址 (VPN 虚拟地址)
     * @param answerIp  被劫持域名要返回的 IP (热点本机地址, 车机连它就能到我们的 443)
     */
    public DnsServer(String listenIp, String answerIp, List<String> hijackDomains)
            throws IOException {
        this.listenIp = listenIp;
        this.answerIp = answerIp;
        this.hijackDomains = hijackDomains;
    }

    /**
     * 在指定地址上监听 DNS。
     *
     * **只应该调用一次, 且传 "0.0.0.0"** —— 绑 0.0.0.0 的 socket
     * 天然接收发往**任何本地地址**的包, 所以 VPN 地址、热点地址、
     * iptables REDIRECT 后的目标地址, 全都覆盖到了。
     *
     * 之前实现绑了多个地址 (VPN IP / 热点 IP / 0.0.0.0), 结果:
     * 0.0.0.0 与已绑定的具体地址**冲突** (同一端口), 只能换端口,
     * 于是出现「具体地址在 15353、0.0.0.0 在 15354」的不一致,
     * 而 iptables 只指向一个端口 -> 另一个上的 socket 成了摆设。
     * 绑一个 0.0.0.0 就彻底没这个问题。
     *
     * 端口被占时**自动顺延**: 依次尝试 DNS_PORT, +1, +2 ... 最多 20 个。
     * Android 上有大量系统服务占端口 (mDNS 5353、NSD 等),
     * 写死端口很容易一启动就 EADDRINUSE。
     */
    public void listenOn(String ip) {
        for (int attempt = 0; attempt < 20; attempt++) {
            int tryPort = DNS_PORT + attempt;
            try {
                DatagramSocket s = new DatagramSocket(
                        new InetSocketAddress(InetAddress.getByName(ip), tryPort));
                s.setSoTimeout(1000);
                sockets.add(s);
                boundPort = tryPort;
                Thread t = new Thread(() -> loop(s), "dns-" + ip);
                t.setDaemon(true);
                t.start();
                if (attempt == 0) {
                    LogBus.log("[dns] 已在 " + ip + ":" + tryPort + " 监听"
                            + " (覆盖所有本地地址)");
                } else {
                    LogBus.log("[dns] 端口 " + (tryPort - attempt)
                            + " 被占用, 改用 " + tryPort);
                }
                return;
            } catch (Exception e) {
                String msg = e.getMessage() == null ? "" : e.getMessage();
                if (msg.contains("EADDRINUSE") || msg.contains("Address already in use")) {
                    continue;   // 换下一个端口
                }
                LogBus.log("[dns] 无法在 " + ip + ":" + tryPort + " 监听: " + msg);
                return;
            }
        }
        LogBus.log("[dns] 连续 20 个端口都被占用, 放弃监听", "ERROR");
    }

    /** 实际绑定的端口 (供 iptables 规则使用)。 */
    public int getBoundPort() {
        return boundPort;
    }

    public void start() {
        LogBus.log("[dns] DNS 劫持已启动, 商店域名 -> " + answerIp);
    }

    /** 出站 socket 必须绕过 VPN 隧道, 否则上游查询会被导回自己形成死循环。 */
    private android.net.VpnService protector;

    void setProtector(android.net.VpnService p) {
        this.protector = p;
    }

    private void protect(java.net.DatagramSocket s) {
        if (protector == null) return;
        try {
            protector.protect(s);
        } catch (Exception ignored) {
        }
    }

    public void stop() {
        running = false;
        for (DatagramSocket s : sockets) {
            try {
                s.close();
            } catch (Exception ignored) {
            }
        }
        sockets.clear();
    }

    private void loop(DatagramSocket socket) {
        byte[] buf = new byte[4096];
        while (running) {
            try {
                DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                socket.receive(pkt);
                byte[] query = Arrays.copyOf(pkt.getData(), pkt.getLength());
                String name = parseQName(query);
                if (name == null) continue;

                byte[] response;
                if (isHijacked(name)) {
                    response = buildAnswer(query, name);
                    LogBus.log("[dns] 劫持 " + name + " -> " + answerIp);
                } else {
                    response = forward(query);
                    if (response == null) {
                        LogBus.log("[dns] 转发失败 " + name);
                        continue;
                    }
                }
                socket.send(new DatagramPacket(response, response.length,
                        pkt.getAddress(), pkt.getPort()));
            } catch (SocketTimeoutException ignored) {
                // 正常轮询超时
            } catch (IOException e) {
                if (running) LogBus.log("[dns] 错误: " + e);
            }
        }
    }

    private boolean isHijacked(String name) {
        for (String d : hijackDomains) {
            if (d.equalsIgnoreCase(name)) return true;
        }
        return false;
    }

    /**
     * 构造 A 记录应答: name -> localIp, TTL 60。
     *
     * 注意 header 字段的字节位置 (这是很容易写错的地方):
     *   [0,1]=ID  [2,3]=FLAGS  [4,5]=QDCOUNT  [6,7]=ANCOUNT
     *   [8,9]=NSCOUNT  [10,11]=ARCOUNT
     * ANCOUNT 写错位置(比如误写成 0)会导致「有 answer 记录但计数为 0」,
     * 客户端会认为没有应答而直接丢弃 —— 表现为车机 DNS 解析失败。
     *
     * AAAA 查询 (qtype=28) 返回**空应答**(ANCOUNT=0, 无记录),
     * 让客户端回退到 A 记录。若这里也回 A, 客户端拿到的类型与查询不符,
     * 行为在不同客户端上不一致。
     */
    private byte[] buildAnswer(byte[] query, String name) {
        int id = ((query[0] & 0xFF) << 8) | (query[1] & 0xFF);
        // QDCOUNT 在 [4,5], **不是** [2,3] —— [2,3] 是 FLAGS。
        // 读错位置会得到 0x0100=256, 于是下面的循环把 question 段反复解析
        // 256 次, qEnd 一路越界, 最终应答字节全错, 客户端直接丢弃。
        int qdCount = ((query[4] & 0xFF) << 8) | (query[5] & 0xFF);

        // 解析 question 段: QNAME(变长) + 0x00 + QTYPE(2) + QCLASS(2)
        int off = 12;
        int qType = 1;
        for (int i = 0; i < qdCount; i++) {
            while (off < query.length && query[off] != 0) {
                off += (query[off] & 0xFF) + 1;
            }
            if (off >= query.length) break;
            off += 1;                 // 跳过 null 结束符
            if (off + 4 > query.length) break;
            if (i == 0) {
                qType = ((query[off] & 0xFF) << 8) | (query[off + 1] & 0xFF);
            }
            off += 4;                 // QTYPE(2) + QCLASS(2)
        }
        // 复制 question 段
        byte[] question = Arrays.copyOfRange(query, 12, off);

        // 只有 A 查询才给 A 记录; AAAA / 其它类型给空应答
        boolean giveAnswer = (qType == 1);
        int ansCount = giveAnswer ? 1 : 0;

        byte[] resp = new byte[12 + question.length + (giveAnswer ? 16 : 0)];
        int p = 0;
        resp[p++] = (byte) (id >> 8);
        resp[p++] = (byte) id;
        resp[p++] = (byte) 0x81; // QR=1, RD=1
        resp[p++] = (byte) 0x80; // RA=1, RCODE=0
        resp[p++] = (byte) ((qdCount >> 8) & 0xFF);
        resp[p++] = (byte) (qdCount & 0xFF);   // [4,5] QDCOUNT
        resp[p++] = (byte) ((ansCount >> 8) & 0xFF);
        resp[p++] = (byte) (ansCount & 0xFF);  // [6,7] ANCOUNT  <- 关键
        resp[p++] = 0;
        resp[p++] = 0;                          // [8,9] NSCOUNT
        resp[p++] = 0;
        resp[p++] = 0;                          // [10,11] ARCOUNT
        System.arraycopy(question, 0, resp, p, question.length);
        p += question.length;
        if (!giveAnswer) {
            return resp;
        }
        // answer: name pointer 0xC00C, type A(1), class IN(1), ttl 60, rdlen 4
        resp[p++] = (byte) 0xC0;
        resp[p++] = 0x0C;
        resp[p++] = 0;
        resp[p++] = 1;
        resp[p++] = 0;
        resp[p++] = 1;
        resp[p++] = 0;
        resp[p++] = 0;
        resp[p++] = 0;
        resp[p++] = 60;
        resp[p++] = 0;
        resp[p++] = 4;
        try {
            byte[] ip = InetAddress.getByName(answerIp).getAddress();
            System.arraycopy(ip, 0, resp, p, 4);
        } catch (Exception e) {
            resp[p] = (byte) 127;
            resp[p + 1] = (byte) 0;
            resp[p + 2] = (byte) 0;
            resp[p + 3] = (byte) 1;
        }
        return resp;
    }

    /** 转发到上游 DNS (自建 UDP 查询)。 */
    private byte[] forward(byte[] query) {
        for (String up : UPSTREAM) {
            try {
                DatagramSocket s = new DatagramSocket();
                s.setSoTimeout(3000);
                protect(s);
                try {
                    s.send(new DatagramPacket(query, query.length,
                            InetAddress.getByName(up), 53));
                    byte[] buf = new byte[4096];
                    DatagramPacket rp = new DatagramPacket(buf, buf.length);
                    s.receive(rp);
                    return Arrays.copyOf(rp.getData(), rp.getLength());
                } finally {
                    s.close();
                }
            } catch (IOException ignored) {
                // 试下一个上游
            }
        }
        return null;
    }

    /** 从 DNS 查询包中取出 QNAME。 */
    private static String parseQName(byte[] data) {
        if (data == null || data.length < 12) return null;
        StringBuilder sb = new StringBuilder();
        int off = 12;
        while (off < data.length) {
            int len = data[off] & 0xFF;
            if (len == 0) break;
            if ((len & 0xC0) != 0) return null; // 压缩指针, 出现在 question 里不正常
            off++;
            if (off + len > data.length) return null;
            sb.append(new String(data, off, len, StandardCharsets.UTF_8));
            sb.append('.');
            off += len;
        }
        String s = sb.toString();
        return s.endsWith(".") ? s.substring(0, s.length() - 1) : s;
    }
}

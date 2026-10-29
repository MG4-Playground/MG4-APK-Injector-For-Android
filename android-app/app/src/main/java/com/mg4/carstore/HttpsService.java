package com.mg4.carstore;

import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.GZIPInputStream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

/**
 * 本地 HTTPS 服务: 处理车机应用商店的请求。
 *
 * - serve 规则命中 -> 不回源, 直接下发本地 APK (支持 Range/206/416)
 * - patch 规则命中 -> 正常回源, 按点路径改写 JSON, 重写 Content-Length
 * - 其余请求        -> 原样转发
 *
 * 证书: assets/chain.pem (叶子 + 中间件) + assets/leaf.key.pem。
 * 车机若信任这些中间件对应的公共根, 就能验通 (与 PC 方案同一套证书)。
 *
 * 端口说明:
 *   Android 普通 App 不能 bind 443 (内核 ip_unprivileged_port_start=1024),
 *   所以这里用 8443, 由 root 下的 iptables REDIRECT 把车机的 tcp/443 转过来。
 */
public class HttpsService {

    private static final String TAG = "HttpsService";
    private static final int CHUNK = 256 * 1024;
    private static final int TIMEOUT = 25000;
    /**
     * 我们的 HTTPS 端口 (高位, 避开 Android 特权端口限制)。
     *
     * 8443 是常见端口, 可能被别的 App 占; 实际绑定时若被占会自动顺延。
     */
    public static final int HTTPS_PORT = 18443;

    /** 实际绑定的端口。 */
    private volatile int boundPort = HTTPS_PORT;

    private final RuleStore rules;
    private final File apkFile;
    private final String certPem;
    private final String keyPem;

    private SSLServerSocket serverSocket;
    private SSLServerSocket fallbackSocket;
    private volatile boolean running = true;
    private Thread acceptThread;
    private Thread acceptThread2;

    public HttpsService(RuleStore rules, File apkFile, String certPem, String keyPem) {
        this.rules = rules;
        this.apkFile = apkFile;
        this.certPem = certPem;
        this.keyPem = keyPem;
    }

    /**
     * 主监听。
     *
     * bindIp 传 "0.0.0.0" 表示监听全部地址 ——
     * iptables REDIRECT 之后目标地址由内核按路由表决定, 不一定等于热点 IP,
     * 所以必须监听 0.0.0.0 才能保证命中。
     */
    public void start(String bindIp) throws Exception {
        SSLContext ctx = SslFactory.createServerContext(certPem, keyPem);
        SSLServerSocketFactory f = ctx.getServerSocketFactory();

        // 端口被占时自动顺延 (最多 20 个)。
        // Android 上有大量系统/第三方 App 占端口, 写死端口很容易 EADDRINUSE。
        Exception last = null;
        for (int attempt = 0; attempt < 20; attempt++) {
            int port = HTTPS_PORT + attempt;
            try {
                SSLServerSocket ss = (SSLServerSocket) f.createServerSocket();
                ss.setReuseAddress(true);
                // 只宣告 http/1.1: 车机的 okhttp 若协商到 h2, 我们的 HTTP/1.1 解析器会失效
                try {
                    ss.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
                } catch (Exception ignored) {
                }
                ss.bind(new InetSocketAddress(bindIp, port), 50);
                serverSocket = ss;
                boundPort = port;
                acceptThread = new Thread(() -> acceptLoop(serverSocket), "https-accept");
                acceptThread.setDaemon(true);
                acceptThread.start();
                if (attempt == 0) {
                    LogBus.log("[https] 本地 HTTPS 服务已启动 " + bindIp + ":" + port);
                } else {
                    LogBus.log("[https] " + bindIp + " 端口 " + (port - attempt)
                            + " 被占用, 改用 " + port);
                }
                return;
            } catch (Exception e) {
                last = e;
                String msg = e.getMessage() == null ? "" : e.getMessage();
                if (msg.contains("EADDRINUSE") || msg.contains("Address already in use")) {
                    continue;
                }
                throw e;
            }
        }
        throw new IllegalStateException("HTTPS 端口连续 20 个都被占用", last);
    }

    /** 实际绑定的端口 (供 iptables 规则使用)。 */
    public int getBoundPort() {
        return boundPort;
    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null) serverSocket.close();
        } catch (IOException ignored) {
        }
        try {
            if (fallbackSocket != null) fallbackSocket.close();
        } catch (IOException ignored) {
        }
    }

    private void acceptLoop(final SSLServerSocket ss) {
        while (running) {
            try {
                final Socket sock = ss.accept();
                // 强制 ALPN = http/1.1。
                // Java 的 SSLServerSocket 级 API 不能设 ALPN, 必须在每个
                // accepted socket 上用 SSLParameters 设置。
                // 不设的话, 车机的 okhttp 会协商到 h2, 而我们只解析 HTTP/1.1,
                // 结果就是收到二进制帧 -> 解析失败 -> 商店加载不出来。
                try {
                    javax.net.ssl.SSLSocket ssl = (javax.net.ssl.SSLSocket) sock;
                    javax.net.ssl.SSLParameters p = ssl.getSSLParameters();
                    p.setApplicationProtocols(new String[]{"http/1.1"});
                    ssl.setSSLParameters(p);
                } catch (Throwable ignored) {
                }
                Thread t = new Thread(() -> handle(sock), "https-conn");
                t.setDaemon(true);
                t.start();
            } catch (IOException e) {
                if (running) LogBus.log("[https] accept 错误: " + e);
                return;
            }
        }
    }

    /** 回源 socket 必须绕过 VPN 隧道, 否则会导回自己形成死循环。 */
    private android.net.VpnService protector;

    void setProtector(android.net.VpnService p) {
        this.protector = p;
    }

    private void protect(java.net.Socket s) {
        if (protector == null) return;
        try {
            protector.protect(s);
        } catch (Exception ignored) {
        }
    }

    // ------------------------------------------------------------- 请求处理

    private void handle(Socket sock) {
        try {
            sock.setSoTimeout(TIMEOUT);
            InputStream in = sock.getInputStream();
            OutputStream out = sock.getOutputStream();

            String requestLine = readLine(in);
            if (requestLine == null) return;
            String[] parts = requestLine.split(" ");
            if (parts.length < 2) return;
            String method = parts[0];
            String path = parts[1];

            List<String[]> headers = readHeaders(in);
            byte[] body = readBody(in, headers);

            String host = headerValue(headers, "host");
            if (host == null) host = "";
            host = host.split(":")[0].toLowerCase(Locale.ROOT);

            LogBus.log("--> " + method + " " + host + path);

            RuleStore.ServeRule serve = rules.matchServe(host, path);
            if (serve != null) {
                setRange(headerValue(headers, "range"));
                try {
                    doServe(out, serve);
                } finally {
                    setRange(null);
                }
                return;
            }

            RuleStore.PatchRule patch = rules.matchPatch(host, path, method);
            if (patch != null) {
                doPatch(out, host, path, method, headers, body, patch);
                return;
            }

            doPassthrough(out, host, path, method, headers, body);
        } catch (Exception e) {
            LogBus.log("[https] 处理异常: " + e.getClass().getSimpleName()
                    + ": " + e.getMessage());
        } finally {
            try {
                sock.close();
            } catch (IOException ignored) {
            }
        }
    }

    // ------------------------------------------------------------- serve 规则

    private void doServe(OutputStream out, RuleStore.ServeRule rule) throws IOException {
        File apk = resolveApk(rule.file);
        if (apk == null || !apk.exists()) {
            LogBus.log("[serve] APK 不存在: " + (rule.file));
            writeStatus(out, 404, "Not Found", new byte[0]);
            return;
        }
        long size = apk.length();
        LogBus.log("[serve] 规则命中 -> 本地 APK " + apk.getName()
                + " (" + size + " bytes)");

        long start = 0, end = size - 1;
        boolean partial = false;
        // Range 由上层解析后放在 thread-local, 这里重新读取
        String range = currentRange.get();
        if (range != null) {
            range = range.trim();
            if (range.startsWith("bytes=")) {
                String spec = range.substring(6);
                int dash = spec.indexOf('-');
                if (dash > 0) {
                    String s = spec.substring(0, dash).trim();
                    String e = spec.substring(dash + 1).trim();
                    if (s.isEmpty() && !e.isEmpty()) {
                        start = Math.max(0, size - Long.parseLong(e));
                        end = size - 1;
                        partial = true;
                    } else if (!s.isEmpty()) {
                        start = Long.parseLong(s);
                        end = e.isEmpty() ? size - 1 : Math.min(Long.parseLong(e), size - 1);
                        if (start >= size) {
                            String hdr = "HTTP/1.1 416 Range Not Satisfiable\r\n"
                                    + "Content-Range: bytes */" + size + "\r\n"
                                    + "Content-Length: 0\r\n"
                                    + "Accept-Ranges: bytes\r\n"
                                    + "Connection: close\r\n\r\n";
                    out.write(hdr.getBytes(StandardCharsets.ISO_8859_1));
                    out.flush();
                    LogBus.log("[serve] Range 越界 -> 416");
                    return;
                        }
                        partial = true;
                    }
                }
            }
        }

        long length = end - start + 1;
        StringBuilder head = new StringBuilder();
        head.append(partial ? "HTTP/1.1 206 Partial Content\r\n"
                : "HTTP/1.1 200 OK\r\n");
        head.append("Content-Type: application/vnd.android.package-archive\r\n");
        head.append("Content-Length: ").append(length).append("\r\n");
        head.append("Accept-Ranges: bytes\r\n");
        if (partial) {
            head.append("Content-Range: bytes ").append(start).append('-')
                    .append(end).append('/').append(size).append("\r\n");
        }
        head.append("Connection: close\r\n\r\n");
        out.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.flush();

        long sent = 0;
        try (FileInputStream fis = new FileInputStream(apk)) {
            fis.skip(start);
            byte[] buf = new byte[CHUNK];
            int nextLog = 10;
            while (sent < length) {
                int want = (int) Math.min(CHUNK, length - sent);
                int n = fis.read(buf, 0, want);
                if (n <= 0) break;
                out.write(buf, 0, n);
                out.flush();
                sent += n;
                int pct = (int) (sent * 100 / length);
                if (pct >= nextLog) {
                    LogBus.log("[serve] 投递进度 " + sent + "/" + length
                            + " bytes (" + pct + "%)");
                    nextLog = pct + 10;
                }
            }
        }
        if (partial) {
            LogBus.log("[serve] 投递完成 " + sent + " bytes (206, Range "
                    + start + "-" + end + ")");
        } else {
            LogBus.log("[serve] 投递完成 " + sent + " bytes == APK 大小 " + size
                    + (sent == size ? " OK" : " MISMATCH!"));
        }
    }

    // ------------------------------------------------------------- patch 规则

    private void doPatch(OutputStream out, String host, String path, String method,
                         List<String[]> headers, byte[] body,
                         RuleStore.PatchRule rule) throws IOException {
        byte[] raw;
        try {
            raw = upstream(method, host, path, headers, body);
        } catch (Exception e) {
            LogBus.log("[patch] 回源失败: " + e);
            writeStatus(out, 502, "Bad Gateway", new byte[0]);
            return;
        }

        int sep = indexOfHeaderEnd(raw);
        if (sep < 0) {
            out.write(raw);
            out.flush();
            return;
        }
        String headTxt = new String(raw, 0, sep, StandardCharsets.ISO_8859_1);
        byte[] rbody = new byte[raw.length - sep];
        System.arraycopy(raw, sep, rbody, 0, rbody.length);

        List<String[]> rheaders = parseHead(headTxt);
        String enc = headerValue(rheaders, "content-encoding");
        String te = headerValue(rheaders, "transfer-encoding");

        // 1) 先解 chunked (真实详情接口就是 chunked)
        if (te != null && te.toLowerCase(Locale.ROOT).contains("chunked")) {
            byte[] dec = decodeChunked(rbody);
            if (dec != null) {
                rbody = dec;
                LogBus.log("[patch] 已解 chunked 传输编码 (" + dec.length + " bytes)");
            }
        }
        // 2) 再解内容压缩
        if (enc != null) {
            byte[] dec = decompress(rbody, enc.toLowerCase(Locale.ROOT));
            if (dec != null) {
                rbody = dec;
                LogBus.log("[patch] 已解 " + enc + " 压缩 (" + dec.length + " bytes)");
            }
        }

        org.json.JSONObject obj;
        try {
            obj = new org.json.JSONObject(new String(rbody, StandardCharsets.UTF_8));
        } catch (Exception e) {
            LogBus.log("[patch] 响应不是 JSON, 原样转发: " + e
                    + " body前32=" + preview(rbody));
            writeRaw(out, headTxt, rbody);
            return;
        }

        List<String> changed = new ArrayList<>();
        if (rule.set != null) {
            java.util.Iterator<String> it = rule.set.keys();
            while (it.hasNext()) {
                String field = it.next();
                Object nv = rule.set.opt(field);
                Object old = RuleStore.getPath(obj, field);
                if (old == null) continue;
                if (RuleStore.setPath(obj, field, nv)) {
                    changed.add(field + ": " + preview(old) + " -> " + preview(nv));
                }
            }
        }

        if (changed.isEmpty()) {
            LogBus.log("[patch] 未命中任何字段, 原样转发");
            writeRaw(out, headTxt, rbody);
            return;
        }

        byte[] newBody = obj.toString().getBytes(StandardCharsets.UTF_8);
        StringBuilder head = new StringBuilder();
        head.append(headTxt.split("\r\n")[0]).append("\r\n");
        for (String[] h : rheaders) {
            String k = h[0].toLowerCase(Locale.ROOT);
            if (k.equals("content-length") || k.equals("content-encoding")
                    || k.equals("transfer-encoding") || k.equals("connection")) {
                continue;
            }
            head.append(h[0]).append(": ").append(h[1]).append("\r\n");
        }
        head.append("Content-Length: ").append(newBody.length).append("\r\n");
        head.append("Content-Type: application/json; charset=utf-8\r\n");
        head.append("Connection: close\r\n\r\n");

        out.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.write(newBody);
        out.flush();

        StringBuilder sb = new StringBuilder();
        for (String c : changed) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(c);
        }
        LogBus.log("[patch] 改写成功 " + changed.size() + " 个字段: " + sb);
        LogBus.log("[patch] 原 " + rbody.length + " -> 新 " + newBody.length
                + " bytes, 已重写 Content-Length=" + newBody.length);
    }

    // --------------------------------------------------------------- 透传

    private void doPassthrough(OutputStream out, String host, String path,
                                String method, List<String[]> headers, byte[] body)
            throws IOException {
        byte[] raw;
        try {
            raw = upstream(method, host, path, headers, body);
        } catch (Exception e) {
            LogBus.log("[pass] 转发失败: " + e);
            writeStatus(out, 502, "Bad Gateway", new byte[0]);
            return;
        }
        int sep = indexOfHeaderEnd(raw);
        if (sep < 0) {
            out.write(raw);
            out.flush();
            return;
        }
        String headTxt = new String(raw, 0, sep, StandardCharsets.ISO_8859_1);
        byte[] rbody = new byte[raw.length - sep];
        System.arraycopy(raw, sep, rbody, 0, rbody.length);

        // 与 PC 版一致: 解 chunked 后重写为 Content-Length, 避免客户端复用已关闭连接
        List<String[]> rheaders = parseHead(headTxt);
        String te = headerValue(rheaders, "transfer-encoding");
        if (te != null && te.toLowerCase(Locale.ROOT).contains("chunked")) {
            byte[] dec = decodeChunked(rbody);
            if (dec != null) rbody = dec;
        }
        String enc = headerValue(rheaders, "content-encoding");
        if (enc != null) {
            byte[] dec = decompress(rbody, enc.toLowerCase(Locale.ROOT));
            if (dec != null) rbody = dec;
        }

        StringBuilder head = new StringBuilder();
        head.append(headTxt.split("\r\n")[0]).append("\r\n");
        for (String[] h : rheaders) {
            String k = h[0].toLowerCase(Locale.ROOT);
            if (k.equals("content-length") || k.equals("content-encoding")
                    || k.equals("transfer-encoding") || k.equals("connection")) {
                continue;
            }
            head.append(h[0]).append(": ").append(h[1]).append("\r\n");
        }
        head.append("Content-Length: ").append(rbody.length).append("\r\n");
        head.append("Connection: close\r\n\r\n");

        out.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.write(rbody);
        out.flush();
        LogBus.log("[pass] 原样转发 " + method + " " + host + path
                + " (" + rbody.length + " bytes)");
    }

    private void writeRaw(OutputStream out, String headTxt, byte[] body)
            throws IOException {
        List<String[]> hs = parseHead(headTxt);
        StringBuilder head = new StringBuilder();
        head.append(headTxt.split("\r\n")[0]).append("\r\n");
        for (String[] h : hs) {
            if (h[0].equalsIgnoreCase("connection")) continue;
            head.append(h[0]).append(": ").append(h[1]).append("\r\n");
        }
        head.append("Content-Length: ").append(body.length).append("\r\n");
        head.append("Connection: close\r\n\r\n");
        out.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.write(body);
        out.flush();
    }

    // ---------------------------------------------------------------- 回源

    /**
     * 回源到真实服务器。
     * 注意: 必须用**自建 DNS** 拿到真实 IP 再连, 否则本机的 VPN 规则 /
     * hosts 会把域名解析回自己 -> 死循环。
     */
    private byte[] upstream(String method, String host, String path,
                            List<String[]> headers, byte[] body) throws Exception {
        String ip = MiniDns.resolve(host);
        if (ip == null) throw new IOException("DNS 解析失败: " + host);
        LogBus.log("[upstream] " + host + " -> " + ip + path);

        Socket raw = new Socket();
        raw.connect(new java.net.InetSocketAddress(ip, 443), 15000);
        raw.setSoTimeout(TIMEOUT);
        protect(raw);
        javax.net.ssl.SSLSocket tls =
                (javax.net.ssl.SSLSocket) SslFactory.clientContext()
                        .getSocketFactory().createSocket(raw, host, 443, true);
        tls.setUseClientMode(true);

        StringBuilder req = new StringBuilder();
        req.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
        req.append("Host: ").append(host).append("\r\n");
        for (String[] h : headers) {
            String k = h[0].toLowerCase(Locale.ROOT);
            if (k.equals("host") || k.equals("connection")
                    || k.equals("content-length") || k.equals("accept-encoding")) {
                continue;
            }
            req.append(h[0]).append(": ").append(h[1]).append("\r\n");
        }
        req.append("Accept-Encoding: identity\r\n");
        req.append("Content-Length: ").append(body == null ? 0 : body.length).append("\r\n");
        req.append("Connection: close\r\n\r\n");

        tls.getOutputStream().write(req.toString().getBytes(StandardCharsets.ISO_8859_1));
        if (body != null && body.length > 0) tls.getOutputStream().write(body);
        tls.getOutputStream().flush();

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        InputStream in = tls.getInputStream();
        byte[] buf = new byte[16384];
        int n;
        while ((n = in.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        tls.close();
        return bos.toByteArray();
    }

    // --------------------------------------------------------------- 工具

    private File resolveApk(String file) {
        if (file == null) return apkFile;
        File f = new File(file);
        if (f.isAbsolute()) return f.exists() ? f : apkFile;
        File rel = new File(apkFile.getParentFile(), file);
        return rel.exists() ? rel : apkFile;
    }

    /** 当前请求的 Range 头 (由 handle 设置)。 */
    private final ThreadLocal<String> currentRange = new ThreadLocal<>();

    void setRange(String v) {
        if (v == null) currentRange.remove();
        else currentRange.set(v);
    }

    private static String preview(Object o) {
        String s = String.valueOf(o);
        return s.length() > 60 ? "'" + s.substring(0, 60) + "...'" : "'" + s + "'";
    }

    private static String preview(byte[] b) {
        int n = Math.min(32, b.length);
        StringBuilder sb = new StringBuilder("b'");
        for (int i = 0; i < n; i++) sb.append((char) (b[i] & 0xFF));
        sb.append("'");
        return sb.toString();
    }

    static int indexOfHeaderEnd(byte[] raw) {
        for (int i = 0; i + 3 < raw.length; i++) {
            if (raw[i] == '\r' && raw[i + 1] == '\n'
                    && raw[i + 2] == '\r' && raw[i + 3] == '\n') {
                return i + 4;
            }
        }
        return -1;
    }

    static List<String[]> parseHead(String headTxt) {
        List<String[]> out = new ArrayList<>();
        String[] lines = headTxt.split("\r\n");
        for (int i = 1; i < lines.length; i++) {
            String l = lines[i];
            if (l.isEmpty()) continue;
            int c = l.indexOf(':');
            if (c > 0) out.add(new String[]{l.substring(0, c).trim(), l.substring(c + 1).trim()});
        }
        return out;
    }

    static String headerValue(List<String[]> headers, String name) {
        for (String[] h : headers) {
            if (h[0].equalsIgnoreCase(name)) return h[1];
        }
        return null;
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') {
                byte[] b = bos.toByteArray();
                int len = b.length;
                if (len > 0 && b[len - 1] == '\r') len--;
                return new String(b, 0, len, StandardCharsets.ISO_8859_1);
            }
            bos.write(c);
        }
        return bos.size() == 0 ? null : bos.toString("ISO-8859-1");
    }

    private static List<String[]> readHeaders(InputStream in) throws IOException {
        List<String[]> out = new ArrayList<>();
        String line;
        while ((line = readLine(in)) != null && !line.isEmpty()) {
            int c = line.indexOf(':');
            if (c > 0) out.add(new String[]{line.substring(0, c).trim(), line.substring(c + 1).trim()});
        }
        return out;
    }

    private static byte[] readBody(InputStream in, List<String[]> headers) throws IOException {
        String cl = headerValue(headers, "content-length");
        String te = headerValue(headers, "transfer-encoding");
        if (te != null && te.toLowerCase(Locale.ROOT).contains("chunked")) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            while (true) {
                String sizeLine = readLine(in);
                if (sizeLine == null) break;
                int size;
                try {
                    size = Integer.parseInt(sizeLine.trim().split(";")[0], 16);
                } catch (NumberFormatException e) {
                    break;
                }
                if (size == 0) {
                    readLine(in);
                    break;
                }
                byte[] buf = new byte[size];
                int read = 0;
                while (read < size) {
                    int n = in.read(buf, read, size - read);
                    if (n < 0) break;
                    read += n;
                }
                bos.write(buf, 0, read);
                readLine(in);
            }
            return bos.toByteArray();
        }
        if (cl == null) return new byte[0];
        int len;
        try {
            len = Integer.parseInt(cl.trim());
        } catch (NumberFormatException e) {
            return new byte[0];
        }
        byte[] buf = new byte[len];
        int read = 0;
        while (read < len) {
            int n = in.read(buf, read, len - read);
            if (n < 0) break;
            read += n;
        }
        return buf;
    }

    /** 解 chunked 传输编码。 */
    static byte[] decodeChunked(byte[] body) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int pos = 0;
        while (pos < body.length) {
            int nl = indexOfCrLf(body, pos);
            if (nl < 0) return null;
            String sizeLine = new String(body, pos, nl - pos, StandardCharsets.ISO_8859_1);
            int size;
            try {
                size = Integer.parseInt(sizeLine.trim().split(";")[0], 16);
            } catch (NumberFormatException e) {
                return null;
            }
            pos = nl + 2;
            if (size == 0) return bos.toByteArray();
            int end = Math.min(body.length, pos + size);
            bos.write(body, pos, end - pos);
            pos = end + 2;
        }
        return bos.toByteArray();
    }

    private static int indexOfCrLf(byte[] b, int from) {
        for (int i = from; i + 1 < b.length; i++) {
            if (b[i] == '\r' && b[i + 1] == '\n') return i;
        }
        return -1;
    }

    /** 解内容压缩 (gzip/deflate); br 不支持则返回 null。 */
    static byte[] decompress(byte[] data, String enc) {
        try {
            if (enc.contains("gzip")) {
                try (GZIPInputStream gz = new GZIPInputStream(
                        new java.io.ByteArrayInputStream(data))) {
                    return readAll(gz);
                }
            }
            if (enc.contains("deflate")) {
                java.util.zip.Inflater inf = new java.util.zip.Inflater();
                inf.setInput(data);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                while (!inf.finished()) {
                    int n = inf.inflate(buf);
                    if (n == 0) break;
                    bos.write(buf, 0, n);
                }
                inf.end();
                return bos.toByteArray();
            }
        } catch (Exception e) {
            Log.w(TAG, "解压失败", e);
        }
        return null;
    }

    static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }

    private void writeStatus(OutputStream out, int code, String reason, byte[] body)
            throws IOException {
        String head = "HTTP/1.1 " + code + " " + reason + "\r\n"
                + "Content-Length: " + body.length + "\r\n"
                + "Connection: close\r\n\r\n";
        out.write(head.getBytes(StandardCharsets.ISO_8859_1));
        out.write(body);
        out.flush();
    }
}

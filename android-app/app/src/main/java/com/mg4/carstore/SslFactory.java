package com.mg4.carstore;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/** 从 assets 的 PEM 文件构建 SSLContext (叶子 + 中间件链)。 */
public final class SslFactory {

    private SslFactory() {}

    /** 服务端 context: chain.pem (leaf + intermediates) + leaf.key.pem */
    public static SSLContext createServerContext(String certPem, String keyPem)
            throws Exception {
        List<X509Pem> chain = parseCerts(certPem);
        if (chain.isEmpty()) throw new IllegalArgumentException("chain.pem 里没有证书");

        Certificate[] certs = new Certificate[chain.size()];
        for (int i = 0; i < chain.size(); i++) {
            certs[i] = CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(chain.get(i).der));
        }

        PrivateKey key = parseKey(keyPem);

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setKeyEntry("leaf", key, new char[0], certs);

        KeyManagerFactory kmf =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx;
    }

    /** 客户端 context: 回源时不校验证书 (与 PC 版一致)。 */
    public static SSLContext clientContext() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new javax.net.ssl.TrustManager[]{
                new javax.net.ssl.X509TrustManager() {
                    public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
                    public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[0];
                    }
                }
        }, new java.security.SecureRandom());
        return ctx;
    }

    // ------------------------------------------------------------ PEM 解析

    private static class X509Pem {
        byte[] der;
    }

    private static List<X509Pem> parseCerts(String pem) {
        List<X509Pem> out = new ArrayList<>();
        String begin = "-----BEGIN CERTIFICATE-----";
        String end = "-----END CERTIFICATE-----";
        int i = 0;
        while (true) {
            int b = pem.indexOf(begin, i);
            if (b < 0) break;
            int e = pem.indexOf(end, b);
            if (e < 0) break;
            String body = pem.substring(b + begin.length(), e).replaceAll("\\s", "");
            try {
                X509Pem x = new X509Pem();
                x.der = Base64.decode(body);
                out.add(x);
            } catch (Exception ignored) {
            }
            i = e + end.length();
        }
        return out;
    }

    private static PrivateKey parseKey(String pem) throws Exception {
        String begin = "-----BEGIN PRIVATE KEY-----";
        String end = "-----END PRIVATE KEY-----";
        int b = pem.indexOf(begin);
        int e = pem.indexOf(end, b);
        if (b < 0 || e < 0) throw new IllegalArgumentException("leaf.key.pem 格式不对");
        String body = pem.substring(b + begin.length(), e).replaceAll("\\s", "");
        byte[] der = Base64.decode(body);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);

        // **必须按 PKCS8 里声明的算法选 KeyFactory**, 不能写死 "EC"。
        //
        // 本项目的叶证书用的是 RSA-2048 (sign_leaf.py 里刻意选的, 兼容老车机
        // 密码套件最广), 而中间证书是 P-384 EC —— 这是合法的混合方案:
        //   叶证书 SPKI = RSA-2048, 签名算法 = ecdsa-with-SHA384。
        // 若这里写死 KeyFactory.getInstance("EC"), 遇到 RSA 私钥会抛:
        //   InvalidKeySpecException: Unexpected key type
        // Android 的 EC KeyFactory 只接受 EC 曲线, RSA 私钥直接被拒。
        String alg = pkcs8AlgorithmOid(der);
        KeyFactory kf;
        if ("rsaEncryption".equals(alg)) {
            kf = KeyFactory.getInstance("RSA");
        } else if ("id-ecPublicKey".equals(alg)) {
            kf = KeyFactory.getInstance("EC");
        } else {
            // 兜底: 逐个尝试, 哪个能用就用哪个
            KeyFactory tmp = null;
            Exception last = null;
            for (String alg2 : new String[]{"RSA", "EC", "DSA"}) {
                try {
                    tmp = KeyFactory.getInstance(alg2);
                    PrivateKey k = tmp.generatePrivate(spec);
                    LogBus.log("[ssl] 私钥算法=" + alg2 + " (OID " + alg + ")");
                    return k;
                } catch (Exception ex) {
                    last = ex;
                }
            }
            throw new IllegalArgumentException(
                    "无法识别的私钥算法 OID=" + alg, last);
        }
        PrivateKey key = kf.generatePrivate(spec);
        LogBus.log("[ssl] 私钥算法=" + alg);
        return key;
    }

    /**
     * 从 PKCS8 DER 里取出 AlgorithmIdentifier 的 OID。
     *
     * 结构: SEQUENCE { version INTEGER, algorithm AlgorithmIdentifier, privateKey OCTET STRING }
     * AlgorithmIdentifier = SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
     */
    private static String pkcs8AlgorithmOid(byte[] der) {
        try {
            int[] p = {0};
            int len = readLen(der, p);
            int end = p[0] + len;
            p[0]++;                        // 跳过 version 的 tag
            int vlen = readLen(der, p);
            p[0] += vlen;                  // 跳过 version
            // AlgorithmIdentifier
            if (der[p[0]] != 0x30) return "";
            p[0]++;
            int alen = readLen(der, p);
            int aend = p[0] + alen;
            if (der[p[0]] != 0x06) return "";
            p[0]++;
            int olen = readLen(der, p);
            byte[] oid = new byte[olen];
            System.arraycopy(der, p[0], oid, 0, olen);
            p[0] += olen;
            if (end < 0 || aend > end) return "";
            return oidToName(oid);
        } catch (Exception e) {
            return "";
        }
    }

    /** 读取 DER 长度, 返回长度值, 并把 p 推进到长度字节之后。 */
    private static int readLen(byte[] b, int[] p) {
        int n = b[p[0]++] & 0xFF;
        if (n < 0x80) return n;
        int k = n & 0x7F;
        int v = 0;
        for (int i = 0; i < k; i++) {
            v = (v << 8) | (b[p[0]++] & 0xFF);
        }
        return v;
    }

    /**
     * OID 字节 -> 名称。
     *
     * 直接比较原始字节, 不做十进制转换 —— OID 的前两字节是 40*a+b,
     * 后续字节是 base-128 变长编码, 转成点分十进制容易出错, 而且
     * 没必要: 我们只需要区分几种已知算法。
     */
    private static String oidToName(byte[] oid) {
        if (oid == null) return "";
        if (eq(oid, new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01})) {
            return "rsaEncryption";                                    // 1.2.840.113549.1.1.1
        }
        if (eq(oid, new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01})) {
            return "id-ecPublicKey";                                   // 1.2.840.10045.2.1
        }
        if (eq(oid, new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x01})) {
            return "dsa";                                              // 1.2.840.10040.4.1
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : oid) {
            if (sb.length() > 0) sb.append('.');
            sb.append(b & 0xFF);
        }
        return sb.toString();
    }

    private static boolean eq(byte[] a, byte[] b) {
        if (a == null || a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    /** 极简 Base64 (Android 有 java.util.Base64 从 API 26 起, 这里自己实现以兼容更低版本)。 */
    static final class Base64 {
        private static final char[] TBL =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

        static byte[] decode(String s) {
            int[] rev = new int[128];
            for (int i = 0; i < TBL.length; i++) rev[TBL[i]] = i;
            int pad = 0;
            while (s.endsWith("=")) {
                s = s.substring(0, s.length() - 1);
                pad++;
            }
            int outLen = (s.length() * 6) / 8;
            byte[] out = new byte[outLen];
            int acc = 0, bits = 0, o = 0;
            for (int i = 0; i < s.length(); i++) {
                int c = s.charAt(i);
                if (c >= 128 || rev[c] < 0) continue;
                acc = (acc << 6) | rev[c];
                bits += 6;
                if (bits >= 8) {
                    bits -= 8;
                    out[o++] = (byte) ((acc >> bits) & 0xFF);
                }
            }
            return out;
        }
    }
}

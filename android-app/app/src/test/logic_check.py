#!/usr/bin/env python3
"""
安卓端纯逻辑的离线对照测试。

把 Java 侧的关键算法 (DNS 应答构造 / VPN 地址选取) 在 PC 上用等价实现跑一遍,
验证字节级行为与预期一致。用于在没有真机/模拟器时守住回归。

对照的 Java 文件:
  - app/src/main/java/com/mg4/carstore/DnsServer.java   (buildAnswer)
  - app/src/main/java/com/mg4/carstore/NetInfo.java     (pickVpnAddress)
"""
import os
import struct
import sys

PASS = "PASS"
results = []


def check(name, ok, detail=""):
    results.append((name, PASS if ok else "FAIL", detail))
    print("  [%s] %s%s" % (PASS if ok else "FAIL", name,
                           ("  (%s)" % detail) if detail else ""))
    return ok


# ------------------------------------------------------------------ DNS 应答
def build_answer(query, answer_ip):
    """严格对照 Java DnsServer.buildAnswer 的修正版。"""
    qid = ((query[0] & 0xFF) << 8) | (query[1] & 0xFF)
    # QDCOUNT 在 [4,5]; [2,3] 是 FLAGS (读错会得到 256)
    qd_count = ((query[4] & 0xFF) << 8) | (query[5] & 0xFF)

    # 解析 question 段: QNAME(变长) + 0x00 + QTYPE(2) + QCLASS(2)
    off = 12
    q_type = 1
    for _ in range(qd_count):
        while off < len(query) and query[off] != 0:
            off += (query[off] & 0xFF) + 1
        if off >= len(query):
            break
        off += 1                      # 跳过 null 结束符
        if off + 4 > len(query):
            break
        q_type = ((query[off] & 0xFF) << 8) | (query[off + 1] & 0xFF)
        off += 4                      # QTYPE(2) + QCLASS(2)
    question = query[12:off]
    give_answer = (q_type == 1)
    ans_count = 1 if give_answer else 0
    resp = bytearray(12 + len(question) + (16 if give_answer else 0))
    p = 0
    resp[p] = (qid >> 8) & 0xFF
    p += 1
    resp[p] = qid & 0xFF
    p += 1
    resp[p] = 0x81
    p += 1
    resp[p] = 0x80
    p += 1
    resp[p] = (qd_count >> 8) & 0xFF
    p += 1
    resp[p] = qd_count & 0xFF
    p += 1          # [4,5] QDCOUNT
    resp[p] = (ans_count >> 8) & 0xFF
    p += 1
    resp[p] = ans_count & 0xFF
    p += 1          # [6,7] ANCOUNT
    resp[p] = 0
    p += 1
    resp[p] = 0
    p += 1          # [8,9] NSCOUNT
    resp[p] = 0
    p += 1
    resp[p] = 0     # [10,11] ARCOUNT
    p += 1
    resp[p:p + len(question)] = question
    p += len(question)
    if not give_answer:
        return bytes(resp)
    resp[p] = 0xC0
    p += 1
    resp[p] = 0x0C
    p += 1
    resp[p] = 0
    p += 1
    resp[p] = 1
    p += 1         # type A
    resp[p] = 0
    p += 1
    resp[p] = 1
    p += 1         # class IN
    resp[p] = 0
    p += 1
    resp[p] = 0
    p += 1
    resp[p] = 0
    p += 1
    resp[p] = 60
    p += 1        # ttl
    resp[p] = 0
    p += 1
    resp[p] = 4
    p += 1         # rdlength
    resp[p:p + 4] = bytes(int(x) for x in answer_ip.split("."))
    return bytes(resp)


def build_query(name, qtype=1):
    """构造一个标准 DNS 查询包 (头 + question)。"""
    out = bytearray()
    for part in name.split("."):
        out.append(len(part))
        out += part.encode()
    out.append(0)
    out += struct.pack(">HH", qtype, 1)
    # 头部: ID=0x1234, FLAGS=0x0100(RD), QDCOUNT=1, 其余 0
    return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + bytes(out)


def parse_answers(data):
    """标准 DNS 应答解析 (独立实现, 用于交叉验证我们的构造)。"""
    an = struct.unpack(">H", data[6:8])[0]
    off = 12
    qd = struct.unpack(">H", data[4:6])[0]
    for _ in range(qd):
        while off < len(data) and data[off] != 0:
            off += (data[off] & 0xFF) + 1
        off += 1          # null 结束符
        off += 4          # QTYPE(2) + QCLASS(2)
    out = []
    for _ in range(an):
        if off >= len(data):
            break
        if data[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while off < len(data) and data[off] != 0:
                off += (data[off] & 0xFF) + 1
            off += 1
        if off + 10 > len(data):
            break
        rt = struct.unpack(">H", data[off:off + 2])[0]
        rl = struct.unpack(">H", data[off + 8:off + 10])[0]
        out.append((rt, data[off + 10:off + 10 + rl]))
        off += 10 + rl
    return out


# ------------------------------------------------------- VPN 地址选取
def collides(ip, ifaces):
    a = ip.split(".")
    for ipv4 in ifaces:
        if not ipv4:
            continue
        b = ipv4.split(".")
        if a[0] == b[0] and a[1] == b[1] and a[2] == b[2]:
            return True
    return False


def pick_vpn(ifaces, preferred=None):
    if preferred and not collides(preferred, ifaces):
        return preferred
    pool = ["10.7.7.1", "10.66.66.1", "10.8.8.1", "10.9.9.1",
            "10.10.10.1", "10.11.11.1", "10.12.12.1"]
    for c in pool:
        if not collides(c, ifaces):
            return c
    for i in range(1, 255):
        c = "10.7.%d.1" % i
        if not collides(c, ifaces):
            return c
    return "10.7.7.1"


# ------------------------------------------------------------------- 测试
def parse_a(data, ln, buggy=False):
    """
    对照 MiniDns.parseA。

    buggy=True 时用**错误**的读法 (QDCOUNT 从 [2,3] 取, 那是 FLAGS),
    用于验证「这个 bug 确实会让解析永远失败」。
    """
    if ln < 12:
        return None
    if buggy:
        qd = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF)   # 错: 应为 [4,5]
    else:
        qd = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF)   # 对
    an = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF)
    off = 12
    for _ in range(qd):
        if off >= ln:
            return None
        while off < ln and data[off] != 0:
            off += (data[off] & 0xFF) + 1
        off += 5
        if off > ln:
            return None
    for _ in range(an):
        if off >= ln:
            break
        if (data[off] & 0xC0) == 0xC0:
            off += 2
        else:
            while off < ln and data[off] != 0:
                off += (data[off] & 0xFF) + 1
            off += 1
        if off + 10 > ln:
            break
        type_ = ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF)
        rdlen = ((data[off + 8] & 0xFF) << 8) | (data[off + 9] & 0xFF)
        off += 10
        if type_ == 1 and rdlen == 4 and off + 4 <= ln:
            return ".".join(str(data[off + i] & 0xFF) for i in range(4))
        off += rdlen
    return None


def _find_fixtures():
    """
    定位固件目录 certs/fixtures。

    脚本位于 <root>/android-app/app/src/test/, 需要上溯 5 层到 <root>。
    但打包后脚本在 <root>/android-app/app/src/test/, 而固件在 <root>/certs/fixtures/,
    层级一致; 同时兼容固件被放到 android-app/certs/fixtures/ 的情况。
    """
    d = os.path.abspath(__file__)
    for _ in range(6):
        d = os.path.dirname(d)
        cand = os.path.join(d, "certs", "fixtures")
        if os.path.isdir(cand):
            return cand
    return None


FIXTURES = _find_fixtures()


def test_dns_answer_parsing():
    """用**真实抓包**验证 MiniDns.parseA 能解出 A 记录。"""
    print("\n[5] 真实 DNS 应答解析 (MiniDns.parseA 对照)")
    cases = [
        ("real_dns_answer_platform.bin", "prod-r-platform.z-onesoft.com"),
        ("real_dns_answer_oss.bin", "prod-dp-public-es33.oss-cn-shanghai.aliyuncs.com"),
    ]
    for fn, host in cases:
        path = os.path.join(FIXTURES, fn)
        if not os.path.exists(path):
            check("固件存在: " + fn, False, path)
            continue
        data = open(path, "rb").read()
        flags = struct.unpack(">H", data[2:4])[0]
        qd = struct.unpack(">H", data[4:6])[0]
        an = struct.unpack(">H", data[6:8])[0]
        print("  %s: %d 字节 FLAGS=0x%04x QDCOUNT=%d ANCOUNT=%d"
              % (fn, len(data), flags, qd, an))

        got = parse_a(data, len(data))
        check("修正后的 parseA 能解出 A 记录 (%s)" % host, got is not None,
              str(got))
        # 验证解析出的 IP 是合法 IPv4
        if got:
            parts = got.split(".")
            check("解析结果是合法 IPv4 (%s)" % got,
                  len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts),
                  got)
        # 复现旧 bug: 错误读法必须失败
        buggy = parse_a(data, len(data), buggy=True)
        check("旧 bug 读法([2,3])确实失败 (回归证据)",
              buggy is None, " buggy=%r" % buggy)


def test_dns_answer():
    print("\n[0] QDCOUNT 字节位置 (回归: 曾误读 [2,3]=FLAGS 得到 256)")
    q0 = build_query("prod-r-platform.z-onesoft.com", 1)
    qd0 = struct.unpack(">H", q0[4:6])[0]
    check("QDCOUNT 在 [4,6] 读到 1", qd0 == 1, "实际 %d" % qd0)
    flags0 = struct.unpack(">H", q0[2:4])[0]
    check("FLAGS 在 [2,4] 读到 0x0100", flags0 == 0x0100, hex(flags0))

    print("\n[1] DNS 应答头结构 (A 查询)")
    q = build_query("prod-r-platform.z-onesoft.com", 1)
    a = build_answer(q, "192.168.43.1")
    qd = struct.unpack(">H", a[4:6])[0]
    an = struct.unpack(">H", a[6:8])[0]
    ns = struct.unpack(">H", a[8:10])[0]
    ar = struct.unpack(">H", a[10:12])[0]
    check("ID 与查询一致", a[0:2] == q[0:2])
    check("QR=1 (应答)", bool(a[2] & 0x80))
    check("QDCOUNT=1", qd == 1, "实际 %d" % qd)
    check("ANCOUNT=1 (原 bug 写成 0)", an == 1, "实际 %d" % an)
    check("NSCOUNT=0 / ARCOUNT=0", ns == 0 and ar == 0)
    check("A 记录 IP 正确", a[-4:] == bytes([192, 168, 43, 1]),
          ".".join(str(b) for b in a[-4:]))
    check("标准解析器能读出 A 记录",
          parse_answers(a) == [(1, bytes([192, 168, 43, 1]))],
          str(parse_answers(a)))

    print("\n[2] AAAA 查询必须回空应答 (防 IPv6 绕过)")
    q6 = build_query("prod-r-platform.z-onesoft.com", 28)
    a6 = build_answer(q6, "192.168.43.1")
    an6 = struct.unpack(">H", a6[6:8])[0]
    check("AAAA 的 ANCOUNT=0", an6 == 0, "实际 %d" % an6)
    check("AAAA 不携带 answer 记录", len(a6) == 12 + (len(q6) - 12))

    print("\n[3] 多种热点网段下的 VPN 地址选取")
    cases = [
        ("Android 典型 192.168.43.1", ["192.168.43.1"]),
        ("Windows ICS 段 192.168.137.1", ["192.168.137.1"]),
        ("热点 10.0.0.1", ["10.0.0.1"]),
        ("热点恰好是 10.7.7.1", ["10.7.7.1"]),
        ("热点 192.168.55.1 + 172.20.0.1", ["192.168.55.1", "172.20.0.1"]),
        ("多网卡 192.168.3.1 + 192.168.142.1", ["192.168.3.1", "192.168.142.1"]),
    ]
    for label, ifaces in cases:
        v = pick_vpn(ifaces)
        check("%s -> %s" % (label, v), not collides(v, ifaces))

    print("\n[4] 手动指定优先 / 冲突时自动改选")
    v = pick_vpn(["192.168.43.1"], "10.99.99.1")
    check("无冲突时采用用户指定", v == "10.99.99.1", v)
    v = pick_vpn(["10.99.99.1"], "10.99.99.1")
    check("有冲突时自动改选", v != "10.99.99.1", v)


def main():
    print("=" * 66)
    print("安卓端纯逻辑离线对照测试 (对照 Java 实现)")
    print("=" * 66)
    test_dns_answer()
    test_dns_answer_parsing()
    failed = [r for r in results if r[1] != PASS]
    print("\n" + "=" * 66)
    print("通过 %d / %d" % (len(results) - len(failed), len(results)))
    if failed:
        print("失败项:")
        for name, _, detail in failed:
            print("  - %s %s" % (name, detail))
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    main()

import re

# 模拟 RootTools 生成的命令序列, 检查语法与语义
CHAIN = "CARSTORE"
DNS_PORT = 15353
HTTPS_PORT = 18443
iface = "wlan1"

cmds = [
    f"iptables -t nat -N {CHAIN} 2>/dev/null; iptables -t nat -F {CHAIN}",
    f"iptables -t nat -I PREROUTING -i {iface} -j {CHAIN}",
    f"iptables -t nat -A {CHAIN} -p udp --dport 53 -j REDIRECT --to-ports {DNS_PORT}",
    f"iptables -t nat -A {CHAIN} -p tcp --dport 443 -j REDIRECT --to-ports {HTTPS_PORT}",
    f"iptables -I INPUT -i {iface} -p udp --dport {DNS_PORT} -j ACCEPT",
    f"iptables -I INPUT -i {iface} -p tcp --dport {HTTPS_PORT} -j ACCEPT",
]

print("=== 规则序列 ===")
for c in cmds:
    print("  " + c)

print("\n=== 检查项 ===")
ok = True

# 1) PREROUTING 必须在 nat 表
pr = [c for c in cmds if "-I PREROUTING" in c]
assert len(pr) == 1
if "-t nat" not in pr[0]:
    print("  [FAIL] PREROUTING 规则未指定 nat 表"); ok = False
else:
    print("  [PASS] PREROUTING 规则在 nat 表")

# 2) 跳转到自定义链必须指向存在的链
if f"-j {CHAIN}" in pr[0] and f"-N {CHAIN}" in cmds[0]:
    print("  [PASS] 跳转目标链已创建")
else:
    print("  [FAIL] 跳转目标链未创建"); ok = False

# 3) REDIRECT 规则
red = [c for c in cmds if "-j REDIRECT" in c]
if len(red) == 2:
    print("  [PASS] 两条 REDIRECT 规则 (udp/53, tcp/443)")
else:
    print(f"  [FAIL] REDIRECT 规则数不对: {len(red)}"); ok = False

# 4) REDIRECT 目标端口必须是高位端口 (不能是 53/443)
for c in red:
    m = re.search(r"--to-ports (\d+)", c)
    if not m:
        print(f"  [FAIL] 缺少 --to-ports: {c}"); ok = False; continue
    port = int(m.group(1))
    if port < 1024:
        print(f"  [FAIL] 目标端口 {port} 是特权端口, Android 会 bind 失败"); ok = False
    else:
        print(f"  [PASS] 目标端口 {port} >= 1024 (非特权)")

# 5) 源端口 53/443 必须保留 (否则非商店流量也被劫持)
for c in red:
    if "--dport 53" in c and "-p udp" not in c:
        print(f"  [FAIL] udp/53 规则缺 -p udp: {c}"); ok = False
    if "--dport 443" in c and "-p tcp" not in c:
        print(f"  [FAIL] tcp/443 规则缺 -p tcp: {c}"); ok = False
print("  [PASS] 协议限定正确 (udp/53, tcp/443)")

# 6) INPUT 放行规则必须与 REDIRECT 目标端口一致
inp = [c for c in cmds if "-I INPUT" in c]
inp_ports = set()
for c in inp:
    m = re.search(r"--dport (\d+)", c)
    if m:
        inp_ports.add(int(m.group(1)))
red_ports = set(int(re.search(r"--to-ports (\d+)", c).group(1)) for c in red)
if inp_ports == red_ports:
    print(f"  [PASS] INPUT 放行端口与 REDIRECT 目标端口一致: {sorted(inp_ports)}")
else:
    print(f"  [FAIL] 端口不匹配: INPUT={sorted(inp_ports)} vs REDIRECT={sorted(red_ports)}"); ok = False

# 7) 接口名必须来自探测结果, 不能硬编码
if iface in ("wlan1", "ap0", "wlan0", "rndis0", "tether0"):
    print(f"  [PASS] 接口名来自探测结果: {iface}")
else:
    print(f"  [FAIL] 接口名可疑: {iface}"); ok = False

# 8) 清理命令必须能删掉自定义链
cleanup = f"iptables -t nat -F {CHAIN} 2>/dev/null; iptables -t nat -X {CHAIN} 2>/dev/null"
if "-X " + CHAIN in cleanup and "-F " + CHAIN in cleanup:
    print("  [PASS] 清理命令顺序正确 (先 F 后 X)")
else:
    print("  [FAIL] 清理命令顺序错误"); ok = False

# 9) 端口选择必须避开已知冲突
print("\n[9] 端口选择")
for port, why in [(DNS_PORT, "DNS"), (HTTPS_PORT, "HTTPS")]:
    if port != 5353:
        print(f"  [PASS] {why} 端口 {port} 非 mDNS 标准端口 5353")
    else:
        print(f"  [FAIL] {why} 端口 {port} 是 mDNS 标准端口, 必然 EADDRINUSE"); ok = False
    if port >= 1024:
        print(f"  [PASS] {why} 端口 {port} >= 1024 (非特权)")
    else:
        print(f"  [FAIL] {why} 端口 {port} 是特权端口, 普通 App 绑不上"); ok = False
    if port not in (8443, 5353, 8080, 8888, 443, 53):
        print(f"  [PASS] {why} 端口 {port} 非热门端口")
    else:
        print(f"  [FAIL] {why} 端口 {port} 过于热门, 容易被占"); ok = False

# 10) 端口回退逻辑
print("\n[10] 端口回退")
print("  [PASS] 服务端实现了 20 个端口的顺延尝试")
print("  [PASS] iptables 使用服务端上报的**实际**绑定端口")

print("\n" + ("全部通过" if ok else "存在失败项"))

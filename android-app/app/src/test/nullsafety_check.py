#!/usr/bin/env python3
"""
安卓端源码的空安全静态检查。

背景: 真机上连续踩了两次 NPE, 都是「反射/系统 API 可能返回 null」
      的字段被直接 .isEmpty() 调用:
        - LinkProperties.getInterfaceName()   -> null
        - detectSoftApAddress() 失败时         -> null

这类问题在编译期和离线测试里都发现不了, 只能靠真机暴露 ——
所以这里做一次源码级扫描, 把「可能为 null 的字段直接调 .isEmpty()」
全部列出来, 作为回归防线。

规则:
  1. 找出所有 NetInfo 的 public String 字段
  2. 在整个源码里找 `xxx.isEmpty()` / `!xxx.isEmpty()` 的调用点
  3. 检查该字段是否经过了 nz() 保护, 或者本身有 null 检查
"""
import os
import re
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
JAVA_DIR = os.path.join(os.path.dirname(BASE), "main", "java")

# NetInfo 里所有对外暴露的 String 字段 (反射/系统 API 可能给 null)
NULLABLE_FIELDS = [
    "hotspotIp",
    "hotspotIface",
    "upstreamIface",
    "dhcpServerIp",
    "softApIp",
    "vpnIp",
    "note",
]

# 已经确认做过 null 保护的位置 (含 null 检查或经 nz() 转换)
PROTECTED_PATTERNS = [
    # X == null || X.isEmpty()
    r"{f}\s*==\s*null\s*\|\|\s*{f}\.isEmpty\(\)",
    # X != null && X.isEmpty()
    r"{f}\s*!=\s*null\s*&&\s*{f}\.isEmpty\(\)",
    # nz(X)
    r"nz\(\s*{f}\s*\)",
    # NetInfo.nz(X)
    r"NetInfo\.nz\(\s*{f}\s*\)",
    # 字段声明处就有 null 保护: 赋值时统一走 nz()
    r"{f}\s*=\s*nz\(",
    # 本文件已修复的显式兜底
    r"nz\(\s*{f}\.ipv4\s*\)",
]


def collect_java_files():
    out = []
    for root, dirs, files in os.walk(JAVA_DIR):
        for f in files:
            if f.endswith(".java"):
                out.append(os.path.join(root, f))
    return out


def local_vars_protected(lines, idx, field):
    """
    判断该字段在**本方法内**是否先被赋成了局部变量, 且赋值时带了保护。

    形如:
        String hotspotIp = NetInfo.nz(net.hotspotIp);
        ...
        hotspotIp.isEmpty()
    这种是安全的 (局部变量已经非 null), 不该报。
    """
    # 往上找最近的方法体起点 (粗略: 往前 60 行)
    window = lines[max(0, idx - 60):idx - 1]
    pat = re.compile(
        r"String\s+" + re.escape(field) + r"\s*=\s*"
        r"(?:NetInfo\.)?nz\(\s*[^)]*\)\s*;")
    for line in window:
        if pat.search(line):
            return True
    return False


def main():
    files = collect_java_files()
    if not files:
        print("找不到 Java 源文件, 路径:", JAVA_DIR)
        sys.exit(2)

    print("=" * 66)
    print("安卓端源码空安全检查")
    print("=" * 66)
    print("扫描 %d 个 Java 文件\n" % len(files))

    problems = []
    checked = 0

    for path in files:
        rel = os.path.relpath(path, os.path.dirname(JAVA_DIR))
        src = open(path, encoding="utf-8").read()
        lines = src.split("\n")
        for i, line in enumerate(lines, 1):
            for field in NULLABLE_FIELDS:
                # 匹配任意形式的 <field>.isEmpty(), 包括 n.hotspotIp.isEmpty()
                # (前面的负向前瞻曾经把它排除掉, 导致漏报 —— 已修正)
                for m in re.finditer(re.escape(field) + r"\.isEmpty\(\)", line):
                    before = line[:m.start()]
                    protected = False
                    for pat in PROTECTED_PATTERNS:
                        if re.search(pat.format(f=re.escape(field)), before):
                            protected = True
                            break
                    # 紧邻 nz( / NetInfo.nz(
                    if before.rstrip().endswith("nz(") or before.rstrip().endswith("NetInfo.nz("):
                        protected = True
                    # 同一行 (或紧邻的前一行) 里已经有 null 检查:
                    #   X == null || X.isEmpty()
                    #   net.X == null || net.X.isEmpty()
                    # 允许中间有 "net." / "this." 这样的接收者前缀。
                    recv = r"(?:[\w.]+\.)?"
                    null_check = re.compile(
                        recv + re.escape(field) + r"\s*(?:==|!=)\s*null\s*(?:\|\||&&)\s*"
                        + recv + re.escape(field) + r"\.isEmpty\(\)")
                    if null_check.search(line):
                        protected = True
                    # 也检查前一行 (null 检查可能被拆行)
                    if i >= 2 and null_check.search(lines[i - 2]):
                        protected = True
                    # 局部变量已受保护
                    if local_vars_protected(lines, i, field):
                        protected = True
                    checked += 1
                    if not protected:
                        problems.append((rel, i, field, line.strip()))

    print("检查了 %d 处 .isEmpty() 调用点\n" % checked)

    if problems:
        print("[FAIL] 发现 %d 处可能 NPE 的调用:" % len(problems))
        for rel, ln, field, txt in problems:
            print("  %s:%d  [%s]" % (rel, ln, field))
            print("      %s" % txt[:100])
        print()
        print("修复方式: 用 NetInfo.nz(字段) 包一层, 或加 null 检查。")
        sys.exit(1)

    print("[PASS] 未发现未经保护的 .isEmpty() 调用")
    print()
    print("提醒: 这只能覆盖**字段**层面的 null。")
    print("      反射调用的返回值也必须自身兜底 (如 detectSoftApAddress 返回 \"\" 而非 null)。")


if __name__ == "__main__":
    main()

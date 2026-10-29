#!/usr/bin/env python3
"""安卓端全部离线测试入口。"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = ["logic_check.py", "iptables_check.py", "nullsafety_check.py"]

failed = []
for t in TESTS:
    print("\n" + "=" * 66)
    print(">>> " + t)
    print("=" * 66)
    r = subprocess.run([sys.executable, os.path.join(HERE, t)], capture_output=True, text=True)
    print(r.stdout)
    if r.stderr.strip():
        print(r.stderr)
    if r.returncode != 0:
        failed.append(t)

print("\n" + "=" * 66)
if failed:
    print("失败: " + ", ".join(failed))
    sys.exit(1)
print("全部测试通过")

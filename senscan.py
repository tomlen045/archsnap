#!/usr/bin/env python3
"""archsnap 交付前敏感扫描: 公司网段/门牌/token/网桥ID"""
import re, sys

FILES = ["archsnap.py", "README.md", "README_EN.md", "LICENSE", ".gitignore"]
PATTERNS = [
    (r"172\.16[\.\s]?\d+\.\d+", "公司网段 172.16"),
    (r"172\.18[\.\s]?\d+\.\d+", "公司网段 172.18"),
    (r"10\.92[\.\s]?\d+\.\d+", "内网池 10.92"),
    (r"192\.168\.(\d+)\.(\d+)", "私网 192.168(需人工确认)"),
    (r"br-[0-9a-f]{10,}", "docker 网桥 ID"),
    (r"ghp_[A-Za-z0-9]{20,}", "GitHub token"),
    (r"gitee[a-z]*_[A-Za-z0-9]{20,}", "Gitee token"),
    (r"[A-Za-z0-9]{32}", "32hex 可疑串(需人工确认)"),
    (r"Appmobsf#|Aixdr#", "内部密码形态"),
]
ALLOW = {"a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"}  # 自测 fixture 合成串白名单
hits = 0
for f in FILES:
    try:
        text = open("/Users/len/CodeBuddy/dx/archsnap/" + f, encoding="utf-8").read()
    except FileNotFoundError:
        continue
    for pat, label in PATTERNS:
        for m in re.finditer(pat, text):
            s = m.group(0)
            if s in ALLOW:
                continue
            ln = text[:m.start()].count("\n") + 1
            print("HIT %-28s %s:%d  %s" % (label, f, ln, s[:44]))
            hits += 1
print("----")
print("HITS:", hits)
sys.exit(1 if hits else 0)

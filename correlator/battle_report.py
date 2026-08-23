#!/usr/bin/env python3
"""correlator/battle_report.py — 生成可读的实战战报（时间线，不依赖 span 树）。

correlate.py 的 render_tree 对多源（本地+服务器+eBPF）混合数据会产生 span 树
递归爆炸。本脚本按时间排序生成精简时间线，字段截断，产出可直接阅读的战报。

用法：
  python3 correlator/battle_report.py \
      --input events/kiro_live.ndjson,events/srv_xxx.ndjson \
      --out output/battle_xxx
"""
import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone

# 时间线关注的事件类型（其余噪声类型跳过）
KEEP_TYPES = {
    "conversation.user", "conversation.assistant",
    "tool.invoke", "tool.result", "tool.http",
    "llm.request", "llm.response",
    "process.spawn", "process.exit",
    "net.connect", "net.listen",
    "fs.read", "fs.write", "fs.create", "fs.delete", "fs.rename",
    "ssh.session.open", "ssh.session.close",
    "trace.begin", "trace.end",
}

ICON = {
    "conversation.user": "👤", "conversation.assistant": "🤖",
    "tool.invoke": "🔧", "tool.result": "↩️", "tool.http": "🌐",
    "llm.request": "🧠", "llm.response": "🧠",
    "process.spawn": "🐣", "process.exit": "💀",
    "net.connect": "🔗", "net.listen": "🔌",
    "fs.read": "📄", "fs.write": "✍️", "fs.create": "🆕",
    "fs.delete": "🗑️", "fs.rename": "♻️",
    "ssh.session.open": "🔓", "ssh.session.close": "🔒",
    "trace.begin": "◆", "trace.end": "◇",
}

SOURCE_TAG = {
    "kiro_observer": "本机进程", "mitmproxy": "应用层", "fsevents": "文件",
    "server_agent": "服务器", "ebpf_tracer": "服务器eBPF",
    "agent_runtime": "语义", "tool_proxy": "工具", "network": "系统",
}


def redact(s: str) -> str:
    """脱敏密码/token。"""
    s = re.sub(r'(-p\s+["\']?)[^"\'\s]+', r'\1***', s, flags=re.I)
    s = re.sub(r'(password|passwd|pwd|secret|token|key)\s*[:=]\s*["\']?[^\s"\']+',
               r'\1=***', s, flags=re.I)
    return s


def brief(ev) -> str:
    a = ev.get("action") or {}
    arg = a.get("arguments_redacted") or {}
    name = a.get("name", "")
    et = ev.get("event_type", "")
    if et.startswith("conversation"):
        return (arg.get("preview") or "")[:90]
    if et in ("tool.invoke", "tool.result"):
        cmd = arg.get("command") or arg.get("path") or arg.get("peer") or ""
        return f"{name} {redact(str(cmd))}"[:90]
    if et in ("llm.request", "llm.response"):
        return f"{name} → {arg.get('host') or a.get('summary', '')}"[:70]
    if et == "net.connect":
        peer = arg.get("peer") or arg.get("host") or ""
        kind = arg.get("peer_kind", "")
        return f"{peer} [{kind}]"[:60]
    if et.startswith("fs."):
        return str(arg.get("path", ""))[:80]
    if et.startswith("process."):
        return f"{arg.get('pid', '')} {arg.get('comm') or arg.get('argv') or arg.get('exe') or name}"[:70]
    if et.startswith("ssh.session"):
        return str(arg.get("desc") or arg.get("sshd_pid") or name)[:60]
    return str(a.get("summary", ""))[:80]


def load(paths):
    events = []
    for p in paths:
        p = p.strip()
        if not p:
            continue
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


# ---------------- 因果关联引擎 ----------------
COMMAND_HINTS = {
    "ssh": ["ssh", "sshd", "sftp-server", "sftp"],
    "scp": ["scp", "sftp-server", "sftp"],
    "git": ["git "],
    "go": ["go ", "monitor", "go build", "golang"],
    "curl": ["curl", "wget"],
    "npm": ["npm", "node"],
    "systemctl": ["systemctl", "systemd"],
    "docker": ["docker"],
}

SYS_EVENT_TYPES = {
    "process.spawn", "process.exit", "net.connect", "net.listen",
    "ssh.session.open", "ssh.session.close", "fs.read", "fs.write",
    "fs.create", "fs.delete",
}


def _parse_ts(ts):
    if not ts:
        return None
    ts = ts.strip()
    try:
        if ts.endswith("Z"):
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z")
    except Exception:
        try:
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")
        except Exception:
            return None


def build_causal_chains(events, window_sec=4.0):
    """把命令类工具调用与其触发的系统事件按「时间窗 + 语义」关联成执行链。"""
    tools = [e for e in events
             if e.get("event_type") == "tool.invoke"
             and e.get("action", {}).get("name") in ("execute_bash", "run_command")]
    sys_pool = [e for e in events if e.get("event_type") in SYS_EVENT_TYPES]

    # 预解析时间戳
    tmap = {}
    def ts_of(e):
        if id(e) not in tmap:
            tmap[id(e)] = _parse_ts(e.get("timestamp", ""))
        return tmap[id(e)]

    chains = []
    for tool in tools:
        cmd = (tool.get("action", {}).get("arguments_redacted") or {}).get("command", "")
        if not cmd:
            continue
        t0 = ts_of(tool)
        if not t0:
            continue
        # 语义 hint
        hints = [k for k, kws in COMMAND_HINTS.items()
                 if any(kw.lower() in cmd.lower() for kw in kws)]
        # 时间窗内找关联系统事件（去重 + 排除背景噪声）
        related = []
        seen_keys = set()
        for s in sys_pool:
            st = ts_of(s)
            if not st:
                continue
            delta = (st - t0).total_seconds()
            if not (0 <= delta <= window_sec):
                continue
            act = s.get("action", {}) or {}
            key = (s.get("span_id"), s.get("event_type"),
                   act.get("summary", ""), act.get("arguments_redacted", {}).get("path", ""))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            s_text = json.dumps(act, ensure_ascii=False)
            # 排除 Kiro 自身背景噪声（走代理、遥测、IDE 配置目录）
            if s.get("event_type") == "net.connect" and "127.0.0.1" in s_text:
                continue
            if "telemetry" in s_text or "Application Support" in s_text:
                continue
            related.append((delta, s))
        # 语义过滤：优先保留与命令关键词匹配的事件；无匹配则仅保留进程类
        if hints and related:
            matched = [(d, s) for d, s in related
                       if any(k in json.dumps(s.get("action", {}), ensure_ascii=False).lower()
                              for k in hints)]
            if matched:
                related = matched
            else:
                related = [(d, s) for d, s in related
                           if s.get("event_type") in ("process.spawn", "process.exit")]
        if related:
            related.sort(key=lambda x: x[0])
            chains.append({"command": cmd, "time": t0, "related": related})
    return chains


def load_alerts(paths):
    """合并实时告警（<trace>_alerts.ndjson）。"""
    alerts = []
    seen = set()
    for p in paths:
        p = p.strip()
        if not p:
            continue
        ap = p[:-len(".ndjson")] + "_alerts.ndjson" if p.endswith(".ndjson") else p + "_alerts"
        if not os.path.exists(ap):
            continue
        with open(ap, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    a = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # 精简：去掉 event 字段（可能含大请求体）
                slim = {k: a.get(k) for k in
                        ("rule_id", "rule_name", "severity", "timestamp",
                         "trace_id", "span_id", "detail", "event_type",
                         "source")}
                key = (slim.get("rule_id"), slim.get("detail"),
                       slim.get("timestamp"))
                if key in seen:
                    continue
                seen.add(key)
                alerts.append(slim)
    return alerts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="NDJSON 逗号分隔")
    ap.add_argument("--out", default="output/battle")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    paths = args.input.split(",")
    events = load(paths)
    alerts = load_alerts(paths)
    if not events:
        print("no events", file=sys.stderr)
        return

    counts = Counter(e.get("event_type") for e in events)
    src = Counter(e.get("source") for e in events)
    tss = [e.get("timestamp", "") for e in events if e.get("timestamp")]
    t_min, t_max = (min(tss), max(tss)) if tss else ("", "")

    # 时间线（只保留关注类型，且跳过 IDE 自身配置目录的文件噪声）
    def _noisy_fs(e):
        if not e.get("event_type", "").startswith("fs."):
            return False
        path = str((e.get("action", {}).get("arguments_redacted") or {}).get("path", ""))
        return "Application Support" in path or "Library/Caches" in path

    timeline = [e for e in events
                if e.get("event_type") in KEEP_TYPES and not _noisy_fs(e)]
    timeline.sort(key=lambda e: e.get("timestamp", ""))

    # 告警汇总（R3 只保留真正"绕过代理直连"：IP 直连或明确标记绕过代理，去掉域名正常出站误报）
    r1 = [a for a in alerts if a.get("rule_id") == "R1"]
    r2 = [a for a in alerts if a.get("rule_id") == "R2"]
    r3 = [a for a in alerts if a.get("rule_id") == "R3" and (
        "绕过代理" in a.get("detail", "") or
        "直连非白名单" in a.get("detail", "") or
        re.search(r"异常外联: \d+\.\d+\.\d+\.\d+", a.get("detail", "")))]

    lines = []
    lines.append("# Kiro Agent 执行监视 — 实战战报")
    lines.append("")
    lines.append(f"- 时间范围：`{t_min}` ~ `{t_max}`")
    lines.append(f"- 事件总数：{len(events)} 条（关注类型 {len(timeline)} 条）")
    lines.append(f"- 数据来源：{dict(src)}")
    lines.append(f"- 告警：R1 密钥 {len(r1)} · R2 越界 {len(r2)} · R3 外联 {len(r3)}")
    lines.append("")
    lines.append("## 事件类型分布")
    lines.append("")
    lines.append("| 类型 | 数量 |")
    lines.append("|---|---|")
    for k, v in counts.most_common():
        lines.append(f"| {k} | {v} |")
    lines.append("")

    lines.append("## 时间线（关键事件）")
    lines.append("")
    lines.append("| 时间 | 层 | 事件 | 摘要 |")
    lines.append("|---|---|---|---|")
    for e in timeline:
        ts = (e.get("timestamp") or "")[11:23]
        src_tag = SOURCE_TAG.get(e.get("source"), e.get("source", "-"))
        et = e.get("event_type", "")
        b = brief(e).replace("|", "\\|")
        lines.append(f"| {ts} | {src_tag} | {ICON.get(et,'·')} {et} | {b} |")
    lines.append("")

    lines.append("## 告警详情")
    lines.append("")
    if not alerts:
        lines.append("- 无")
    # R1 优先（最严重），再 R2/R3
    for a in r1 + r2 + r3:
        det = redact(str(a.get("detail", "")))[:160]
        lines.append(f"- **[{a.get('rule_id')}]** {a.get('timestamp', '')} — {det}")
    lines.append("")

    # 因果执行链：命令 → 触发的系统事件
    chains = build_causal_chains(events)
    lines.append("## 因果执行链（命令 → 系统动作）")
    lines.append("")
    if not chains:
        lines.append("- 无关联")
    for ch in chains:
        cmd = redact(ch["command"])[:90]
        t0 = (ch["time"].astimezone(timezone.utc).strftime("%H:%M:%S")
              if ch["time"] else "")
        lines.append(f"- 🔧 `{cmd}`")
        for delta, s in ch["related"][:6]:
            et = s.get("event_type", "")
            sb = brief(s).replace("|", "\\|")[:80]
            src = SOURCE_TAG.get(s.get("source"), s.get("source", "-"))
            lines.append(f"    +{delta:.1f}s [{src}] {ICON.get(et, '·')} {sb}")
    lines.append("")

    lines.append("## 安全发现小结")
    lines.append("")
    lines.append("- 明文密码复现：见 R1 告警（`sshpass -p` / `password=` 命令）")
    lines.append("- 异常外联：见 R3 告警（绕过代理直连公网，peer_kind=direct）")
    lines.append("- 越界文件操作：见 R2 告警")
    lines.append("")
    lines.append("---")
    lines.append("*本报告由 Agent 执行监视器自动生成，敏感信息已脱敏。*")

    out_path = os.path.join(args.out, "BATTLE_REPORT.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # 附带 alerts.json
    with open(os.path.join(args.out, "alerts.json"), "w", encoding="utf-8") as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)

    print(f"战报已生成: {out_path}")
    print(f"  事件 {len(events)} 条，时间线 {len(timeline)} 条，告警 {len(alerts)} 条")


if __name__ == "__main__":
    main()

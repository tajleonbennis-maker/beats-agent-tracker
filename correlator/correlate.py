"""跨层事件关联引擎（规范第 5.1 节采集顺序第 4-6 步 + 第 7 节 MVP）。

输入：Filebeat 采集后的 NDJSON（兼容 Beats 包装格式）。
输出：
  timeline.md       按 trace/span 树 + 时间排序的执行链（语义链 + 系统链同屏）
  alerts.json       三条内置规则的告警
  trace_summary.json 统计
  evidence_pkg/     脱敏证据包（哈希链可验证）
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "runtime"))
import rules as rules_mod
from trace import canonical_core, chain_hash, HASHED_FIELDS

ICON = {
    "trace.begin": "◆", "user_request": "👤", "model.turn": "🧠",
    "tool.call": "🔧", "tool.result": "↩️", "fs.read": "📄", "fs.write": "✍️",
    "fs.create": "🆕", "fs.delete": "🗑️",
    "process.exec": "⚡", "process.spawn": "🐣", "process.exit": "💀",
    "process.span": "🧩",
    "net.connect": "🌐", "net.listen": "🔌",
    "approval": "✅", "git.diff": "🔀", "fs.snapshot": "📸",
    "final_response": "🏁", "trace.end": "◇",
    "ssh.session.open": "🔓", "ssh.session.close": "🔒",
    "session.heartbeat": "💓",
}
SOURCE_TAG = {"agent_runtime": "语义", "tool_proxy": "工具", "network": "系统",
              "git": "系统", "kernel": "系统", "kiro_observer": "被动",
              "server_agent": "服务器"}


def load_events(path: str) -> list:
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            # 兼容 Beats 输出：若 trace_id 不在根上，尝试解 message
            if "trace_id" not in ev and isinstance(ev.get("message"), str):
                try:
                    inner = json.loads(ev["message"])
                    if isinstance(inner, dict) and "trace_id" in inner:
                        ev = inner
                except json.JSONDecodeError:
                    pass
            if "trace_id" in ev:
                events.append(ev)
    return events


def build_tree(events: list):
    by_span = {}
    children = {}
    roots = []
    for ev in events:
        sid = ev.get("span_id")
        by_span.setdefault(sid, []).append(ev)
    for ev in events:
        p = ev.get("parent_span_id")
        if p and p in by_span:
            children.setdefault(p, []).append(ev)
        else:
            roots.append(ev)
    return by_span, children, roots


def render_tree(events: list, alerts: list) -> str:
    by_span, children, roots = build_tree(events)
    alert_spans = {a["span_id"] for a in alerts}
    lines = []

    def ev_label(ev):
        a = ev.get("action") or {}
        name = a.get("name", "")
        arg = (a.get("arguments_redacted") or {})
        brief = (arg.get("command") or arg.get("path") or arg.get("peer") or "")[:80]
        rs = a.get("result_summary") or {}
        outcome = rs.get("exit_code", "")
        pol = (ev.get("policy") or {}).get("decision", "")
        mark = " ⚠️" if ev.get("span_id") in alert_spans else ""
        extra = f" exit={outcome}" if outcome != "" else ""
        return (f"{ICON.get(ev.get('event_type'), '·')} "
                f"[{SOURCE_TAG.get(ev.get('source'), ev.get('source'))}] "
                f"{ev.get('event_type')} {name} {brief}".rstrip()
                + (f" (policy={pol}{extra})" if pol else "") + mark)

    def walk(ev, depth):
        lines.append("  " * depth + ev.get("timestamp", "")[11:23] + " " + ev_label(ev))
        for sid_children in [ev]:
            pass
        for child in sorted(children.get(ev.get("span_id"), []),
                            key=lambda e: e.get("timestamp", "")):
            walk(child, depth + 1)

    for r in sorted(roots, key=lambda e: e.get("timestamp", "")):
        walk(r, 0)
    return "\n".join(lines)


def render_table(events: list, alerts: list) -> str:
    alert_map = {}
    for a in alerts:
        alert_map.setdefault(a["span_id"], []).append(a["rule_id"])
    rows = ["| 时间 | 层 | 事件 | Span | 动作 | 策略 | 告警 |",
            "|---|---|---|---|---|---|---|"]
    for ev in sorted(events, key=lambda e: e.get("timestamp", "")):
        a = ev.get("action") or {}
        arg = (a.get("arguments_redacted") or {})
        act = arg.get("command") or arg.get("path") or arg.get("peer") or a.get("name", "")
        rows.append(
            f"| {ev.get('timestamp','')[11:23]} "
            f"| {SOURCE_TAG.get(ev.get('source'), '-')} "
            f"| {ICON.get(ev.get('event_type'), '')} {ev.get('event_type')} "
            f"| `{(ev.get('span_id') or '')[:18]}` "
            f"| `{str(act)[:48]}` "
            f"| {(ev.get('policy') or {}).get('decision', '-')} "
            f"| {','.join(alert_map.get(ev.get('span_id'), [])) or ''} |")
    return "\n".join(rows)


def verify_chain(events: list) -> dict:
    """验证哈希链完整性（Beats 只透传、不改哈希覆盖字段时应当全部通过）。

    多源合并：按 trace_id 分组各自验证（本地观察器与服务器采集端是两条独立链）。
    """
    by_trace = {}
    for ev in events:
        by_trace.setdefault(ev.get("trace_id", "?"), []).append(ev)
    bad, per_trace = [], {}
    for tid, evs in by_trace.items():
        prev = "GENESIS"
        t_bad = []
        for ev in evs:  # 文件原始顺序即链序（load_events 已保持顺序）
            e = ev.get("evidence") or {}
            if e.get("prev_hash") != prev or chain_hash(prev, ev) != e.get("hash"):
                t_bad.append(ev.get("span_id"))
                prev = e.get("hash") or prev  # 链断后继续找头
                continue
            prev = e["hash"]
        per_trace[tid] = {"ok": not t_bad, "broken_at": t_bad}
        bad.extend(t_bad)
    return {"ok": len(bad) == 0, "broken_at": bad, "per_trace": per_trace}


def context_from(events: list) -> dict:
    """跨多个 trace.begin 合并上下文（本地 + 服务器多源）。"""
    ctx = {"workspace_root": None, "net_allowlist": [],
           "task": None, "hosts": []}
    for ev in events:
        if ev.get("event_type") == "trace.begin":
            arg = (ev.get("action") or {}).get("arguments_redacted") or {}
            host = (ev.get("actor") or {}).get("name") or \
                (ev.get("actor") or {}).get("vendor")
            if host and host not in ctx["hosts"]:
                ctx["hosts"].append(host)
            if ctx["workspace_root"] is None:
                ctx["workspace_root"] = arg.get("workspace_root")
            if not ctx["net_allowlist"] and arg.get("net_allowlist"):
                ctx["net_allowlist"] = arg.get("net_allowlist")
            if ctx["task"] is None:
                ctx["task"] = arg.get("task")
    return ctx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True,
                    help="NDJSON 路径，多个用逗号分隔（本地+服务器多源合并）")
    ap.add_argument("--out", default="output")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    # 多源合并：逗号分隔输入，各文件保持原始链序（分链验证）
    events = []
    for path in args.input.split(","):
        path = path.strip()
        if path:
            events.extend(load_events(path))
    if not events:
        print("no events found", file=sys.stderr)
        sys.exit(1)
    trace_ids = []
    for ev in events:
        t = ev.get("trace_id")
        if t and t not in trace_ids:
            trace_ids.append(t)
    trace_id = trace_ids[0]
    ctx = context_from(events)

    alerts = rules_mod.evaluate(events, ctx)
    integrity = verify_chain(events)

    # 合并实时告警（观察器/服务器端内容嗅探产生的 <trace>_alerts.ndjson）
    for path in args.input.split(","):
        path = path.strip()
        if not path:
            continue
        ap = path[:-len(".ndjson")] + "_alerts.ndjson" \
            if path.endswith(".ndjson") else path + "_alerts"
        if os.path.exists(ap):
            with open(ap, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            a = json.loads(line)
                            if a not in alerts:
                                alerts.append(a)
                        except json.JSONDecodeError:
                            continue

    tree = render_tree(events, alerts)
    table = render_table(events, alerts)
    counts = {}
    for ev in events:
        counts[ev["event_type"]] = counts.get(ev["event_type"], 0) + 1

    md = [
        f"# Agent 执行链时间轴 — `{trace_id}`"
        + (f"（+{len(trace_ids) - 1} 个关联源：{', '.join(trace_ids[1:])}）"
           if len(trace_ids) > 1 else ""),
        "",
        f"- 任务：{ctx.get('task')}",
        f"- 工作区：{ctx.get('workspace_root')}",
        f"- 监视主机：{', '.join(ctx.get('hosts') or []) or '—'}",
        f"- 事件总数：{len(events)}（{counts}）",
        f"- 告警：{len(alerts)} 条；证据链校验：{'✅ 完整' if integrity['ok'] else '❌ 断裂于 ' + str(integrity['broken_at'])}",
        "",
        "## 执行链（树）",
        "语义链（agent_runtime）与系统链（network/git）通过 span 父子关系关联：",
        "",
        "```text",
        tree,
        "```",
        "",
        "## 时间轴（表）",
        table,
        "",
        "## 告警详情",
    ]
    for a in alerts:
        rn = a.get("rule_name") or a.get("rule_id", "")
        ts = a.get("timestamp") or ""
        sp = a.get("span_id") or ""
        det = a.get("detail", "")
        md.append(f"- **[{a.get('rule_id', '')} {rn}]** {ts} "
                  f"span=`{sp[:18]}` — {det}")
    if not alerts:
        md.append("- 无")
    open(os.path.join(args.out, "timeline.md"), "w", encoding="utf-8").write("\n".join(md))

    json.dump(alerts, open(os.path.join(args.out, "alerts.json"), "w"),
              ensure_ascii=False, indent=2)
    summary = {
        "trace_id": trace_id, "events": len(events), "counts": counts,
        "alerts": len(alerts), "integrity": integrity, "context": ctx,
        "metrics_hint": {
            "event_coverage": "见 counts vs 任务步骤数",
            "causal_linking": "net.connect/process.exec 均挂在 tool.call span 下",
        },
    }
    json.dump(summary, open(os.path.join(args.out, "trace_summary.json"), "w"),
              ensure_ascii=False, indent=2)

    # 证据包
    from evidence import export_package
    pkg = export_package(events, alerts, summary, args.out)
    print(json.dumps({"timeline": os.path.join(args.out, "timeline.md"),
                      "alerts": len(alerts), "integrity_ok": integrity["ok"],
                      "evidence_pkg": pkg}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

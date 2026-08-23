#!/usr/bin/env python3
"""流量事件关联：把 Packetbeat 输出 join 回 Agent Trace。

为什么需要这一步：
- 语义执行链（tool.call/fs.read/...）和进程事实（process.spawn）都带 trace_id；
- 但 Packetbeat 在内核/驱动层抓包，看不到子进程环境变量里的 AGENT_TRACE_ID，
  流量事件天生没有 trace_id；
- 关联键 = 四元组 + 时间窗：Agent 主动外联时，socket 本地端
  (source.ip:port) 会出现在对应 net.connect 事件的 local 字段里。

用法：
    python correlator/enrich.py <processed.ndjson> <packetbeat.ndjson> <out.ndjson>

输出：
- join 上的流量事件补 trace.id / trace.span_id（指向匹配的 net.connect）；
- join 不上的标记 correlation.state=unattributed —— 这本身是安全信号：
  存在没有工具调用对应的流量（绕过网关的出网）。
- 所有输出先过 trace.py 的 redact()（与主链路同一脱敏边界）。
"""
import json
import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "runtime"))
from trace import redact  # noqa: E402

TIME_WINDOW = timedelta(seconds=30)


def _ts(ev: dict):
    for key in ("timestamp", "@timestamp"):
        v = ev.get(key)
        if not v:
            continue
        try:
            return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        except ValueError:
            continue
    return None


def _tuple(pb: dict):
    """取 Packetbeat 事件四元组（ECS flow/source/destination）。"""
    flow = pb.get("flow") or pb
    src_ip = flow.get("source", {}).get("ip") or pb.get("source", {}).get("ip")
    src_port = flow.get("source", {}).get("port")
    dst_ip = flow.get("destination", {}).get("ip") or pb.get("destination", {}).get("ip")
    dst_port = flow.get("destination", {}).get("port")
    if src_ip and src_port and dst_ip and dst_port:
        return f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"
    return None, None


def load_ndjson(path):
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


def join(trace_events, packetbeat_events, window=TIME_WINDOW):
    # 索引：net.connect 事件按 (local, peer) 分组
    net_index = {}
    for ev in trace_events:
        if ev.get("event_type") != "net.connect":
            continue
        args = (ev.get("action") or {}).get("arguments_redacted") or {}
        local, peer = args.get("local"), args.get("peer")
        if local and peer:
            net_index.setdefault((local, peer), []).append(
                {"ts": _ts(ev), "trace_id": ev.get("trace_id") or (ev.get("trace") or {}).get("id"),
                 "span_id": ev.get("span_id"),
                 "pid": args.get("pid")})

    joined, unattributed = [], []
    for pb in packetbeat_events:
        local, peer = _tuple(pb)
        out = dict(pb)
        match = None
        if local and peer:
            for cand in net_index.get((local, peer), []):
                if cand["ts"] and _ts(pb) \
                        and abs((_ts(pb) - cand["ts"]).total_seconds()) <= window.total_seconds():
                    match = cand
                    break
        if match:
            out.setdefault("trace", {})["id"] = match["trace_id"]
            out["correlation"] = {
                "state": "joined",
                "matched_event": "net.connect",
                "span_id": match["span_id"],
                "pid": match["pid"],
                "method": "4-tuple+time-window",
            }
            joined.append(out)
        else:
            out["correlation"] = {"state": "unattributed",
                                  "reason": "no matching net.connect (bypassed gateway?)"}
            unattributed.append(out)
    return joined, unattributed


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(2)
    trace_events = load_ndjson(sys.argv[1])
    pb_events = load_ndjson(sys.argv[2])
    joined, unattr = join(trace_events, pb_events)

    with open(sys.argv[3], "w", encoding="utf-8") as f:
        for ev in joined + unattr:
            f.write(json.dumps(redact(ev), ensure_ascii=False) + "\n")

    print(f"packetbeat 事件总数 : {len(pb_events)}")
    print(f"已关联到 trace     : {len(joined)}")
    print(f"未归属流量(可疑)   : {len(unattr)}")
    if joined:
        tids = {ev["trace"]["id"] for ev in joined}
        print(f"涉及 trace_id      : {', '.join(sorted(tids))}")
    for ev in unattr[:10]:
        ds = ev.get("event", {}).get("dataset", "?")
        local, peer = _tuple(ev)
        print(f"  [unattributed] {ds} {local} -> {peer}")
    sys.exit(0)


if __name__ == "__main__":
    main()

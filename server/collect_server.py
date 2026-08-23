#!/usr/bin/env python3
"""中央汇集器（collector）：接收各采集端上报的事件流，统一落盘 + 链校验。

架构：
  Mac 本地   kiro/observer.py  → events/kiro_*.ndjson（直写）
  服务器     server/agent.py   → 本地留档 + POST /ingest 上报到这里
                          ↓
  collector（本机 :8787）→ events/<trace_id>.ndjson（按源分文件）
                          → 每次接收校验哈希链连续性（断裂即告警）

之后 correlator 用逗号分隔多文件输入即可出"本地 + 服务器"合并时间轴：
  python3 correlator/correlate.py --input events/kiro_xxx.ndjson,events/srv_yyy.ndjson --out output/report

用法：
  python3 server/collect_server.py [--port 8787] [--events-dir events]
  服务器端配合：agent.py --report-url http://<本机IP>:8787/ingest
"""
import argparse
import http.server
import json
import os
import sys
import time
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "runtime"))
from trace import chain_hash  # noqa: E402


class CollectorState:
    def __init__(self, events_dir):
        self.events_dir = events_dir
        os.makedirs(events_dir, exist_ok=True)
        self.chains = {}        # trace_id -> last hash（服务端续链校验）
        self.broken = set()     # 链断裂的 trace_id
        self.received = {}      # trace_id -> 事件数
        self._load_existing()

    def _load_existing(self):
        for fn in os.listdir(self.events_dir):
            if not fn.endswith(".ndjson"):
                continue
            tid = fn[:-7]
            last = None
            with open(os.path.join(self.events_dir, fn), encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            last = json.loads(line)
                        except json.JSONDecodeError:
                            continue
            if last:
                self.chains[tid] = last.get("evidence", {}).get("hash", "GENESIS")
                self.received[tid] = self.received.get(tid, 0) + 1

    def ingest(self, trace_id, events):
        n_ok, n_bad = 0, 0
        path = os.path.join(self.events_dir, f"{trace_id}.ndjson")
        prev = self.chains.get(trace_id, "GENESIS")
        with open(path, "a", encoding="utf-8") as f:
            for ev in events:
                try:
                    got_prev = ev.get("evidence", {}).get("prev_hash")
                    got_hash = ev.get("evidence", {}).get("hash")
                    if got_prev != prev or chain_hash(prev, ev) != got_hash:
                        n_bad += 1
                        print(f"🚨 [chain] {trace_id} 链校验失败"
                              f"（expect prev={prev[:12]}… got={str(got_prev)[:12]}…）"
                              f"——事件可能被篡改或乱序", flush=True)
                        self.broken.add(trace_id)
                        # 不中断：记录后继续按本地链校验后续事件
                        prev = got_hash if got_hash else prev
                    else:
                        n_ok += 1
                        prev = got_hash
                    f.write(json.dumps(ev, ensure_ascii=False) + "\n")
                except Exception:
                    n_bad += 1
        self.chains[trace_id] = prev
        self.received[trace_id] = self.received.get(trace_id, 0) + len(events)
        return n_ok, n_bad


class Handler(http.server.BaseHTTPRequestHandler):
    state: CollectorState = None

    def do_POST(self):
        if not self.path.startswith("/ingest"):
            self.send_error(404)
            return
        tid = self.headers.get("X-Trace-Id") or "unknown"
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        events = []
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                if "trace_id" in ev:
                    events.append(ev)
            except json.JSONDecodeError:
                continue
        if not events:
            self.send_error(400, "no valid events")
            return
        # 以事件自报的 trace_id 为准（防 header 伪造错配）
        tid = events[0].get("trace_id", tid)
        n_ok, n_bad = self.state.ingest(tid, events)
        resp = json.dumps({"ok": n_ok, "bad": n_bad,
                           "trace_id": tid,
                           "total_received": self.state.received[tid],
                           "chain_broken": tid in self.state.broken})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(resp.encode())
        print(f"[{time.strftime('%H:%M:%S')}] ingest {tid}: "
              f"+{len(events)} 事件（ok={n_ok} bad={n_bad}）", flush=True)

    def do_GET(self):
        if self.path == "/status":
            resp = json.dumps({
                "traces": {t: {"events": self.state.received.get(t, 0),
                               "chain_broken": t in self.state.broken}
                           for t in self.state.chains}},
                ensure_ascii=False, indent=1)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp.encode())
        elif self.path.startswith("/events"):
            self._events()
        else:
            self.send_error(404)

    def _events(self):
        """GET /events?trace_id=<id|latest:prefix>&offset=N&limit=M
        返回该 trace 的事件（自证页面 / correlator 的数据源）。"""
        qs = parse_qs(urlparse(self.path).query)
        tid = (qs.get("trace_id") or [""])[0]
        try:
            offset = int((qs.get("offset") or ["0"])[0])
            limit = int((qs.get("limit") or ["500"])[0])
        except ValueError:
            offset, limit = 0, 500
        if not tid:
            self.send_error(400, "trace_id required")
            return
        if tid.startswith("latest:"):
            prefix = tid[len("latest:"):]
            best, best_mt = None, -1
            for fn in os.listdir(self.state.events_dir):
                if fn.startswith(prefix) and fn.endswith(".ndjson"):
                    mt = os.path.getmtime(
                        os.path.join(self.state.events_dir, fn))
                    if mt > best_mt:
                        best, best_mt = fn, mt
            if not best:
                resp = json.dumps({"trace_id": None, "total": 0,
                                   "events": [], "chain_broken": False,
                                   "error": f"no trace matches {prefix}*"})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(resp.encode())
                return
            tid = best[:-7]
        events = []
        path = os.path.join(self.state.events_dir, f"{tid}.ndjson")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        resp = json.dumps({"trace_id": tid,
                           "total": len(events),
                           "events": events[offset:offset + limit],
                           "chain_broken": tid in self.state.broken},
                          ensure_ascii=False)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(resp.encode())

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser(description="中央汇集器")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--events-dir", default=os.path.join(ROOT, "events"))
    args = ap.parse_args()

    Handler.state = CollectorState(args.events_dir)
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"◆ collector 监听 0.0.0.0:{args.port}"
          f"（POST /ingest，GET /status）", flush=True)
    print(f"  事件落盘: {args.events_dir}/<trace_id>.ndjson", flush=True)
    print(f"  服务器端配置: agent.py --report-url "
          f"http://<本机IP>:{args.port}/ingest", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\ncollector 已停止")


if __name__ == "__main__":
    main()

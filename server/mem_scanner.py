#!/usr/bin/env python3
"""server/mem_scanner.py — 服务器端进程内存取证扫描器。

背景：Kiro 通过 SSH 在服务器上跑命令（如 sshpass -p "密码" ssh ...）时，
密码会短暂出现在进程内存里。本扫描器读 sshd 会话进程树内进程的
/proc/pid/mem，检测明文密码/token/私钥残留，命中即 R1 告警。

扫描对象：sshd 会话（"sshd: user@pts/N"）进程树内的进程（与 agent.py 同范围）
扫描方式：读 /proc/pid/maps 的可读段 → /proc/pid/mem 对应地址 → 正则搜敏感模式
性能：只扫可读写段，限制单段/单进程扫描量，默认每 30 秒一轮

用法（root）：
  python3 server/mem_scanner.py --report-url http://127.0.0.1:18787/ingest
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import signal
import sys
import time
import urllib.request

SCHEMA_VERSION = "0.1"
HASHED_FIELDS = [
    "schema_version", "trace_id", "span_id", "parent_span_id", "timestamp",
    "source", "event_type", "actor", "action", "policy",
]

# 内存残留敏感模式（bytes 匹配）
MEM_SECRET_PATTERNS = [
    ("sshpass明文密码", re.compile(rb"sshpass\s+-p\s+\S{4,}")),
    ("密码赋值", re.compile(rb"(?i)(password|passwd|pwd|secret)\s*[=:]\s*[\x20-\x7e]{6,}")),
    ("OpenAI-token", re.compile(rb"sk-[A-Za-z0-9]{20,}")),
    ("GitHub-token", re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("AWS-key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("私钥", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

# 扫描限制（避免大进程拖慢采集）
MAX_SEGMENT = 16 * 1024 * 1024      # 单段最大 16MB
MAX_PER_PROCESS = 64 * 1024 * 1024  # 单进程最大 64MB
SSHD_SESSION_RE = re.compile(r"sshd:.*(@|notty)")


def new_id(prefix):
    ts = int(time.time() * 1000)
    return f"{prefix}_{ts:012x}{secrets.token_hex(10)}"


def canonical_core(event):
    core = {k: event.get(k) for k in HASHED_FIELDS}
    core["evidence"] = {k: v for k, v in (event.get("evidence") or {}).items()
                        if k != "hash"}
    return json.dumps(core, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def chain_hash(prev_hash, event):
    return hashlib.sha256(
        (prev_hash + "|" + canonical_core(event)).encode()).hexdigest()


def proc_snapshot():
    """({pid: ppid}, {ssh 会话 pid 集合})"""
    procs, sessions = {}, set()
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            with open(f"/proc/{pid}/stat", "rb") as f:
                data = f.read().decode("utf-8", "replace")
            rp = data.rpartition(")")
            ppid = int(rp[2].split()[1])
            procs[pid] = ppid
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = f.read().replace(b"\x00", b" ").decode(
                    "utf-8", "replace").strip()
            if SSHD_SESSION_RE.search(argv):
                sessions.add(pid)
        except (OSError, ValueError, IndexError):
            continue
    return procs, sessions


def tree_from(procs, seeds):
    tree = set(seeds)
    children = {}
    for pid, d in procs.items():
        children.setdefault(d, []).append(pid)
    queue = list(seeds)
    while queue:
        cur = queue.pop()
        for c in children.get(cur, []):
            if c not in tree:
                tree.add(c)
                queue.append(c)
    return tree


def scan_memory(pid):
    """扫描进程内存，返回命中的敏感模式名列表。"""
    hits = []
    try:
        with open(f"/proc/{pid}/maps", "r") as f:
            maps = f.read()
    except OSError:
        return hits

    segs = []
    for line in maps.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        rng, perms = parts[0], parts[1]
        if "r" not in perms:
            continue
        try:
            start, end = (int(x, 16) for x in rng.split("-"))
        except ValueError:
            continue
        size = end - start
        if size > MAX_SEGMENT:
            continue
        segs.append((start, end))

    try:
        mem = open(f"/proc/{pid}/mem", "rb")
    except OSError:
        return hits

    scanned = 0
    try:
        for start, end in segs:
            if scanned >= MAX_PER_PROCESS:
                break
            try:
                mem.seek(start)
                data = mem.read(end - start)
            except OSError:
                continue
            scanned += len(data)
            for name, pat in MEM_SECRET_PATTERNS:
                if pat.search(data):
                    if name not in hits:
                        hits.append(name)
    finally:
        mem.close()
    return hits


class MemScanner:
    def __init__(self, report_url=None, interval=30):
        self.report_url = report_url
        self.interval = interval
        self.trace_id = new_id("mem")
        self.prev_hash = "GENESIS"
        self.count = 0
        self._pending = []
        self._stop = False
        self._scanned_pids = {}   # pid -> 上次命中数

    def _emit(self, etype, actor, action):
        ev = {
            "schema_version": SCHEMA_VERSION,
            "trace_id": self.trace_id,
            "span_id": new_id("span"),
            "parent_span_id": None,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "source": "mem_scanner",
            "event_type": etype,
            "actor": actor,
            "action": action,
            "policy": {"decision": "observe",
                       "reason": "server-side: 进程内存取证扫描"},
            "evidence": {"prev_hash": self.prev_hash},
        }
        ev["evidence"]["hash"] = chain_hash(self.prev_hash, ev)
        self.prev_hash = ev["evidence"]["hash"]
        self.count += 1
        print(f"[{time.strftime('%H:%M:%S')}] {etype:<12} "
              f"{action.get('summary', '')[:90]}", flush=True)
        if self.report_url:
            self._pending.append(json.dumps(ev, ensure_ascii=False))
            if len(self._pending) >= 5:
                self._flush()
        return ev

    def _flush(self):
        if not self._pending or not self.report_url:
            return
        body = "\n".join(self._pending).encode()
        req = urllib.request.Request(
            self.report_url, data=body,
            headers={"Content-Type": "application/x-ndjson",
                     "X-Trace-Id": self.trace_id})
        try:
            urllib.request.urlopen(req, timeout=5)
            self._pending = []
        except Exception:
            pass

    def scan_once(self):
        procs, sessions = proc_snapshot()
        tree = tree_from(procs, sessions)
        if not tree:
            return 0
        found_total = 0
        for pid in sorted(tree):
            if pid == os.getpid():
                continue  # 跳过自身
            hits = scan_memory(pid)
            # 只在"新命中"时告警（避免重复刷屏）
            prev_hits = self._scanned_pids.get(pid, set())
            new_hits = [h for h in hits if h not in prev_hits]
            if new_hits:
                self._emit("mem.secret",
                           {"type": "process", "pid": pid},
                           {"name": "memory_scan",
                            "arguments_redacted": {"pid": pid,
                                                   "patterns": new_hits},
                            "result_summary": {"all_hits": hits},
                            "summary": f"pid{pid} 内存残留敏感信息："
                                       f"{','.join(new_hits)}"})
                found_total += len(new_hits)
            self._scanned_pids[pid] = set(hits)
        return found_total

    def run(self):
        signal.signal(signal.SIGTERM, self._request_stop)
        print(f"◆ mem_scanner begin  trace={self.trace_id} "
              f"每 {self.interval}s 扫一轮", flush=True)
        t_scan = 0
        t_flush = time.time()
        while not self._stop:
            now = time.time()
            if now - t_scan >= self.interval:
                n = self.scan_once()
                if n:
                    print(f"  本轮命中 {n} 个敏感残留", flush=True)
                t_scan = now
            if now - t_flush >= 5:
                self._flush()
                t_flush = now
            time.sleep(1)

    def _request_stop(self, signum, frame):
        self._stop = True


def main():
    ap = argparse.ArgumentParser(description="服务器端进程内存取证扫描器")
    ap.add_argument("--report-url", default=None)
    ap.add_argument("--interval", type=float, default=30)
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("需要 root 运行（读 /proc/pid/mem）", file=sys.stderr)
        sys.exit(1)

    scanner = MemScanner(report_url=args.report_url, interval=args.interval)
    scanner.run()


if __name__ == "__main__":
    main()

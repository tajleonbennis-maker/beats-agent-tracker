#!/usr/bin/env python3
"""server/ebpf_tracer.py — 基于 eBPF 的服务器端采集器，覆盖轮询盲区。

背景：agent.py 靠轮询 /proc（0.25s 进程 / 0.5s 网络）采集，短于轮询间隔的
短命进程/连接会被漏掉。本采集器用 eBPF 在内核态挂 tracepoint，进程 exec 与
TCP connect 的每个事件都触发，零漏采。

追踪目标：
  sched:sched_process_exec   进程启动（pid/ppid/comm/二进制路径）
  syscalls:sys_enter_connect TCP 连接（pid/fd/对端 IP:port）

过滤：只保留 sshd 会话进程树（"sshd: user@pts/N"）内的进程，与 agent.py
的监视范围一致；其余丢弃。

事件 schema 0.1（与 agent.py 同构），支持 --report-url 逐批上报中央汇集器。

用法（root）：
  python3 server/ebpf_tracer.py --report-url http://127.0.0.1:18787/ingest
依赖：python3-bpfcc（BCC）
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

try:
    from bcc import BPF
except ImportError:
    print("需要 python3-bpfcc：apt install python3-bpfcc bpfcc-tools",
          file=sys.stderr)
    sys.exit(1)

SCHEMA_VERSION = "0.1"
HASHED_FIELDS = [
    "schema_version", "trace_id", "span_id", "parent_span_id", "timestamp",
    "source", "event_type", "actor", "action", "policy",
]

# ---------------- eBPF 程序（C，内嵌）
BPF_TEXT = r"""
#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256

// 进程启动事件
struct exec_evt_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];
};

// TCP connect 事件
struct conn_evt_t {
    u32 pid;
    u32 daddr;      // 对端 IPv4（网络字节序）
    u16 dport;      // 对端端口（网络字节序）
    u16 family;     // AF_INET=2 / AF_INET6=10
};

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(conn_events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_evt_t evt = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task && task->real_parent) {
        evt.ppid = task->real_parent->tgid;
    }

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.filename[0] = '\0';   // 完整路径由用户态从 /proc 补充

    exec_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct conn_evt_t evt = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid >> 32;

    // 读用户态 sockaddr（只处理 IPv4，IPv6 读前 16 字节拿 family）
    struct sockaddr_in addr4 = {};
    bpf_probe_read_user(&addr4, sizeof(addr4), (void *)args->uservaddr);

    evt.family = addr4.sin_family;
    if (evt.family == AF_INET) {
        evt.daddr = addr4.sin_addr.s_addr;
        evt.dport = addr4.sin_port;
        conn_events.perf_submit(args, &evt, sizeof(evt));
    }
    return 0;
}
"""

AF_INET = 2


def _is_local(ip: str) -> bool:
    """本地/私有网段判断（回环、链路本地、RFC1918 私网）。"""
    if ip.startswith("127.") or ip == "0.0.0.0" or ip.startswith("169.254."):
        return True
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (ValueError, IndexError):
            pass
    return False


def _ipv4(addr_net_bytes: int) -> str:
    # sin_addr.s_addr 存网络字节序，小端机上读出为反序 u32，按 little 还原
    b = addr_net_bytes.to_bytes(4, "little")
    return ".".join(str(x) for x in b)


def _ntohs(v: int) -> int:
    return ((v & 0xFF) << 8) | ((v >> 8) & 0xFF)


# ---------------- schema 0.1（与 agent.py 同构的自包含副本）
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


class EBpfTracer:
    def __init__(self, report_url=None, trace_id=None, debug=False):
        self.report_url = report_url
        self.debug = debug
        self.trace_id = trace_id or new_id("ebpf")
        self.session_span = new_id("span")
        self.prev_hash = "GENESIS"
        self.count = 0
        self.counts = {}
        self._pending = []
        self._stop = False
        self._sshd_pids = set()
        self._tree = set()
        self._pid_span = {}
        self._last_tree_refresh = 0

        self.bpf = BPF(text=BPF_TEXT)
        self.bpf["exec_events"].open_perf_buffer(self._on_exec, page_cnt=64)
        self.bpf["conn_events"].open_perf_buffer(self._on_conn, page_cnt=64)

    # ---- 事件构造 ----
    def _emit(self, span_id, parent_span_id, etype, actor, action):
        ev = {
            "schema_version": SCHEMA_VERSION,
            "trace_id": self.trace_id,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "source": "ebpf_tracer",
            "event_type": etype,
            "actor": actor,
            "action": action,
            "policy": {"decision": "observe",
                       "reason": "server-side eBPF: 内核态进程/连接追踪"},
            "evidence": {"prev_hash": self.prev_hash,
                         "raw_event_ref": f"object://events/{self.trace_id}/{self.count:06d}"},
        }
        ev["evidence"]["hash"] = chain_hash(self.prev_hash, ev)
        self.prev_hash = ev["evidence"]["hash"]
        self.count += 1
        self.counts[etype] = self.counts.get(etype, 0) + 1
        print(f"[{time.strftime('%H:%M:%S')}] {etype:<14} "
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
            pass  # 保留待重试

    # ---- sshd 会话树维护（复用 agent.py 思路）----
    def _refresh_tree(self):
        """定时刷新 sshd 会话 pid 集合 + 完整进程树。"""
        if time.time() - self._last_tree_refresh < 2:
            return
        self._last_tree_refresh = time.time()
        procs = {}
        sessions = set()
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
                if argv.startswith("sshd:") and "@" in argv:
                    sessions.add(pid)
            except (OSError, ValueError, IndexError):
                continue
        # 从 sshd 会话向下遍历进程树
        children = {}
        for pid, ppid in procs.items():
            children.setdefault(ppid, []).append(pid)
        tree = set()
        queue = list(sessions)
        while queue:
            cur = queue.pop()
            for c in children.get(cur, []):
                if c not in tree:
                    tree.add(c)
                    queue.append(c)
        self._sshd_pids = sessions
        self._tree = tree

    def _in_tree(self, pid, ppid):
        return pid in self._tree or ppid in self._tree or ppid in self._sshd_pids

    # ---- perf buffer 回调 ----
    def _on_exec(self, cpu, data, size):
        evt = self.bpf["exec_events"].event(data)
        pid, ppid = evt.pid, evt.ppid
        comm = evt.comm.decode("utf-8", "replace").rstrip("\x00")
        # 完整路径用户态补充（短命进程可能已退出，读不到则回退 comm）
        try:
            filename = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            filename = comm
        self._refresh_tree()
        if self.debug:
            print(f"[debug exec] pid={pid} ppid={ppid} comm={comm} "
                  f"exe={filename} in_tree={self._in_tree(pid, ppid)}", flush=True)
        if not self._in_tree(pid, ppid):
            return
        # 进程首次 exec 记录 span，后续 exec 记 process.spawn
        if pid in self._pid_span:
            parent = self._pid_span[pid]
        else:
            parent = self.session_span
        span = new_id("span")
        self._pid_span[pid] = span
        self._tree.add(pid)   # 实时纳入进程树，供后续 connect 事件按 pid 过滤
        self._emit(span, parent, "process.spawn",
                   {"type": "process", "pid": pid, "name": comm},
                   {"name": "exec",
                    "arguments_redacted": {"pid": pid, "ppid": ppid,
                                           "comm": comm,
                                           "exe": filename},
                    "result_summary": {"via_ebpf": True},
                    "summary": f"{comm} ({filename})"})

    def _on_conn(self, cpu, data, size):
        evt = self.bpf["conn_events"].event(data)
        pid = evt.pid
        if evt.family != AF_INET:
            return
        self._refresh_tree()
        if not self._in_tree(pid, 0):
            return
        daddr = _ipv4(evt.daddr)
        dport = _ntohs(evt.dport)
        span = self._pid_span.get(pid) or self.session_span
        peer_kind = "local" if _is_local(daddr) else "direct"
        self._emit(span, self.session_span, "net.connect",
                   {"type": "process", "pid": pid},
                   {"name": "connect",
                    "arguments_redacted": {"peer": f"{daddr}:{dport}",
                                           "peer_kind": peer_kind},
                    "result_summary": {"via_ebpf": True},
                    "summary": f"pid{pid} → {daddr}:{dport} "
                               f"[{'本地' if peer_kind == 'local' else '⚠️ 外联'}]"})

    def run(self, duration=None):
        signal.signal(signal.SIGTERM, self._request_stop)
        print(f"◆ ebpf_tracer begin  trace={self.trace_id} "
              f"内核追踪 execve + connect", flush=True)
        start = time.time()
        t_report = start
        while not self._stop:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
            self._refresh_tree()
            if time.time() - t_report >= 5:
                self._flush()
                t_report = time.time()
            if duration and time.time() - start >= duration:
                break
        self._flush()
        print(f"◆ ebpf_tracer end  共 {self.count} 条事件 "
              f"by_type={self.counts}", flush=True)

    def _request_stop(self, signum, frame):
        self._stop = True


def main():
    ap = argparse.ArgumentParser(description="eBPF 服务器端采集器")
    ap.add_argument("--report-url", default=None,
                    help="中央汇集器 URL（http://host:8787/ingest）")
    ap.add_argument("--trace-id", default=None)
    ap.add_argument("--duration", type=int, default=0)
    ap.add_argument("--debug", action="store_true", help="打印所有 eBPF 事件（不过滤）")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("需要 root 运行（加载 eBPF 需特权）", file=sys.stderr)
        sys.exit(1)

    tracer = EBpfTracer(report_url=args.report_url, trace_id=args.trace_id,
                        debug=args.debug)
    tracer.run(args.duration or None)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""ebpf_web_tracer.py — daemon（Web 应用）进程树版 eBPF 采集器。

与 server/ebpf_tracer.py 的区别：过滤种子。原版只保留 **sshd 会话进程树**
内的事件（为"SSH 上去操作"的场景设计）；Web 应用是 systemd 拉起的常驻服务，
不在 sshd 树里，事件会被全部过滤掉。本采集器把种子改为可配置：

  --seed-cmd  <正则>   /proc/<pid>/cmdline 命中即视为根（推荐，最直观）
                       例：--seed-cmd 'demo_app|gunicorn|my-webapp'
  --seed-unit <名称>   /proc/<pid>/cgroup 命中 systemd unit 即视为根
                       例：--seed-unit my-webapp.service
  --seed-pid  <pid>    指定 pid 及其全部后代为监视树

其余行为与原版一致：BCC 挂 sched_process_exec + sys_enter_connect
tracepoint，零漏采短命进程/瞬时连接；事件 schema 0.1 自带哈希链，
--report-url 逐批上报中央汇集器。

用法（root，Linux，需 python3-bpfcc）：
  python3 webapp/ebpf_web_tracer.py --seed-cmd demo_app \\
      --report-url http://127.0.0.1:18787/ingest
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

BPF_TEXT = r"""
#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256

struct exec_evt_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];
};

struct conn_evt_t {
    u32 pid;
    u32 daddr;
    u16 dport;
    u16 family;
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
    evt.filename[0] = '\0';

    exec_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct conn_evt_t evt = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid >> 32;

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


def _is_local(ip):
    if ip.startswith("127.") or ip == "0.0.0.0" or ip.startswith("169.254."):
        return True
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            if 16 <= int(ip.split(".")[1]) <= 31:
                return True
        except (ValueError, IndexError):
            pass
    return False


def _ipv4(addr_net_bytes):
    b = addr_net_bytes.to_bytes(4, "little")
    return ".".join(str(x) for x in b)


def _ntohs(v):
    return ((v & 0xFF) << 8) | ((v >> 8) & 0xFF)


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


def _read_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode(
                "utf-8", "replace").strip()
    except OSError:
        return ""


def _read_cgroup(pid):
    try:
        with open(f"/proc/{pid}/cgroup", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


class WebEbpfTracer:
    """daemon 进程树版 eBPF 采集器。"""

    def __init__(self, seed_cmd=None, seed_unit=None, seed_pids=None,
                 report_url=None, trace_id=None, debug=False):
        self.seed_cmd = re.compile(seed_cmd) if seed_cmd else None
        self.seed_unit = seed_unit
        self.seed_pids = set(int(p) for p in (seed_pids or []))
        self.report_url = report_url
        self.debug = debug
        self.trace_id = trace_id or new_id("ebpfweb")
        self.session_span = new_id("span")
        self.prev_hash = "GENESIS"
        self.count = 0
        self.counts = {}
        self._pending = []
        self._stop = False
        self._tree = set()
        self._pid_span = {}
        self._last_tree_refresh = 0

        self.bpf = BPF(text=BPF_TEXT)
        self.bpf["exec_events"].open_perf_buffer(self._on_exec, page_cnt=64)
        self.bpf["conn_events"].open_perf_buffer(self._on_conn, page_cnt=64)

    # ---- 事件构造（与 server/ebpf_tracer.py 一致）----
    def _emit(self, span_id, parent_span_id, etype, actor, action):
        ev = {
            "schema_version": SCHEMA_VERSION,
            "trace_id": self.trace_id,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "source": "ebpf_web_tracer",
            "event_type": etype,
            "actor": actor,
            "action": action,
            "policy": {"decision": "observe",
                       "reason": "server-side eBPF: daemon 进程树追踪"},
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
            pass

    # ---- 种子识别 + 进程树维护 ----
    def _is_root(self, pid, cmdline, cgroup):
        if self.seed_pids and pid in self.seed_pids:
            return True
        if self.seed_cmd and cmdline and self.seed_cmd.search(cmdline):
            return True
        if self.seed_unit and self.seed_unit in cgroup:
            return True
        return False

    def _refresh_tree(self):
        if time.time() - self._last_tree_refresh < 2:
            return
        self._last_tree_refresh = time.time()
        procs = {}
        roots = set()
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
            except (OSError, ValueError, IndexError):
                continue
            cmdline = _read_cmdline(pid)
            cgroup = _read_cgroup(pid) if self.seed_unit else ""
            if self._is_root(pid, cmdline, cgroup):
                roots.add(pid)
        # 从种子根向下遍历进程树（自根包含）
        children = {}
        for pid, ppid in procs.items():
            children.setdefault(ppid, []).append(pid)
        tree = set(roots)
        queue = list(roots)
        while queue:
            cur = queue.pop()
            for c in children.get(cur, []):
                if c not in tree:
                    tree.add(c)
                    queue.append(c)
        # 已退出但仍被 span 追踪的 pid 保留（短命进程后续 connect 归属）
        self._tree = tree | {p for p in self._pid_span if p not in tree}

    def _in_tree(self, pid, ppid):
        return pid in self._tree or ppid in self._tree

    # ---- perf buffer 回调 ----
    def _on_exec(self, cpu, data, size):
        evt = self.bpf["exec_events"].event(data)
        pid, ppid = evt.pid, evt.ppid
        comm = evt.comm.decode("utf-8", "replace").rstrip("\x00")
        try:
            filename = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            filename = comm
        self._refresh_tree()
        if self.debug:
            print(f"[debug exec] pid={pid} ppid={ppid} comm={comm} "
                  f"in_tree={self._in_tree(pid, ppid)}", flush=True)
        if not self._in_tree(pid, ppid):
            return
        if pid in self._pid_span:
            parent = self._pid_span[pid]
        else:
            parent = self.session_span
        span = new_id("span")
        self._pid_span[pid] = span
        self._tree.add(pid)
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
        seed_desc = []
        if self.seed_cmd:
            seed_desc.append(f"cmd~/{self.seed_cmd.pattern}/")
        if self.seed_unit:
            seed_desc.append(f"unit={self.seed_unit}")
        if self.seed_pids:
            seed_desc.append(f"pids={sorted(self.seed_pids)}")
        print(f"◆ ebpf_web_tracer begin  trace={self.trace_id} "
              f"种子: {', '.join(seed_desc) or '(无，请指定种子!)'}", flush=True)
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
        print(f"◆ ebpf_web_tracer end  共 {self.count} 条事件 "
              f"by_type={self.counts}", flush=True)

    def _request_stop(self, signum, frame):
        self._stop = True


def main():
    ap = argparse.ArgumentParser(description="daemon 进程树版 eBPF 采集器")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--seed-cmd", default=None,
                   help="进程 cmdline 正则，命中即根（推荐）")
    g.add_argument("--seed-unit", default=None,
                   help="systemd unit 名（按 /proc/<pid>/cgroup 匹配）")
    g.add_argument("--seed-pid", type=int, default=None,
                   help="根进程 pid（含全部后代）")
    ap.add_argument("--report-url", default=None,
                    help="中央汇集器 URL（http://host:18787/ingest）")
    ap.add_argument("--trace-id", default=None)
    ap.add_argument("--duration", type=int, default=0)
    ap.add_argument("--debug", action="store_true",
                    help="打印所有 eBPF 事件（不过滤）")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("需要 root 运行（加载 eBPF 需特权）", file=sys.stderr)
        sys.exit(1)

    tracer = WebEbpfTracer(
        seed_cmd=args.seed_cmd,
        seed_unit=args.seed_unit,
        seed_pids=[args.seed_pid] if args.seed_pid else None,
        report_url=args.report_url, trace_id=args.trace_id,
        debug=args.debug)
    tracer.run(args.duration or None)


if __name__ == "__main__":
    main()

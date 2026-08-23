#!/usr/bin/env python3
"""Agent-Monitor 服务器端采集器（server agent）。

背景（2026-08-23 实战）：本地观察器看得见 Kiro 在 Mac 上做什么，但 Kiro
SSH 部署到服务器之后的动作完全是黑箱（写什么文件、跑什么命令、往外联
什么）。本采集器部署在被部署的服务器上，补上这一段视野。

监视范围（root 运行，systemd 常驻）：
  SSH 会话   /proc 扫描 sshd 会话进程（"sshd: user@pts/N"）的完整进程树
             —— 远端 Agent（Kiro）在 SSH 里跑的每条命令都是这个树的子孙
  进程       树内新进程 → process.spawn（argv 来自 /proc/pid/cmdline）
  网络       /proc/net/tcp(+6) ESTABLISHED + /proc/*/fd 的 socket inode 映射
             → sshd 树内进程的外联（数据外传可见）+ 连往 22 端口的会话
  文件       可配置监视根（默认 /opt /srv /root /var/www /home）walk-diff
             → fs.create / fs.write / fs.delete
  内容嗅探   新写小文本文件命中私钥/明文密码/token 模式 → 实时 R1 告警
             （remote-deploy.sh 带密码落盘的瞬间就报警，不用等事后）

事件与本地观察器同 schema 0.1（SHA-256 哈希链防篡改，自包含无外部依赖）。
输出：/var/lib/agent-monitor/events/srv_<trace_id>.ndjson（逐事件实时落盘）
可选：--report-url http://<监视机>:8787/ingest 逐批上报中央汇集器。

用法（root）：
  python3 server/agent.py --watch /opt,/srv --report-url http://...:8787/ingest
  优雅停止：touch /var/lib/agent-monitor/STOP 或 systemctl stop agent-monitor
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
STATE_DIR = "/var/lib/agent-monitor"
STOP_FILE = os.path.join(STATE_DIR, "STOP")
GRACEFUL_EXIT_CODE = 42

# ------------------------------------------------ schema 0.1（自包含副本）
HASHED_FIELDS = [
    "schema_version", "trace_id", "span_id", "parent_span_id", "timestamp",
    "source", "event_type", "actor", "action", "policy",
]

_VALUE_KEYS = re.compile(
    r"(?i)^(authorization|cookie|set-cookie|password|passwd|secret|token|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?id)$")
_STRING_PATTERNS = [
    re.compile(r"(?i)(authorization|bearer)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*\S+"),
    re.compile(r"sk-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]
REDACTED = "[REDACTED]"


def redact(obj):
    if isinstance(obj, dict):
        return {k: (REDACTED if _VALUE_KEYS.match(str(k)) and v else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, str):
        for pat in _STRING_PATTERNS:
            obj = pat.sub(REDACTED, obj)
    return obj


def truncate(s, n=500):
    return s if len(s) <= n else s[:n] + "...[truncated]"


def new_id(prefix):
    ts = int(time.time() * 1000)
    return f"{prefix}_{ts:012x}{secrets.token_hex(10)}"


def _strip_nulls(obj):
    if isinstance(obj, dict):
        return {k: _strip_nulls(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_nulls(x) for x in obj if x is not None]
    return obj


def canonical_core(event):
    core = {k: event.get(k) for k in HASHED_FIELDS}
    core["evidence"] = {k: v for k, v in (event.get("evidence") or {}).items()
                        if k != "hash"}
    core = _strip_nulls(core)
    return json.dumps(core, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def chain_hash(prev_hash, event):
    return hashlib.sha256(
        (prev_hash + "|" + canonical_core(event)).encode()).hexdigest()


class EventWriter:
    def __init__(self, events_dir, trace_id):
        os.makedirs(events_dir, exist_ok=True)
        self.path = os.path.join(events_dir, f"{trace_id}.ndjson")
        self.trace_id = trace_id
        self.prev_hash = "GENESIS"
        self.count = 0
        self._fh = open(self.path, "a", encoding="utf-8")

    def build(self, source, event_type, span_id, parent_span_id,
              actor, action=None, policy=None):
        return {
            "schema_version": SCHEMA_VERSION,
            "trace_id": self.trace_id,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "source": source,
            "event_type": event_type,
            "actor": actor,
            "action": action or {},
            "policy": policy or {},
            "evidence": {},
        }

    def emit(self, event):
        event["evidence"]["prev_hash"] = self.prev_hash
        event["evidence"]["raw_event_ref"] = (
            f"object://events/{self.trace_id}/{self.count:06d}")
        h = chain_hash(self.prev_hash, event)
        event["evidence"]["hash"] = h
        self.prev_hash = h
        self._fh.write(json.dumps(event, ensure_ascii=False) + "\n")
        self._fh.flush()
        self.count += 1
        return event

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass


def resume_chain(writer, events_dir):
    """断点续写：从已有文件恢复 prev_hash / count。"""
    path = writer.path
    last = None
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line)
                    except json.JSONDecodeError:
                        continue
    if last:
        writer.prev_hash = last.get("evidence", {}).get("hash", "GENESIS")
        writer.count = sum(1 for _ in open(path, encoding="utf-8"))


# ------------------------------------------------ 内容密钥嗅探
SECRET_CONTENT_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("sshpass-password", re.compile(r"(?i)\bsshpass\b[^|;&]*\s-p\s+\S+")),
    ("password-assign", re.compile(
        r"(?i)\b(passw(or)?d|pwd|secret|token|api[_-]?key|server_pass)\b"
        r"\s*[=:]\s*['\"]?[^\s'\"]{8,}")),
]
SNIFF_MAX_BYTES = 262144
SNIFF_SUFFIXES = {".sh", ".py", ".env", ".yml", ".yaml", ".json", ".txt",
                  ".md", ".conf", ".toml", ".ini", ".cfg", ".js", ".ts",
                  ".go", ".rb", ""}


def sniff_secrets(abs_path):
    hits = []
    try:
        st = os.stat(abs_path)
        if st.st_size <= 0 or st.st_size > SNIFF_MAX_BYTES:
            return hits
        if os.path.splitext(abs_path)[1].lower() not in SNIFF_SUFFIXES:
            return hits
        with open(abs_path, "rb") as f:
            text = f.read().decode("utf-8", "replace")
        for name, pat in SECRET_CONTENT_PATTERNS:
            m = pat.search(text)
            if m:
                hits.append((name, text[:m.start()].count("\n") + 1))
    except OSError:
        pass
    return hits


# ------------------------------------------------ /proc 采集
SSHD_SESSION_RE = re.compile(r"sshd:.*(@|notty)")


def proc_snapshot():
    """({pid: {"ppid": int, "argv": str, "exe": str}}, {pid: sshd会话描述})"""
    procs, sessions = {}, {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            with open(f"/proc/{pid}/stat", "rb") as f:
                # pid (comm) state ppid —— comm 可能含空格，按括号定位
                data = f.read().decode("utf-8", "replace")
                rp = data.rpartition(")")
                fields = rp[2].split()
                ppid = int(fields[1])
            argv = ""
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = f.read().replace(b"\x00", b" ").decode(
                    "utf-8", "replace").strip()
            comm = data[data.index("(") + 1:data.rindex(")")]
            procs[pid] = {"ppid": ppid, "argv": argv or f"[{comm}]"}
            m = SSHD_SESSION_RE.search(argv)
            if m:
                sessions[pid] = argv
        except (OSError, ValueError, IndexError):
            continue
    return procs, sessions


def tree_from(procs, seeds):
    tree = set(seeds)
    children = {}
    for pid, d in procs.items():
        children.setdefault(d["ppid"], []).append(pid)
    queue = list(seeds)
    while queue:
        cur = queue.pop()
        for c in children.get(cur, []):
            if c not in tree:
                tree.add(c)
                queue.append(c)
    return tree


def net_snapshot():
    """ESTABLISHED 连接 [(inode, local, peer)]。"""
    conns = []
    for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(fn, encoding="utf-8") as f:
                lines = f.read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10 or parts[3] != "01":   # 01 = ESTABLISHED
                continue
            def _fmt(a):
                ip, port = a.split(":")
                return f"{int(port, 16)}"
            local_port = _fmt(parts[1])
            peer_ip_hex, peer_port_hex = parts[2].split(":")
            peer_port = int(peer_port_hex, 16)
            conns.append((parts[9], local_port, peer_ip_hex, peer_port))
    return conns


def inode_owner_map():
    """{socket inode: pid}——扫 /proc/*/fd。"""
    owners = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        fddir = f"/proc/{name}/fd"
        try:
            for fd in os.listdir(fddir):
                try:
                    link = os.readlink(os.path.join(fddir, fd))
                except OSError:
                    continue
                if link.startswith("socket:["):
                    owners[link[8:-1]] = int(name)
        except OSError:
            continue
    return owners


def hex_to_ip(h):
    if len(h) == 8:  # /proc/net/tcp 的 IPv4：8 位 hex，按小端字组翻转
        return ".".join(str(int(h[i:i + 2], 16)) for i in (6, 4, 2, 0))
    if len(h) != 32:
        return h
    # IPv6：8 组 4 hex，翻转每 32 位字内的字节序
    groups = [h[i:i + 4] for i in range(0, 32, 4)]
    fixed = []
    for g in groups:
        fixed.append("".join(reversed([g[i:i + 2] for i in (0, 2)])))
    return ":".join(fixed)


def _is_local(ip):
    return ip in ("127.0.0.1", "::1", "0.0.0.0")


# ------------------------------------------------ 文件监控
DEFAULT_WATCH = ["/opt", "/srv", "/root", "/var/www", "/home"]
EXCLUDE_DIRS = {"node_modules", "__pycache__", ".cache", "cache", "logs",
                ".git/objects", "proc", "sys", "dev", "run"}


def scan_files(roots):
    state = {}
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames
                           if d not in EXCLUDE_DIRS and not d.startswith(".git")]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                try:
                    st = os.stat(full)
                    state[full] = (st.st_mtime_ns, st.st_size)
                except OSError:
                    pass
    return state


# ------------------------------------------------ 实时告警
def check_alerts(ev, workspace_roots, alerts_fh):
    alerts = []
    etype = ev.get("event_type")
    args = (ev.get("action") or {}).get("arguments_redacted") or {}
    if etype in ("fs.create", "fs.write", "fs.delete"):
        path = args.get("path", "")
        verb = {"fs.create": "创建", "fs.write": "写入", "fs.delete": "删除"}[etype]
        if etype in ("fs.create", "fs.write"):
            for name, line_no in sniff_secrets(path):
                alerts.append((f"文件内容含疑似密钥（模式 {name}，第 {line_no} 行）"
                               f"— {path}", "R1"))
        base = os.path.basename(path).lower()
        if any(s in base for s in ("id_rsa", ".env", "secret", "credential",
                                   ".pem", ".key")):
            alerts.append((f"{verb}了敏感命名文件 {path}", "R1"))
        if not any(path.startswith(r) for r in workspace_roots):
            alerts.append((f"文件操作越界：{verb} {path} 不在监视根内", "R2"))
    elif etype == "net.connect":
        peer = args.get("peer", "")
        if args.get("peer_kind") == "direct":
            alerts.append((f"SSH 会话内进程外联 {peer}", "R3"))
    for detail, rule_id in alerts:
        a = {"rule_id": rule_id,
             "rule_name": {"R1": "密钥访问", "R2": "越界写入",
                           "R3": "异常外联"}[rule_id],
             "severity": "high", "trace_id": ev.get("trace_id"),
             "span_id": ev.get("span_id"),
             "timestamp": ev.get("timestamp"),
             "event_type": etype, "source": ev.get("source"),
             "detail": detail}
        alerts_fh.write(json.dumps(a, ensure_ascii=False) + "\n")
        alerts_fh.flush()
        print(f"\033[31m🚨 [{rule_id}] {detail}\033[0m", flush=True)


# ------------------------------------------------ 主采集器
class ServerAgent:
    def __init__(self, watch_roots, events_dir, report_url=None,
                 poll_proc=0.5, poll_net=1.0, poll_file=3.0, resume=None):
        self.watch_roots = [os.path.realpath(r) for r in watch_roots]
        self.poll_proc, self.poll_net, self.poll_file = poll_proc, poll_net, poll_file
        self.report_url = report_url
        self.trace_id = resume or new_id("srv")
        self.writer = EventWriter(events_dir, self.trace_id)
        if resume:
            resume_chain(self.writer, events_dir)
        self.alerts_path = os.path.join(events_dir, f"{self.trace_id}_alerts.ndjson")
        self.alerts_fh = open(self.alerts_path, "a", encoding="utf-8")
        self.session_span = new_id("span")
        self.pid_spans = {}
        self.seen_pids = {}
        self.baselined = False
        self.ssh_sessions = {}       # pid -> argv 描述
        self.seen_conns = set()
        self.file_baseline = None
        self.counts = {}
        self.start_time = time.time()
        self._stop = False
        self._pending_report = []

    def emit(self, span, parent, etype, actor, action):
        ev = self.writer.build(
            source="server_agent", event_type=etype,
            span_id=span, parent_span_id=parent,
            actor=actor, action=redact(action),
            policy={"decision": "observe",
                    "reason": "server-side: 被部署主机上的被动采集"})
        self.writer.emit(ev)
        self.counts[etype] = self.counts.get(etype, 0) + 1
        check_alerts(ev, self.watch_roots, self.alerts_fh)
        if self.report_url:
            self._pending_report.append(json.dumps(ev, ensure_ascii=False))
            if len(self._pending_report) >= 5:
                self._flush_report()
        return ev

    def _flush_report(self):
        if not self._pending_report or not self.report_url:
            return
        body = "\n".join(self._pending_report).encode()
        req = urllib.request.Request(
            self.report_url, data=body,
            headers={"Content-Type": "application/x-ndjson",
                     "X-Trace-Id": self.trace_id})
        try:
            urllib.request.urlopen(req, timeout=5)
            self._pending_report = []
        except Exception as e:
            print(f"[report] 上报失败（{e}），保留待重试", flush=True)

    def proc_span(self, pid, argv):
        if pid not in self.pid_spans:
            sp = new_id("span")
            self.pid_spans[pid] = sp
            self.emit(sp, self.session_span, "process.span",
                      {"type": "process", "pid": pid,
                       "name": argv.split(" ")[0].split("/")[-1]},
                      {"name": "process",
                       "arguments_redacted": {"pid": pid, "exe": argv},
                       "result_summary": {}})
        return self.pid_spans[pid]

    def poll_processes(self):
        procs, sessions = proc_snapshot()
        # 新 SSH 会话 → ssh.session.open
        for pid, desc in sessions.items():
            if pid not in self.ssh_sessions:
                self.ssh_sessions[pid] = desc
                self.emit(new_id("span"), self.session_span, "ssh.session.open",
                          {"type": "session", "pid": pid},
                          {"name": "ssh_session_open",
                           "arguments_redacted": {"sshd_pid": pid,
                                                  "desc": truncate(desc, 120)},
                           "result_summary": {}})
                self._print(f"🔓 ssh.session.open {desc}")
        for pid in list(self.ssh_sessions):
            if pid not in sessions:
                desc = self.ssh_sessions.pop(pid)
                self.emit(self.session_span, None, "ssh.session.close",
                          {"type": "session", "pid": pid},
                          {"name": "ssh_session_close",
                           "arguments_redacted": {"sshd_pid": pid,
                                                  "desc": truncate(desc, 120)},
                           "result_summary": {}})
                self._print(f"🔒 ssh.session.close {desc}")

        tree = tree_from(procs, set(self.ssh_sessions))
        if not self.baselined and tree:
            for pid in sorted(tree):
                self.seen_pids[pid] = procs[pid]["argv"]
                self.proc_span(pid, self.seen_pids[pid])
            self.baselined = True
            self._print(f"  进程基线：{len(tree)} 个（sshd 会话 {len(self.ssh_sessions)}）")
            return
        for pid in sorted(tree):
            if pid not in self.seen_pids:
                argv = procs[pid]["argv"]
                self.seen_pids[pid] = argv
                parent_span = self.pid_spans.get(procs[pid]["ppid"]) or \
                    self.session_span
                self.emit(new_id("span"), parent_span, "process.spawn",
                          {"type": "process", "pid": pid,
                           "name": argv.split(" ")[0].split("/")[-1]},
                          {"name": "spawn",
                           "arguments_redacted": {
                               "pid": pid, "ppid": procs[pid]["ppid"],
                               "argv": truncate(argv, 400),
                               "via_ssh": True},
                           "result_summary": {"tree_size": len(tree)}})
                self._print(f"🌱 process.spawn pid{pid} "
                            f"{argv.split(' ')[0].split('/')[-1]}  "
                            f"{truncate(argv, 80)}")
                self.proc_span(pid, argv)
        for pid in list(self.seen_pids):
            if pid not in tree:
                argv = self.seen_pids.pop(pid)
                self.emit(self.pid_spans.get(pid, self.session_span),
                          self.session_span, "process.exit",
                          {"type": "process", "pid": pid},
                          {"name": "exit",
                           "arguments_redacted": {"pid": pid},
                           "result_summary": {"argv": truncate(argv, 200)}})

    def poll_network(self):
        owners = inode_owner_map()
        for inode, local_port, peer_ip_hex, peer_port in net_snapshot():
            pid = owners.get(inode)
            if pid is None or pid not in self.seen_pids:
                continue
            peer_ip = hex_to_ip(peer_ip_hex)
            key = (pid, local_port, peer_ip, peer_port)
            if key in self.seen_conns:
                continue
            self.seen_conns.add(key)
            if pid in self.ssh_sessions:
                pk = "ssh-inbound"   # sshd 会话自身的接入连接，非主动外联
            elif _is_local(peer_ip):
                pk = "local"
            else:
                pk = "direct"
            span = self.pid_spans.get(pid) or self.proc_span(
                pid, self.seen_pids.get(pid, ""))
            self.emit(span, self.session_span, "net.connect",
                      {"type": "process", "pid": pid},
                      {"name": "connect",
                       "arguments_redacted": {
                           "local_port": local_port,
                           "peer": f"{peer_ip}:{peer_port}",
                           "peer_kind": pk},
                       "result_summary": {}})
            self._print(f"🌐 net.connect   pid{pid} → {peer_ip}:{peer_port} "
                        f"[{'SSH接入' if pk == 'ssh-inbound' else '本地' if pk == 'local' else '⚠️ 外联'}]")

    def poll_files(self):
        cur = scan_files(self.watch_roots)
        if self.file_baseline is None:
            self.file_baseline = cur
            return
        base = self.file_baseline
        for path, st in cur.items():
            if path not in base:
                etype, icon, verb = "fs.create", "🆕", "创建"
            elif base[path] != st:
                etype, icon, verb = "fs.write", "✍️", "修改"
            else:
                continue
            self.emit(new_id("span"), self.session_span, etype,
                      {"type": "filesystem", "path": path},
                      {"name": verb,
                       "arguments_redacted": {"path": path},
                       "result_summary": {"size": st[1]}})
            self._print(f"{icon} {etype:<11} {path}  ({st[1]}B)")
        for path in base:
            if path not in cur:
                self.emit(new_id("span"), self.session_span, "fs.delete",
                          {"type": "filesystem", "path": path},
                          {"name": "删除",
                           "arguments_redacted": {"path": path},
                           "result_summary": {}})
                self._print(f"🗑️ fs.delete     {path}")
        self.file_baseline = cur

    def heartbeat(self):
        self.emit(self.session_span, None, "session.heartbeat",
                  {"type": "agent", "name": "server-agent"},
                  {"name": "heartbeat",
                   "arguments_redacted": {},
                   "result_summary": {
                       "uptime_sec": round(time.time() - self.start_time, 0),
                       "events": self.writer.count,
                       "ssh_sessions": len(self.ssh_sessions),
                       "watched_processes": len(self.seen_pids)}})

    def _print(self, msg):
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

    def run(self, duration=None):
        signal.signal(signal.SIGTERM, self._request_stop)
        self.emit(self.session_span, None, "trace.begin",
                  {"type": "host", "name": os.uname().nodename,
                   "mode": "server-agent"},
                  {"name": "server_session",
                   "arguments_redacted": {
                       "watch_roots": self.watch_roots,
                       "note": "服务器端被动采集：SSH 会话进程树 + 文件 + 外联"},
                   "result_summary": {}})
        self._print(f"◆ trace.begin    server={os.uname().nodename} "
                    f"roots={self.watch_roots}")
        t_proc = t_net = t_file = t_hb = t_report = time.time()
        while not self._stop:
            now = time.time()
            try:
                if now - t_proc >= self.poll_proc:
                    self.poll_processes(); t_proc = now
                if now - t_net >= self.poll_net:
                    self.poll_network(); t_net = now
                if now - t_file >= self.poll_file:
                    self.poll_files(); t_file = now
                if now - t_hb >= 30:
                    self.heartbeat(); t_hb = now
                if now - t_report >= 5:
                    self._flush_report(); t_report = now
            except Exception as e:
                self._print(f"⚠️ 采集轮询异常（{e}），继续")
                time.sleep(1)
            if os.path.exists(STOP_FILE):
                try:
                    os.remove(STOP_FILE)
                except OSError:
                    pass
                break
            if duration and now - self.start_time >= duration:
                break
            time.sleep(0.15)

        self._flush_report()
        self.emit(self.session_span, None, "trace.end",
                  {"type": "host", "name": os.uname().nodename},
                  {"name": "server_session_end",
                   "arguments_redacted": {},
                   "result_summary": {
                       "duration_sec": round(time.time() - self.start_time, 1),
                       "events": self.writer.count,
                       "by_type": self.counts}})
        self.writer.close()
        self.alerts_fh.close()
        self._print(f"◆ trace.end      共 {self.writer.count} 条事件 → "
                    f"{self.writer.path}")

    def _request_stop(self, signum, frame):
        self._stop = True


def main():
    ap = argparse.ArgumentParser(description="Agent-Monitor 服务器端采集器")
    ap.add_argument("--watch", default=",".join(DEFAULT_WATCH),
                    help="逗号分隔的监视根目录")
    ap.add_argument("--events-dir", default=os.path.join(STATE_DIR, "events"))
    ap.add_argument("--report-url", default=None,
                    help="中央汇集器 URL（http://host:8787/ingest）")
    ap.add_argument("--poll-proc", type=float, default=0.5)
    ap.add_argument("--poll-net", type=float, default=1.0)
    ap.add_argument("--poll-file", type=float, default=3.0)
    ap.add_argument("--duration", type=int, default=0)
    ap.add_argument("--resume", default=None, help="续写的 trace_id")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("建议 root 运行（否则看不到其他用户进程与 socket 归属）",
              file=sys.stderr)

    agent = ServerAgent(
        [r.strip() for r in args.watch.split(",") if r.strip()],
        args.events_dir, report_url=args.report_url,
        poll_proc=args.poll_proc, poll_net=args.poll_net,
        poll_file=args.poll_file, resume=args.resume)
    agent.run(args.duration or None)
    sys.exit(GRACEFUL_EXIT_CODE if agent._stop else 0)


if __name__ == "__main__":
    main()

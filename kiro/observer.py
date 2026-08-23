#!/usr/bin/env python3
"""Kiro 被动观察器 v2：监视第三方 AI IDE（Kiro）的系统级行为。

v2 针对实战（2026-08-23 kiro_agent_test 部署监视战）暴露的问题全面升级：

  盲区修复  全进程树追踪：不只 Kiro.app 前缀进程，凡 pid→ppid 链可达
            Kiro 种子进程的都是目标（Kiro 终端里跑的 go/git/ssh 孙进程
            全部入镜）；ps 不可用时 libproc 降级也带 ppid（PROC_PIDTBSDINFO）。
            另支持 --seed-pid / --seed-pattern 监视任意 Agent，产品化通用。
  网络归属  lsof 连接按"当轮实时进程树"归属，不等 spawn 事件先落账——
            短命孙进程（git push / ssh）的连接不再漏拍。
  实时告警  内嵌规则引擎：R1/R2/R3 事件级即时评估 + 文件内容嗅探
            （明文密码 / 私钥 / token 模式），🚨 实时打印并落盘
            <trace>_alerts.ndjson——进程被杀告警也在磁盘上。
  长期运行  逐事件实时落盘（原有）+ --resume 断点续写（哈希链无缝接续）
            + STOP 哨兵文件 + SIGTERM 优雅退出（退出码 42 = 正常停止，
            watchdog 据此不再拉起）+ 30 秒心跳事件（监视空窗可检测）。

事件复用 schema 0.1（SHA-256 哈希链防篡改），span 树：
  kiro.session（root）
  ├─ 进程 span（每 pid 一个）── net.connect / process.spawn / process.exit
  └─ workspace span ── fs.create / fs.write / fs.delete

用法：
  python3 kiro/observer.py --workspace /path/to/project [--duration 600]
  python3 kiro/observer.py --workspace ... --resume <trace_id>   # 断点续写
  python3 kiro/observer.py --workspace ... --seed-pid <pid>      # 监视任意 Agent
  优雅停止：touch events/STOP 或 kill -TERM <pid>（watchdog 配合）
"""
import argparse
import ctypes
import ctypes.util
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "runtime"))
sys.path.insert(0, os.path.join(ROOT, "correlator"))
from trace import EventWriter, new_id, redact, truncate  # noqa: E402
import rules as rules_mod  # noqa: E402  R1/R2/R3 复用同一套规则语义

KIRO_APP_PREFIX = "/Applications/Kiro.app"
DEFAULT_EXCLUDE = {"node_modules", ".venv", "__pycache__", ".next", "dist",
                   "build", ".turbo", ".DS_Store", "target", "vendor"}
GRACEFUL_EXIT_CODE = 42          # watchdog 约定：42 = 优雅停止，不重启

# ------------------------------------------------ 文件内容密钥嗅探（实时 R1）
SECRET_CONTENT_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("sshpass-password", re.compile(r"(?i)\bsshpass\b[^|;&]*\s-p\s+\S+")),
    ("password-assign", re.compile(
        r"(?i)\b(passw(or)?d|pwd|secret|token|api[_-]?key|server_pass)\b"
        r"\s*[=:]\s*['\"]?[^\s'\"]{8,}")),
]
SNIFF_MAX_BYTES = 262144         # 只嗅探 ≤256KB 的文件
SNIFF_SUFFIXES = {".sh", ".py", ".env", ".yml", ".yaml", ".json", ".txt",
                  ".md", ".conf", ".toml", ".ini", ".cfg", ".js", ".ts",
                  ".go", ".rb", ""}


# ---------------------------------------------------------------- 进程快照
def _libc():
    return ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def ps_snapshot():
    """ps 全量快照：{pid: {"ppid": int|None, "argv": str}}。

    每次 fork 一个 ps 子进程（~200-400ms），仅用于低频刷新（种子 argv 前缀
    匹配、脚本型 Agent 兜底）；高频轮询走 libproc_scan()。
    """
    try:
        r = subprocess.run(["ps", "-axo", "pid=,ppid=,args="],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0 and r.stdout.strip():
            procs = {}
            for line in r.stdout.splitlines():
                parts = line.strip().split(None, 2)
                if len(parts) == 3:
                    try:
                        procs[int(parts[0])] = {"ppid": int(parts[1]),
                                                "argv": parts[2]}
                    except ValueError:
                        pass
            if procs:
                return procs, "ps"
    except Exception:
        pass
    return {}, "ps"


def _kern_proc_ppids():
    """sysctl KERN_PROC_ALL → {pid: ppid}。单次系统调用，毫秒级。

    高频轮询快路径：树构建只需要 pid/ppid 图（exe/argv 只对树内新 pid
    按需补抓），比全量扫描快一个量级，支持 0.1s 级轮询。
    kinfo_proc 记录 648 字节（darwin 实证）：pid @ +40，ppid @ +560，
    用 launchd(pid=1 → ppid=0) 自校验，失败返回 None（调用方走 ps 兜底）。
    """
    libc = _libc()
    mib = (ctypes.c_int * 3)(1, 14, 0)              # CTL_KERN, KERN_PROC, KERN_PROC_ALL
    size = ctypes.c_size_t(0)
    if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0 \
            or size.value < 648:
        return None
    buf = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0:
        return None
    raw = buf.raw[:size.value]
    out = {}
    offset_ok = False
    for i in range(len(raw) // 648):
        b = i * 648
        pid = int.from_bytes(raw[b + 40:b + 44], "little", signed=True)
        ppid = int.from_bytes(raw[b + 560:b + 564], "little", signed=True)
        if pid == 1 and ppid == 0:
            offset_ok = True
        if pid > 0:
            out[pid] = ppid
    return out if offset_ok else None


def libproc_scan():
    """libproc 全量扫描：{pid: {"ppid", "exe", "argv"(None)}}。

    低频刷新用（每 10s）：种子重发现（exe/argv 前缀匹配）+ argv 兜底。
    ppid 走 KERN_PROC_ALL（与 ps 同源）——注意 proc_pidinfo(PROC_PIDTBSDINFO)
    实测对本机所有进程返回 0/ENOMEM，不可用。
    """
    ppids = _kern_proc_ppids()
    if ppids is None:
        return {}, "libproc"
    libc = _libc()
    procs = {}
    pathbuf = ctypes.create_string_buffer(4096)
    for pid in ppids:
        exe = ""
        if libc.proc_pidpath(pid, pathbuf, 4096) > 0:
            exe = pathbuf.value.decode("utf-8", "replace")
        procs[pid] = {"ppid": ppids[pid], "exe": exe, "argv": None}
    return procs, "libproc"


def _proc_argv(libc, pid):
    """KERN_PROCARGS2 取单个进程完整 argv（按 argc 截断，不带环境变量）。

    失败返回 None（进程已退出/权限不足）——此时调用方降级用 exe 路径。
    """
    try:
        mib = (ctypes.c_int * 3)(1, 49, pid)
        size = ctypes.c_size_t(0)
        if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) == 0 \
                and 0 < size.value < 1 << 20:
            b = ctypes.create_string_buffer(size.value)
            if libc.sysctl(mib, 3, b, ctypes.byref(size), None, 0) == 0:
                argc = int.from_bytes(b.raw[:4], "little", signed=True)
                if 0 < argc < 4096:
                    parts = b.raw[4:].split(b"\x00")
                    # 布局实证（2026-08-23）：argc(4B) + [exec_path] + argv[0..argc-1] + envp
                    # 第一个字符串是 exec 路径（独立于 argv），必须跳过，否则丢最后一个参数
                    cand = [p.decode("utf-8", "replace")
                            for p in parts[1:1 + argc]]
                    cand = [p for p in cand if p]
                    if cand:
                        return " ".join(cand)
    except Exception:
        pass
    return None


def build_tree(procs, seed_pids, extra_prefixes=()):
    """种子进程 + ppid 可达的全部子孙（Kiro 终端里的 shell/go/git/ssh…）。"""
    tree = set(seed_pids)
    children = {}
    for pid, d in procs.items():
        pp = d.get("ppid")
        if pp is not None:
            children.setdefault(pp, []).append(pid)
    queue = list(seed_pids)
    while queue:
        cur = queue.pop()
        for c in children.get(cur, []):
            if c not in tree:
                tree.add(c)
                queue.append(c)
    # 孤儿兜底：exe/argv 路径命中额外前缀（如 workspace 里编译出的二进制，
    # 中间父进程已退出导致 ppid 链断裂时仍可追踪）
    for pid, d in procs.items():
        if pid in tree:
            continue
        a = (d.get("argv") or "") or (d.get("exe") or "")
        for pfx in extra_prefixes:
            if pfx and a.startswith(pfx):
                tree.add(pid)
                break
    return tree


# ---------------------------------------------------------------- 网络快照
def lsof_snapshot():
    """[(pid, local, peer_host, peer_port, kind)]，kind ∈ {connect, listen}。"""
    try:
        r = subprocess.run(["lsof", "-iTCP", "-n", "-P", "-F", "pn"],
                           capture_output=True, text=True, timeout=15)
        if r.returncode != 0 and not r.stdout.strip():
            return []
        out = r.stdout
    except Exception:
        return []
    conns, cur_pid = [], None
    for line in out.splitlines():
        if line.startswith("p"):
            try:
                cur_pid = int(line[1:])
            except ValueError:
                cur_pid = None
        elif line.startswith("n") and cur_pid is not None:
            name = line[1:]
            if "->" in name:
                local, peer = name.split("->", 1)
                ph, _, pp = peer.rpartition(":")
                conns.append((cur_pid, local, ph, pp, "connect"))
            else:
                conns.append((cur_pid, name, None, None, "listen"))
    return conns


def peer_kind(peer_host):
    if peer_host in ("127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"):
        return "local"
    return "direct"


# ---------------------------------------------------------------- 文件监控
def scan_files(ws, exclude):
    state = {}
    for dirpath, dirnames, filenames in os.walk(ws):
        dirnames[:] = [d for d in dirnames if d not in exclude]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            try:
                st = os.stat(full)
                state[os.path.relpath(full, ws)] = (st.st_mtime_ns, st.st_size)
            except OSError:
                pass
    return state


def sniff_secrets(abs_path):
    """读取小文本文件，返回命中的密钥模式名列表（不外泄内容本身）。"""
    hits = []
    try:
        st = os.stat(abs_path)
        if st.st_size <= 0 or st.st_size > SNIFF_MAX_BYTES:
            return hits
        if os.path.splitext(abs_path)[1].lower() not in SNIFF_SUFFIXES:
            return hits
        with open(abs_path, "rb") as f:
            data = f.read()
        text = data.decode("utf-8", "replace")
        for name, pat in SECRET_CONTENT_PATTERNS:
            m = pat.search(text)
            if m:
                line_no = text[:m.start()].count("\n") + 1
                hits.append((name, line_no))
    except OSError:
        pass
    return hits


# ---------------------------------------------------------------- 实时告警
class RealtimeAlerts:
    """事件级即时规则评估：R1/R2/R3 + 内容嗅探，实时打印 + 落盘。"""

    def __init__(self, workspace, events_dir, trace_id):
        self.workspace = workspace
        self.ctx = {"workspace_root": workspace,
                    "net_allowlist": ["127.0.0.1", "::1", "localhost"]}
        self.path = os.path.join(events_dir, f"{trace_id}_alerts.ndjson")
        self.count = 0
        self._fh = open(self.path, "a", encoding="utf-8")

    def check(self, ev):
        alerts = rules_mod.evaluate([ev], self.ctx)
        # 内容嗅探（R1 增强）：fs.create/fs.write 命中密钥模式
        if ev.get("event_type") in ("fs.create", "fs.write"):
            rel = (ev.get("action", {}).get("arguments_redacted") or {}) \
                .get("path", "")
            if rel:
                hits = sniff_secrets(os.path.join(self.workspace, rel))
                for name, line_no in hits:
                    alerts.append({
                        "rule_id": "R1", "rule_name": "密钥访问",
                        "severity": "high", "span_id": ev.get("span_id"),
                        "parent_span_id": ev.get("parent_span_id"),
                        "trace_id": ev.get("trace_id"),
                        "timestamp": ev.get("timestamp"),
                        "event_type": ev.get("event_type"),
                        "source": ev.get("source"),
                        "detail": f"文件内容含疑似密钥（模式 {name}，"
                                  f"第 {line_no} 行）— {rel}",
                    })
        for a in alerts:
            self.count += 1
            self._fh.write(json.dumps(a, ensure_ascii=False) + "\n")
            self._fh.flush()
            print(f"\033[31m🚨 [{a['rule_id']}] {a['detail']}\033[0m",
                  flush=True)
        return alerts

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass


# ---------------------------------------------------------------- 观察器
class KiroObserver:
    def __init__(self, workspace, events_dir, poll_proc, poll_net, poll_file,
                 seed_pid=None, seed_pattern=None, resume=None, agent_name="Kiro",
                 collector_url=None, capture_reads=False):
        self.workspace = os.path.realpath(os.path.expanduser(workspace))
        self.poll_proc, self.poll_net, self.poll_file = poll_proc, poll_net, poll_file
        self.seed_pid = seed_pid
        # seed_pattern 支持逗号分隔多个前缀（如同时监视 CodeBuddy.app 与扩展宿主）
        self.seed_patterns = [p.strip() for p in (seed_pattern or KIRO_APP_PREFIX).split(",") if p.strip()]
        self.agent_name = agent_name
        self.agent_slug = re.sub(r"[^a-z0-9]+", "_", agent_name.lower()).strip("_") or "agent"
        self.collector_url = collector_url
        self.capture_reads = capture_reads
        self.stop_file = os.path.join(events_dir, "STOP")
        # 断点续写：沿用旧 trace_id + 从最后一事件恢复哈希链
        if resume:
            self.trace_id = resume
            self.writer = EventWriter(events_dir, resume)
            self._restore_chain(events_dir)
        else:
            self.trace_id = new_id(self.agent_slug)
            self.writer = EventWriter(events_dir, self.trace_id)
        self.alerts = RealtimeAlerts(self.workspace, events_dir, self.trace_id)
        self.session_span = new_id("span")
        self.ws_span = new_id("span")
        self.pid_spans = {}
        self.seen_pids = {}
        self.spawn_ts = {}             # pid → 首次见到的时间（exit 事件算存活时长用）
        self.seen_conns = set()
        self._last_ps = 0.0            # 上次全量刷新时间（种子重发现 + argv 兜底）
        self._full_procs = {}          # 低频全量扫描结果（exe/argv 缓存）
        self._pending = {}             # 新 pid 首拍信息（下一轮确认为真实 spawn，避开 fork→exec 窗口）
        self.current_tree = set()      # 当轮实时进程树（网络归属用）
        self.file_baseline = None
        self.counts = {}
        self.start_time = time.time()
        self.resumed = bool(resume)
        self._stop_requested = False
        self.seen_fds = set()          # (pid,path) 已上报的文件读取，去重
        self._emit_lock = threading.RLock()   # 事件写入串行化（哈希链 + 多线程轮询）
        self._stop_evt = threading.Event()    # 通知各轮询线程收尾


    def _restore_chain(self, events_dir):
        path = os.path.join(events_dir, f"{self.trace_id}.ndjson")
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
            self.writer.prev_hash = last.get("evidence", {}).get("hash", "GENESIS")
            self.writer.count = sum(1 for _ in open(path, encoding="utf-8"))

    # ---- 事件发射（含实时告警 + collector 广播） ----
    def emit(self, span, parent, etype, actor, action):
        with self._emit_lock:
            ev = self.writer.build(
                source=f"{self.agent_slug}_observer", event_type=etype,
                span_id=span, parent_span_id=parent,
                actor=actor, action=redact(action),
                policy={"decision": "observe",
                        "reason": "passive: 目标 Agent 不经过网关，仅系统事实观测"})
            self.writer.emit(ev)
            self.counts[etype] = self.counts.get(etype, 0) + 1
            self.alerts.check(ev)      # 实时告警：进程死了告警也在磁盘
        # 网络上报在锁外（不阻塞事件写入；乱序无害）
        self._post_collector(ev)
        return ev

    def _post_collector(self, ev):
        if not self.collector_url:
            return
        try:
            data = json.dumps(ev, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(
                self.collector_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=2)
        except Exception as e:
            # 网络抖动不致命，静默降级
            pass

    def proc_span(self, pid, argv):
        with self._emit_lock:
            if pid not in self.pid_spans:
                sp = new_id("span")
                self.pid_spans[pid] = sp
                plugin = self._agent_plugin(argv)
                actor = {"type": "process", "name": self._proc_name(argv, pid),
                         "pid": pid}
                if plugin:
                    actor["agent_plugin"] = plugin
                self.emit(sp, self.session_span, "process.span",
                          actor,
                          {"name": "process",
                           "arguments_redacted": {"pid": pid, "exe": argv,
                                                  "agent_plugin": plugin},
                           "result_summary": {}})
        return self.pid_spans[pid]

    @staticmethod
    def _proc_name(argv, pid):
        if not argv:
            return f"pid{pid}"
        return argv.split(" ")[0].split("/")[-1]

    @staticmethod
    def _agent_plugin(argv):
        """从 VS Code Extension Host/CLI 参数识别 Agent 插件。"""
        value = (argv or "").lower()
        patterns = (
            ("WorkBuddy", ("workbuddy", "codebuddyextension", "codebuddy")),
            ("Continue", ("continue.continue", "/continue/", "continue-extension")),
            ("Codex", ("openai.chatgpt", "openai.codex", "/.codex/", " codex ")),
            ("GitHub Copilot", ("github.copilot", "copilot-chat")),
            ("Cline", ("saoudrizwan.claude-dev", "cline")),
        )
        for name, needles in patterns:
            if any(needle in value for needle in needles):
                return name
        if "extensionhost" in value or "extension-host" in value:
            return "VS Code Extension Host"
        return None

    def _seed_pids(self, procs):
        seeds = [p for p, d in procs.items()
                 if any(((d.get("argv") or "").startswith(pfx) or
                         (d.get("exe") or "").startswith(pfx))
                        for pfx in self.seed_patterns)]
        if self.seed_pid and self.seed_pid in procs:
            seeds.append(self.seed_pid)
        return set(seeds)

    # ---- 三层采集 ----
    def _emit_spawn(self, pid, argv, exe, parent_pid, ts, mode):
        """发 process.spawn 事件（spawn 语义统一出口）。"""
        argv = argv or ""
        exe = exe or ""
        self.seen_pids[pid] = argv or exe
        self.spawn_ts[pid] = ts
        parent_span = (self.pid_spans.get(parent_pid) or
                       self.session_span)
        parent_argv = self.seen_pids.get(parent_pid) or ""
        plugin = self._agent_plugin(argv or exe)
        actor = {"type": "process", "name": self._proc_name(argv or exe, pid),
                 "pid": pid}
        if plugin:
            actor["agent_plugin"] = plugin
        self.emit(new_id("span"), parent_span, "process.spawn", actor,
                  {"name": "spawn",
                   "arguments_redacted": {"pid": pid,
                                          "ppid": parent_pid,
                                          "exe": truncate(exe, 200),
                                           "argv": truncate(argv or exe, 500),
                                          "agent_plugin": plugin,
                                          "parent_argv": truncate(parent_argv, 150) if parent_argv else None,
                                          "scan_mode": mode},
                   "result_summary": {"tree_size": len(self.current_tree)}})
        self._print(f"🌱 process.spawn pid{pid} "
                    f"{self._proc_name(argv or exe, pid)}  {truncate(argv or exe, 90)}")
        self.proc_span(pid, argv or exe)

    def _emit_exit(self, pid, argv):
        """发 process.exit 事件（带存活时长）。"""
        lifetime = round(time.time() - self.spawn_ts.pop(pid, time.time()), 1)
        sp = self.pid_spans.get(pid, self.session_span)
        self.emit(sp, self.session_span, "process.exit",
                  {"type": "process", "pid": pid},
                  {"name": "exit",
                   "arguments_redacted": {"pid": pid,
                                          "argv": truncate(argv or "", 300),
                                          "lifetime_sec": lifetime},
                   "result_summary": {"argv": truncate(argv or "", 200)}})

    def _refetch_pending(self, pid):
        """30ms 定时器回调：重取 pending pid 的 exe/argv（跨过 fork→exec 窗口）。"""
        info = self._pending.get(pid)
        if info is None:
            return  # 已被确认/发事件，无需重取
        try:
            libc = _libc()
            argv = _proc_argv(libc, pid)
            if argv:
                info["argv"] = argv
            pathbuf = ctypes.create_string_buffer(4096)
            if libc.proc_pidpath(pid, pathbuf, 4096) > 0:
                info["exe"] = pathbuf.value.decode("utf-8", "replace")
        except Exception:
            pass

    def poll_processes(self):
        now = time.time()
        # ---- 快路径：sysctl KERN_PROC_ALL 纯 pid/ppid 表（单次系统调用 ~3ms）----
        ppids = _kern_proc_ppids()
        if ppids is None:
            ppids = {p: d.get("ppid") for p, d in (self._full_procs or {}).items()}
        # ---- 低频全量刷新（每 10s）：种子重发现（exe/argv 前缀）+ 全量 argv 兜底 ----
        if now - self._last_ps >= 10 or not self._full_procs:
            self._last_ps = now
            full, _ = libproc_scan()
            psprocs, _ = ps_snapshot()
            for pid, d in full.items():
                d["argv"] = (psprocs.get(pid) or {}).get("argv")
            self._full_procs = full
        # ---- 树构建（纯 ppid 图）----
        seeds = {p for p in self._seed_pids(self._full_procs) if p in ppids}
        tree = set(seeds)
        children = {}
        for pid, pp in ppids.items():
            if pp is not None:
                children.setdefault(pp, []).append(pid)
        queue = list(seeds)
        while queue:
            cur = queue.pop()
            for c in children.get(cur, []):
                if c not in tree:
                    tree.add(c)
                    queue.append(c)
        # 工作区前缀孤儿兜底（低频全量扫描的 argv/exe）
        for pid, d in self._full_procs.items():
            if pid in tree or pid not in ppids:
                continue
            a = (d.get("argv") or "") or (d.get("exe") or "")
            if a.startswith(self.workspace + "/"):
                tree.add(pid)
        # 孤儿续跟踪：中间父进程退出后孙进程 reparent 到 launchd(1)，ppid 链
        # 断裂，但已见 pid 仍在跟踪范围内（agent 长命令不因父进程退出而丢拍）
        tree |= {p for p in self.seen_pids if p in ppids}
        self.current_tree = tree
        # ---- 树成员信息视图（exe/argv 低频缓存 + 新 pid 即时补抓）----
        procs = {}
        for pid in tree:
            fp = self._full_procs.get(pid) or {}
            procs[pid] = {"ppid": ppids.get(pid), "exe": fp.get("exe") or "",
                          "argv": fp.get("argv")}
        # ---- 新 pid 先挂 pending：fork→exec 窗口里子进程还带着父进程镜像
        #      （exe/argv 均为父进程的），下一轮确认时才是真实命令行 ----
        libc = None
        pathbuf = None
        for pid in tree:
            if pid in self.seen_pids or pid in self._pending:
                continue
            if libc is None:
                libc = _libc()
                pathbuf = ctypes.create_string_buffer(4096)
            exe = ""
            if libc.proc_pidpath(pid, pathbuf, 4096) > 0:
                exe = pathbuf.value.decode("utf-8", "replace")
            argv = _proc_argv(libc, pid) or procs[pid].get("argv") or ""
            self._pending[pid] = {"exe": exe, "argv": argv, "ts": now,
                                  "ppid": ppids.get(pid)}
            # 30ms 后重取一次 exe/argv：跨过 fork→exec 窗口（~5-20ms），
            # 短命进程（活不过一轮轮询）也能锁到 exec 后的真实命令行
            threading.Timer(0.03, self._refetch_pending, args=(pid,)).start()
        # ---- 首轮：当前树作为基线静默入账（吸收 pending）----
        if not self.seen_pids and tree:
            for pid in sorted(tree):
                info = self._pending.pop(pid, None)
                if info:
                    procs[pid]["exe"] = info["exe"] or procs[pid].get("exe") or ""
                    if info["argv"]:
                        procs[pid]["argv"] = info["argv"]
                self.seen_pids[pid] = procs[pid].get("argv") or procs[pid].get("exe") or ""
                self.spawn_ts[pid] = now
                self.proc_span(pid, self.seen_pids[pid])
            self._print(f"  进程基线：{len(tree)} 个（模式 kernproc）")
            return
        # ---- pending 确认：仍在树 → 取真实 argv 发 spawn；
        #      已消失（短命）→ 用首拍信息补发 spawn + 立即 exit ----
        for pid in list(self._pending):
            if pid in self.seen_pids:
                self._pending.pop(pid)
                continue
            info = self._pending.pop(pid)
            if pid in tree:
                if libc is None:
                    libc = _libc()
                argv = _proc_argv(libc, pid) or info["argv"]
                exe = procs.get(pid, {}).get("exe") or info["exe"]
                self._emit_spawn(pid, argv, exe, ppids.get(pid), info["ts"],
                                 "kernproc")
            else:
                # 短命进程：死在两轮轮询之间。首拍/30ms 重取的信息可能是
                # fork→exec 窗口的父进程镜像（argv/exe == 父进程的）——
                # 标记为 ghost，不误报成"执行了父进程的命令"
                parent_argv = self.seen_pids.get(info["ppid"]) or ""
                ghost = (info["argv"] and parent_argv and
                         info["argv"] == parent_argv)
                self._emit_spawn(pid,
                                 "" if ghost else info["argv"],
                                 "" if ghost else info["exe"], info["ppid"],
                                 info["ts"],
                                 "kernproc+ephemeral+ghost" if ghost
                                 else "kernproc+ephemeral")
                self._emit_exit(pid, info["argv"] or info["exe"])
        # ---- 退出 ----
        for pid in list(self.seen_pids):
            if pid not in tree:
                argv = self.seen_pids.pop(pid)
                self._emit_exit(pid, argv)

    def poll_network(self):
        # 关键修复：按"当轮实时树 ∪ 已见 pid"归属，短命孙进程连接不再漏
        allowed = self.current_tree | set(self.seen_pids)
        for pid, local, ph, pp, kind in lsof_snapshot():
            if pid not in allowed:
                continue
            key = (pid, local, ph, pp, kind)
            if key in self.seen_conns:
                continue
            self.seen_conns.add(key)
            span = self.pid_spans.get(pid) or self.proc_span(
                pid, self.seen_pids.get(pid, ""))
            if kind == "listen":
                self.emit(span, self.session_span, "net.listen",
                          {"type": "process", "pid": pid},
                          {"name": "listen",
                           "arguments_redacted": {"local": local},
                           "result_summary": {}})
                self._print(f"🔌 net.listen    pid{pid} {local}")
                continue
            pk = peer_kind(ph)
            note = "本地回环(代理/内部服务)" if pk == "local" else "⚠️ 直连公网(绕过代理)"
            self.emit(span, self.session_span, "net.connect",
                      {"type": "process", "pid": pid},
                      {"name": "connect",
                       "arguments_redacted": {"local": local,
                                              "peer": f"{ph}:{pp}",
                                              "peer_kind": pk},
                       "result_summary": {"note": note}})
            self._print(f"🌐 net.connect   pid{pid} {local} → {ph}:{pp}  [{note}]")

    def poll_files(self):
        if self.capture_reads:
            self._poll_file_reads()
        cur = scan_files(self.workspace, DEFAULT_EXCLUDE)
        if self.file_baseline is None:
            self.file_baseline = cur
            if self.resumed:
                # 续写重启：diff 出停止期间的文件变化并补记
                pass  # 基线即当前态，变化从现在起记录
            return
        base = self.file_baseline
        for rel, st in cur.items():
            if rel not in base:
                etype, icon, verb = "fs.create", "🆕", "创建"
            elif base[rel] != st:
                etype, icon, verb = "fs.write", "✍️", "修改"
            else:
                continue
            self.emit(self.ws_span, self.session_span, etype,
                      {"type": "workspace", "path": rel},
                      {"name": verb,
                       "arguments_redacted": {"path": rel},
                       "result_summary": {"size": st[1]}})
            self._print(f"{icon} {etype:<11} {rel}  ({st[1]}B)")
        for rel in base:
            if rel not in cur:
                self.emit(self.ws_span, self.session_span, "fs.delete",
                          {"type": "workspace", "path": rel},
                          {"name": "删除",
                           "arguments_redacted": {"path": rel},
                           "result_summary": {}})
                self._print(f"🗑️ fs.delete     {rel}")
        self.file_baseline = cur

    # ---------------------------------------------------------------- 文件读取捕获
    SENSITIVE_READ_PATTERNS = [
        ".ssh/", ".gnupg/", ".aws/", ".gitconfig", ".git-credentials",
        ".netrc", "Keychains", ".npmrc", ".pypirc", ".docker/config.json",
        ".kube/config", ".env", ".bash_history", ".zsh_history",
        ".bashrc", ".zshrc", ".profile", ".zprofile", ".bash_profile",
        ".claude.json", ".git-credentials", ".dockerignore", ".p10k.zsh",
    ]

    def _is_sensitive_read(self, path):
        """判定一个已打开文件路径是否值得上报为 fs.read。

        只报已知敏感模式，避免把 .DS_Store 等噪音全报上来。
        """
        p = path.lower()
        for pat in self.SENSITIVE_READ_PATTERNS:
            if pat.lower() in p:
                return True
        return False

    def _poll_file_reads(self):
        """通过 lsof 文件描述符扫描捕获进程打开的文件（重点：敏感读取）。"""
        for pid in self.current_tree:
            try:
                r = subprocess.run(["lsof", "-a", "-p", str(pid), "-F", "fn"],
                                   capture_output=True, text=True, timeout=5)
                if r.returncode != 0:
                    continue
                cur_fd = None
                for line in r.stdout.splitlines():
                    if line.startswith("f"):
                        cur_fd = line[1:]
                    elif line.startswith("n") and cur_fd:
                        path = line[1:]
                        key = (pid, path)
                        if key in self.seen_fds:
                            cur_fd = None
                            continue
                        # lsof FD 列：cwd/txt/rtd/mem 等表示打开；'r' 读模式，'u' 读写
                        # 这里只要有路径即认为已打开，再做敏感过滤避免噪音
                        if self._is_sensitive_read(path):
                            self.seen_fds.add(key)
                            span = self.pid_spans.get(pid) or self.proc_span(
                                pid, self.seen_pids.get(pid, ""))
                            self.emit(span, self.session_span, "fs.read",
                                      {"type": "process", "pid": pid},
                                      {"name": "read",
                                       "arguments_redacted": {
                                           "path": path,
                                           "fd": cur_fd,
                                           "sensitive": True},
                                       "result_summary": {}})
                            self._print(f"📖 fs.read       pid{pid} {path}")
                        cur_fd = None
            except Exception:
                pass

    def heartbeat(self):
        self.emit(self.session_span, None, "session.heartbeat",
                  {"type": "agent", "name": self.agent_name},
                  {"name": "heartbeat",
                   "arguments_redacted": {},
                   "result_summary": {
                       "uptime_sec": round(time.time() - self.start_time, 0),
                       "events": self.writer.count,
                       "realtime_alerts": self.alerts.count,
                       "tree_size": len(self.current_tree)}})

    def _print(self, msg):
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

    # ---- 主循环 ----
    def run(self, duration):
        procs, mode = ps_snapshot()
        seeds = self._seed_pids(procs)
        begin_type = "trace.resume" if self.resumed else "trace.begin"
        self.emit(self.session_span, None, begin_type,
                  {"type": "agent", "name": self.agent_name,
                   "mode": "passive-observer-v2"},
                  {"name": "session",
                   "arguments_redacted": {
                       "workspace_root": self.workspace,
                       "net_allowlist": ["127.0.0.1", "::1", "localhost"],
                       "seed_processes_at_start": len(seeds),
                       "proc_scan_mode": mode,
                       "note": "被动观察 v2：全进程树追踪（含孙进程）+ "
                               "实时告警 + 断点续写"},
                   "result_summary": {}})
        self._print(f"◆ {begin_type}  workspace={self.workspace}")
        self._print(f"  种子进程: {len(seeds)} 个，扫描模式: {mode}")
        self._print(f"  优雅停止: touch {self.stop_file} 或 kill -TERM；"
                    f"实时告警实时落盘")

        signal.signal(signal.SIGTERM, self._request_stop)

        # v3：三类轮询独立线程——串行循环时 lsof（150-300ms/次）会把进程
        # 高频轮询饿死（实测 0.1s 配置实际 ~2s 一拍，短命子进程几乎全漏）。
        def poll_loop(fn, interval, name):
            t = time.time()
            while not self._stop_evt.is_set():
                if time.time() - t >= interval:
                    try:
                        fn()
                    except Exception as ex:            # 单类轮询异常不拖垮整个观察器
                        self._print(f"  ⚠️ {name} 轮询异常: {ex}")
                    t = time.time()
                self._stop_evt.wait(0.02)

        threads = [
            threading.Thread(target=poll_loop,
                             args=(self.poll_processes, self.poll_proc, "proc"),
                             daemon=True, name="poll-proc"),
            threading.Thread(target=poll_loop,
                             args=(self.poll_network, self.poll_net, "net"),
                             daemon=True, name="poll-net"),
            threading.Thread(target=poll_loop,
                             args=(self.poll_files, self.poll_file, "file"),
                             daemon=True, name="poll-file"),
        ]
        for th in threads:
            th.start()
        t_hb = time.time()
        try:
            while not self._stop_requested:
                now = time.time()
                if now - t_hb >= 30:
                    self.heartbeat(); t_hb = now
                if os.path.exists(self.stop_file):
                    try:
                        os.remove(self.stop_file)
                    except OSError:
                        pass
                    self._print("  收到 STOP 哨兵，优雅停止")
                    break
                if duration and now - self.start_time >= duration:
                    break
                time.sleep(0.05)
        except KeyboardInterrupt:
            pass
        finally:
            self._stop_evt.set()
            for th in threads:
                th.join(timeout=3)

        self.emit(self.session_span, None, "trace.end",
                  {"type": "agent", "name": self.agent_name},
                  {"name": "session_end",
                   "arguments_redacted": {},
                   "result_summary": {"duration_sec": round(time.time() - self.start_time, 1),
                                      "events": self.writer.count,
                                      "realtime_alerts": self.alerts.count,
                                      "by_type": self.counts}})
        self.alerts.close()
        return self.finish()

    def _request_stop(self, signum, frame):
        self._stop_requested = True

    def finish(self):
        events_path = self.writer.path
        out_dir = os.path.join(ROOT, "output", self.trace_id)
        os.makedirs(out_dir, exist_ok=True)
        self._print(f"\n◆ trace.end      共 {self.writer.count} 条事件 → {events_path}")
        import shutil
        processed = os.path.join(out_dir, "processed.ndjson")
        shutil.copyfile(events_path, processed)
        # 实时告警也归档一份
        if self.alerts.count:
            shutil.copyfile(self.alerts.path,
                            os.path.join(out_dir, "realtime_alerts.ndjson"))
        try:
            subprocess.run([sys.executable,
                            os.path.join(ROOT, "correlator", "correlate.py"),
                            "--input", processed, "--out", out_dir],
                           check=True)
        except Exception as e:
            print(f"correlate 失败: {e}", file=sys.stderr)
        print(f"\n报告目录: {out_dir}")
        print(f"  timeline.md / alerts.json / trace_summary.json / evidence_pkg/")
        return out_dir


def main():
    ap = argparse.ArgumentParser(
        description="被动观察器 v2（全进程树 + 实时告警 + 断点续写）")
    ap.add_argument("--workspace", required=True, help="Agent 打开的项目路径")
    ap.add_argument("--duration", type=int, default=0,
                    help="监视秒数（0 = 一直运行到 STOP/TERM）")
    ap.add_argument("--events-dir", default=os.path.join(ROOT, "events"))
    ap.add_argument("--poll-proc", type=float, default=0.1,
                    help="进程轮询间隔秒（v3 默认 0.1：sysctl 快路径单次 ~3ms）")
    ap.add_argument("--poll-net", type=float, default=0.3,
                    help="网络轮询间隔秒（v2 默认 0.3）")
    ap.add_argument("--poll-file", type=float, default=3.0)
    ap.add_argument("--seed-pid", type=int, default=None,
                    help="种子进程 pid（监视任意 Agent，不必是 Kiro）")
    ap.add_argument("--seed-pattern", default=KIRO_APP_PREFIX,
                    help="种子进程 argv 前缀（默认 /Applications/Kiro.app）")
    ap.add_argument("--agent-name", default="Kiro")
    ap.add_argument("--resume", default=None,
                    help="续写的 trace_id：沿用哈希链继续记录同一会话")
    ap.add_argument("--collector", default=None,
                    help="实时面板收集器 URL，例如 http://127.0.0.1:8787/ingest")
    ap.add_argument("--capture-reads", action="store_true",
                    help="启用 lsof 文件描述符扫描，捕获敏感文件读取（fs.read）")
    args = ap.parse_args()

    if not os.path.isdir(args.workspace):
        print(f"workspace 不存在: {args.workspace}", file=sys.stderr)
        sys.exit(1)

    # 单实例锁：曾出现两个 observer 并发 resume 同一 trace_id，平行演化出
    # 两条相同的哈希链（所有事件双份、完整性校验失败）。PID 检测锁根治；
    # 撞锁时 exit 42，让守护它的 watchdog 也一并退出（旧实例继续服务）。
    os.makedirs(args.events_dir, exist_ok=True)
    lock = os.path.join(args.events_dir, ".observer.lock")
    if os.path.exists(lock):
        try:
            old_pid = int(open(lock, encoding="utf-8").read().strip())
            os.kill(old_pid, 0)
            print(f"[observer] 已有实例在运行 (pid {old_pid})，本实例退出。",
                  file=sys.stderr)
            sys.exit(GRACEFUL_EXIT_CODE)
        except (ValueError, ProcessLookupError, PermissionError):
            pass  # 陈旧锁（持有者已死），接管
    with open(lock, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))

    obs = KiroObserver(args.workspace, args.events_dir,
                       args.poll_proc, args.poll_net, args.poll_file,
                       seed_pid=args.seed_pid,
                       seed_pattern=args.seed_pattern,
                       resume=args.resume, agent_name=args.agent_name,
                       collector_url=args.collector,
                       capture_reads=args.capture_reads)
    obs.run(args.duration or None)
    sys.exit(GRACEFUL_EXIT_CODE if obs._stop_requested else 0)


if __name__ == "__main__":
    main()

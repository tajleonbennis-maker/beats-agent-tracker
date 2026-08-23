"""系统事实链传感器：进程树扫描 + TCP 连接监控（macOS/Linux 通用、纯 stdlib）。

对应规范第 2/5 节：在工具执行期间采集真实发生的子进程与网络连接，
通过 PID + 时间窗 + 环境变量注入（AGENT_TRACE_ID / AGENT_SPAN_ID）
把系统事件挂到对应工具调用 Span 下。
"""
import os
import re
import subprocess
import sys
import threading
import time


def _run(cmd: list) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return out.stdout or ""
    except Exception:
        return ""


def descendants(pid: int) -> set:
    """递归收集 pid 的全部后代（macOS 用 pgrep -P，Linux 同样可用）。"""
    result, frontier = set(), [pid]
    while frontier:
        p = frontier.pop()
        result.add(p)
        out = _run(["pgrep", "-P", str(p)])
        for line in out.split():
            try:
                child = int(line)
            except ValueError:
                continue
            if child not in result:
                frontier.append(child)
    return result


def parse_conn_name(name: str):
    """解析 lsof -F 的 n 字段。

    -F 模式不带状态后缀：`127.0.0.1:65049->127.0.0.1:9997`；
    人类可读模式带状态：`...->... (ESTABLISHED)`。两种都兼容。
    返回 (local, peer_host, peer_port, state)；无 peer 的视为 LISTEN。
    """
    if "->" not in name:
        return name, None, None, "LISTEN"
    local, peer = name.split("->", 1)
    state = "ESTABLISHED"
    m = re.search(r"\s*\(([A-Z]+)\)$", peer)
    if m:
        state = m.group(1)
        peer = peer[:m.start()]
    peer = peer.strip()
    host, _, port = peer.rpartition(":")
    return local, host.strip("[]"), port, state


# ---------- 进程详情采集（无 ps 依赖：macOS libproc / Linux /proc） ----------
_libc = None


def _get_libc():
    global _libc
    if _libc is None:
        import ctypes.util
        _libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                            use_errno=True)
    return _libc


def _proc_info_darwin(pid: int):
    """macOS：proc_pidpath 取 exe，proc_pidinfo(PROC_PIDTBSDINFO) 取 ppid，
    sysctl kern.procargs2 取完整 argv。均为系统调用，无需 root，也不依赖 ps。"""
    import ctypes
    libc = _get_libc()
    info = {"pid": pid, "ppid": None, "exe": None, "argv": None}
    # exe
    buf = ctypes.create_string_buffer(4096)
    if libc.proc_pidpath(pid, buf, 4096) > 0:
        info["exe"] = buf.value.decode("utf-8", "replace")
    # ppid（buffer 需 ≥ sizeof(struct proc_bsdinfo)=136，ppid 在偏移 16）
    binfo = ctypes.create_string_buffer(1024)
    rc = libc.proc_pidinfo(pid, 3, 0, binfo, 1024)  # 3 = PROC_PIDTBSDINFO
    if rc >= 20:
        import struct
        info["ppid"] = struct.unpack_from("5I", binfo.raw, 0)[4]
    # argv（mib = {CTL_KERN=1, KERN_PROCARGS2=49, pid}）
    # 缓冲区布局：[int32 argc][exec_path][argv[0]]..[argv[argc-1]][环境变量...]
    # 必须按 argc 截断，否则子进程的环境变量会混入 argv（可能含密钥）。
    mib = (ctypes.c_int * 3)(1, 49, pid)
    size = ctypes.c_size_t(65536)
    abuf = ctypes.create_string_buffer(65536)
    if libc.sysctl(mib, 3, abuf, ctypes.byref(size), None, 0) == 0:
        raw = abuf.raw[4:size.value]
        argc = int.from_bytes(abuf.raw[:4], "little")
        parts = [p.decode("utf-8", "replace") for p in raw.split(b"\x00") if p]
        if 0 < argc <= len(parts):
            parts = parts[1:1 + argc]  # 跳过 exec_path，只取 argv
        info["argv"] = " ".join(parts)
    if info["ppid"] is None and info["argv"] is None:
        return None
    return info


def _proc_info_linux(pid: int):
    info = {"pid": pid, "ppid": None, "exe": None, "argv": None}
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            # 字段4是 ppid；comm 可能含空格，按 ") " 之后解析
            data = f.read().decode("utf-8", "replace")
            info["ppid"] = int(data.rpartition(")")[2].split()[1])
    except (OSError, ValueError, IndexError):
        pass
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            parts = [p.decode("utf-8", "replace") for p in f.read().split(b"\x00") if p]
            info["argv"] = " ".join(parts)
            if parts:
                info["exe"] = parts[0]
    except OSError:
        pass
    if info["ppid"] is None and info["argv"] is None:
        return None
    return info


def proc_info(pid: int):
    """取单个进程的 {pid, ppid, exe, argv}；进程已退出返回 None。"""
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return None
    if sys.platform == "darwin":
        return _proc_info_darwin(pid)
    return _proc_info_linux(pid)


class ProcessMonitor:
    """轮询进程树，捕获新增进程的详情（pid/ppid/argv/exe）。

    与 NetMonitor 同一模式：轮询期间发现的新 pid 只上报一次。
    补齐规范第 2 节"系统事实链"的进程维度：不仅知道"跑了命令"，
    还要知道进程树里每个进程的真实身份（可执行路径 + 完整 argv）。
    """

    def __init__(self, poll_interval: float = 0.15):
        self.poll_interval = poll_interval
        self._seen = set()
        self.processes = []  # [{pid, ppid, exe, argv}]
        self._stop = threading.Event()
        self._thread = None

    def snapshot(self, pids: set):
        for pid in pids:
            if pid in self._seen:
                continue
            info = proc_info(pid)
            if info is None:
                continue
            self._seen.add(pid)
            info["argv"] = _sanitize_argv(info.get("argv") or "")
            self.processes.append(info)

    def start(self, root_pid: int):
        def loop():
            while not self._stop.is_set():
                self.snapshot(descendants(root_pid))
                time.sleep(self.poll_interval)
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop_and_collect(self, root_pid: int) -> list:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self.snapshot(descendants(root_pid))  # 收尾补采一次
        return self.processes


_ARG_SECRET_RE = re.compile(
    r"(?i)((?:--?[A-Za-z_-]*(?:token|secret|password|passwd|api[_-]?key|key))\s*[=:]\s*)[^\s\"']+"
    r"|((?i:bearer)\s+)[A-Za-z0-9._\-]+")


def _sanitize_argv(argv: str) -> str:
    """argv 层脱敏：敏感键值对与 Bearer token 的值打码（与 trace.py 策略一致）。"""
    if not argv:
        return argv
    return _ARG_SECRET_RE.sub(
        lambda m: (m.group(1) or m.group(2)) + "[REDACTED]", argv)


class NetMonitor:
    """轮询 lsof，捕获进程树内新增的 TCP 连接。

    lsof 在 macOS 上无需 root 即可看到本用户进程的连接。
    每条连接只上报一次（四元组+状态去重）。
    """

    def __init__(self, poll_interval: float = 0.25):
        self.poll_interval = poll_interval
        self._seen = set()
        self.connections = []  # [{local, peer_host, peer_port, state, pid}]
        self._stop = threading.Event()
        self._thread = None

    @staticmethod
    def _lsof_entries() -> list:
        out = _run(["lsof", "-iTCP", "-n", "-P", "-F", "pn"])
        entries, cur = [], None
        for line in out.splitlines():
            if line.startswith("p"):
                if cur:
                    entries.append(cur)
                cur = {"pid": int(line[1:] or 0)}
            elif line.startswith("n") and cur is not None:
                cur["name"] = line[1:]
        if cur:
            entries.append(cur)
        return entries

    def snapshot(self, pids: set):
        for ent in self._lsof_entries():
            pid = ent.get("pid")
            if pid not in pids:
                continue
            local, peer_host, peer_port, state = parse_conn_name(ent.get("name", ""))
            dedup = (pid, local, peer_host, peer_port, state)
            if dedup in self._seen:
                continue
            self._seen.add(dedup)
            self.connections.append({
                "pid": pid, "local": local,
                "peer_host": peer_host, "peer_port": peer_port,
                "state": state,
            })

    def start(self, root_pid: int):
        def loop():
            while not self._stop.is_set():
                self.snapshot(descendants(root_pid))
                time.sleep(self.poll_interval)
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop_and_collect(self, root_pid: int) -> list:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self.snapshot(descendants(root_pid))  # 收尾补采一次
        return self.connections


def inject_trace_env(trace_id: str, span_id: str) -> dict:
    """工具网关把关联标识注入子进程环境变量（规范 5.1 采集顺序第 2 步）。"""
    env = dict(os.environ)
    env["AGENT_TRACE_ID"] = trace_id
    env["AGENT_SPAN_ID"] = span_id
    return env

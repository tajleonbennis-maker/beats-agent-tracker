"""受控工具网关：包装 read_file / write_file / run_command 三个工具。

职责（规范第 5 节 Controlled Tool Gateway）：
- 每次调用生成 tool.call Span；
- 文件操作发 fs.read / fs.write 子事件（带文件哈希）；
- Shell 包装器注入 AGENT_TRACE_ID/AGENT_SPAN_ID，采集真实进程树与 TCP 连接
  （process.exec / net.connect 子事件）；
- 策略判断（allow/ask/deny）与审批事件；
- 输出在写入事件前脱敏（见 runtime/trace.py）。
"""
import hashlib
import os
import subprocess

from trace import new_id, redact, truncate
from sensors import NetMonitor, ProcessMonitor, inject_trace_env

MAX_OUTPUT = 2000  # 事件中保留的 stdout/stderr 摘要长度


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


class PolicyEngine:
    """极简策略引擎：相对路径按工作区解析；工作区内读写放行；
    出网命令需审批；工作区外写入走审批。"""

    def __init__(self, workspace_root: str):
        self.workspace_root = os.path.realpath(workspace_root)

    def resolve(self, path: str) -> str:
        p = os.path.expanduser(path)
        if not os.path.isabs(p):
            p = os.path.join(self.workspace_root, p)
        return os.path.realpath(p)

    def _inside(self, path: str) -> bool:
        return self.resolve(path).startswith(self.workspace_root + os.sep)

    def check(self, event_type: str, action: dict) -> dict:
        if event_type == "fs.read":
            return {"decision": "allow", "rule_id": "workspace-read", "approval_id": None}
        if event_type == "fs.write":
            if self._inside(action.get("path", "")):
                return {"decision": "allow", "rule_id": "workspace-write", "approval_id": None}
            return {"decision": "ask", "rule_id": "outside-write-approval", "approval_id": None}
        if event_type == "process.exec":
            return {"decision": "allow", "rule_id": "workspace-shell", "approval_id": None}
        return {"decision": "allow", "rule_id": "default", "approval_id": None}


class ToolGateway:
    def __init__(self, writer, actor: dict, workspace_root: str,
                 auto_approve: bool = True):
        self.writer = writer
        self.actor = actor
        self.policy = PolicyEngine(workspace_root)
        self.auto_approve = auto_approve
        self.approvals = 0

    # ---------- 基础事件 ----------
    def _emit(self, source, event_type, span_id, parent_span_id, action,
              policy=None, evidence_extra=None):
        ev = self.writer.build(
            source=source, event_type=event_type, span_id=span_id,
            parent_span_id=parent_span_id, actor=self.actor,
            action=redact(action), policy=policy,
            evidence_extra=evidence_extra)
        return self.writer.emit(ev)

    def _approval(self, parent_span_id, action_name, decision_reason):
        """模拟审批流：策略判 ask 时弹出审批事件（演示中自动批准/拒绝）。"""
        self.approvals += 1
        approval_id = f"appr_{self.approvals:04d}"
        asked = {"decision": "ask", "rule_id": "high-risk-approval", "approval_id": None}
        self._emit("agent_runtime", "approval", new_id("span"),
                   parent_span_id,
                   {"name": action_name, "arguments_redacted": {"reason": decision_reason}},
                   policy=asked)
        approved = self.auto_approve
        self._emit("agent_runtime", "approval", new_id("span"),
                   parent_span_id,
                   {"name": action_name,
                    "result_summary": {"outcome": "approved" if approved else "denied"}},
                   policy={"decision": "allow" if approved else "deny",
                           "rule_id": "high-risk-approval",
                           "approval_id": approval_id})
        return approved

    # ---------- 工具入口 ----------
    def call(self, tool: str, args: dict, parent_span_id, model_turn_note: str = ""):
        span_id = new_id("span")
        self._emit("tool_proxy", "tool.call", span_id, parent_span_id,
                   {"name": tool, "arguments_redacted": args})
        dispatch = {
            "read_file": self._read_file,
            "write_file": self._write_file,
            "run_command": self._run_command,
        }
        if tool not in dispatch:
            self._emit("tool_proxy", "tool.call", new_id("span"), span_id,
                       {"name": tool,
                        "result_summary": {"error": f"unknown tool {tool}"},
                        "turn_context": model_turn_note})
            return None
        result = dispatch[tool](args, span_id)
        # 补充 tool.call 的结果事件（tool.result），便于时间轴展示
        self._emit("tool_proxy", "tool.result", new_id("span"), span_id,
                   {"name": tool, "result_summary": result,
                    "turn_context": model_turn_note})
        return result

    # ---------- read_file ----------
    def _read_file(self, args, span_id):
        path = self.policy.resolve(args["path"])
        pol = self.policy.check("fs.read", {"path": path})
        content, err = "", None
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as e:
            err = str(e)
        fh = sha256_file(path)
        self._emit("tool_proxy", "fs.read", new_id("span"), span_id,
                   {"name": "read_file",
                    "arguments_redacted": {"path": path},
                    "result_summary": {"bytes": len(content.encode(errors="replace")),
                                       "error": err}},
                   policy=pol,
                   evidence_extra={"artifact_hashes": [{"path": path, "sha256": fh}]})
        return {"bytes": len(content.encode(errors="replace")), "error": err,
                "content_preview": truncate(redact(content), 300)}

    # ---------- write_file ----------
    def _write_file(self, args, span_id):
        path = self.policy.resolve(args["path"])
        content = args.get("content", "")
        pol = self.policy.check("fs.write", {"path": path})
        if pol["decision"] == "ask":
            if not self._approval(span_id, f"write_file({path})",
                                  "写入路径位于工作区之外"):
                self._emit("tool_proxy", "fs.write", new_id("span"), span_id,
                           {"name": "write_file",
                            "arguments_redacted": {"path": path, "bytes": len(content)},
                            "result_summary": {"error": "denied by approval"}},
                           policy={"decision": "deny", **pol})
                return {"error": "denied by approval"}
            pol = {"decision": "allow", **pol, "approval_id": f"appr_{self.approvals:04d}"}
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        fh = sha256_file(path)
        self._emit("tool_proxy", "fs.write", new_id("span"), span_id,
                   {"name": "write_file",
                    "arguments_redacted": {"path": path, "bytes": len(content)},
                    "result_summary": {"bytes_written": len(content)}},
                   policy=pol,
                   evidence_extra={"artifact_hashes": [{"path": path, "sha256": fh}]})
        return {"bytes_written": len(content)}

    # ---------- run_command ----------
    def _run_command(self, args, span_id):
        cmd = args["command"]
        pol = self.policy.check("process.exec", {"command": cmd})
        if _needs_egress_approval(cmd) and not self._approval(
                span_id, f"run_command({truncate(cmd, 60)})",
                "命令包含网络出网行为（curl/wget）"):
            pol = {"decision": "deny", **pol}
        proc_span = new_id("span")
        env = inject_trace_env(self.writer.trace_id, span_id)
        monitor = NetMonitor(poll_interval=0.15)
        proc_monitor = ProcessMonitor(poll_interval=0.15)
        started = False
        proc = None
        result = {}
        if pol["decision"] != "deny":
            proc = subprocess.Popen(["/bin/zsh", "-c", cmd], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True)
            monitor.start(proc.pid)
            proc_monitor.start(proc.pid)
            started = True
            out, errout = proc.communicate()
            conns = monitor.stop_and_collect(proc.pid)
            procs = proc_monitor.stop_and_collect(proc.pid)
            result = {"exit_code": proc.returncode}
        else:
            out, errout, conns, procs = "", "", [], []
            result = {"exit_code": None, "error": "denied by approval"}
        # process.exec 事件（含脱敏后的输出摘要）
        self._emit("tool_proxy", "process.exec", proc_span, span_id,
                   {"name": "run_command",
                    "arguments_redacted": {"command": cmd,
                                           "env_injected": ["AGENT_TRACE_ID",
                                                            "AGENT_SPAN_ID"]},
                    "result_summary": {
                        "exit_code": result.get("exit_code"),
                        "stdout": truncate(redact(out), MAX_OUTPUT),
                        "stderr": truncate(redact(errout), MAX_OUTPUT),
                        "processes": len(procs) if started else 0,
                    }},
                   policy=pol,
                   evidence_extra={
                       "artifact_hashes": [],
                       "raw_event_ref": None})
        # process.spawn 子事件：进程树里每个进程的真实身份（系统事实链·进程维度）
        for p in procs:
            self._emit("system", "process.spawn", new_id("span"), span_id,
                       {"name": "process",
                        "arguments_redacted": {
                            "pid": p["pid"], "ppid": p["ppid"],
                            "exe": p["exe"],
                            "argv": truncate(p.get("argv", ""), 500)},
                        "result_summary": {"observed_by": "ps_sampler"}},
                       policy={"decision": pol["decision"],
                               "rule_id": "process-observed",
                               "approval_id": pol.get("approval_id")})
        # net.connect 子事件：系统事实链
        for c in conns:
            self._emit("network", "net.connect", new_id("span"), span_id,
                       {"name": "tcp",
                        "arguments_redacted": {
                            "local": c["local"],
                            "peer": f"{c['peer_host']}:{c['peer_port']}" if c["peer_host"] else None,
                            "state": c["state"],
                            "pid": c["pid"]},
                        "result_summary": {"state": c["state"]}},
                       policy={"decision": pol["decision"], "rule_id": "egress-observed",
                               "approval_id": pol.get("approval_id")})
        result.setdefault("exit_code", None)
        result["stdout_preview"] = truncate(redact(out), 300)
        result["stderr_preview"] = truncate(redact(errout), 300)
        return result


def descendants_of(proc):
    if proc is None:
        return set()
    from sensors import descendants
    try:
        return descendants(proc.pid)
    except Exception:
        return set()


_EGRESS_RE = None


def _needs_egress_approval(cmd: str) -> bool:
    import re
    global _EGRESS_RE
    if _EGRESS_RE is None:
        _EGRESS_RE = re.compile(r"(?i)\b(curl|wget|nc|ncat|ssh|scp|rsync|git\s+(push|clone|fetch))\b")
    return bool(_EGRESS_RE.search(cmd))

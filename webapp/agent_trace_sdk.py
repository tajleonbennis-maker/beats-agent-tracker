#!/usr/bin/env python3
"""agent_trace_sdk.py — Web 应用声明式执行链上报 SDK（零依赖）。

给"部署在服务器上、内置大模型调用"的 Web 应用做 Agent 执行链跟踪：
把用户对话轮次、LLM 调用、工具调用按 schema 0.1 事件上报到 collector，
与 eBPF / MITM 采集的系统事实（同 trace_id）汇合成完整执行链。

设计要点：
  - 每个用户会话一条 trace（web_<session_id>），多租户可分开取证
  - 自带哈希链（与 runtime/trace.py 算法一致），collect_server 可直接链校验
  - 上报前对参数做脱敏（密钥/密码替换为 [REDACTED]），只传 redacted 版本
  - 纯标准库，任何 Python 3.8+ 环境可用；失败静默重试，不影响业务主流程

用法见 webapp/README.md。
"""
import hashlib
import json
import re
import secrets
import threading
import time
import urllib.request

SCHEMA_VERSION = "0.1"

HASHED_FIELDS = [
    "schema_version", "trace_id", "span_id", "parent_span_id", "timestamp",
    "source", "event_type", "actor", "action", "policy",
]

# 脱敏：上报参数里出现这些模式时替换掉（R1 检测看的是路径级敏感信息，
# 值本身的明文永远不应该出应用）
REDACT_PATTERNS = [
    (re.compile(r"(?i)(sk-\w{8})\w+"), r"\1…[REDACTED]"),
    (re.compile(r"(?i)(api[_-]?key|apikey|password|passwd|secret|token)"
                r"\s*([:=]\s*)(['\"]?)\S+"), r"\1\2\3[REDACTED]"),
    (re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?"
                r"(-----END [A-Z ]*PRIVATE KEY-----)"), r"\1[REDACTED]\2"),
]


def redact(obj):
    """递归脱敏 dict/list/str。"""
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, str):
        for pat, rep in REDACT_PATTERNS:
            obj = pat.sub(rep, obj)
        return obj
    return obj


def _strip_nulls(obj):
    if isinstance(obj, dict):
        return {k: _strip_nulls(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_nulls(x) for x in obj if x is not None]
    return obj


def canonical_core(event):
    """与 runtime/trace.py 完全一致的规范化序列化（哈希链两端一致）。"""
    core = {k: event.get(k) for k in HASHED_FIELDS}
    core["evidence"] = {k: v for k, v in (event.get("evidence") or {}).items()
                        if k != "hash"}
    core = _strip_nulls(core)
    return json.dumps(core, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def chain_hash(prev_hash, event):
    return hashlib.sha256(
        (prev_hash + "|" + canonical_core(event)).encode()).hexdigest()


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


class SessionTrace:
    """一个用户会话的执行链。线程安全（Web 应用多请求并发埋点）。"""

    def __init__(self, sdk, session_id):
        self.sdk = sdk
        self.trace_id = f"web_{session_id}"
        self.session_span = f"span_{int(time.time() * 1000):012x}{secrets.token_hex(8)}"
        self._lock = threading.Lock()
        self._prev_hash = "GENESIS"
        self._pending = []
        self._started = False

    # ---------- 基础 ----------

    def _emit(self, event_type, actor, action, parent_span_id=None,
              policy=None):
        ev = {
            "schema_version": SCHEMA_VERSION,
            "trace_id": self.trace_id,
            "span_id": f"span_{int(time.time() * 1000):012x}{secrets.token_hex(8)}",
            "parent_span_id": parent_span_id or self.session_span,
            "timestamp": _now(),
            "source": self.sdk.source,
            "event_type": event_type,
            "actor": actor,
            "action": action,
            "policy": policy or {"decision": "observe",
                                 "reason": "webapp SDK 声明式上报"},
            "evidence": {"prev_hash": self._prev_hash,
                         "raw_event_ref": f"object://events/{self.trace_id}"},
        }
        with self._lock:
            ev["evidence"]["hash"] = chain_hash(self._prev_hash, ev)
            self._prev_hash = ev["evidence"]["hash"]
            self._pending.append(json.dumps(ev, ensure_ascii=False))
            if len(self._pending) >= self.sdk.flush_threshold:
                self._flush_locked()
        return ev

    def _flush_locked(self):
        if not self._pending:
            return
        body = "\n".join(self._pending).encode()
        req = urllib.request.Request(
            self.sdk.collector_url, data=body,
            headers={"Content-Type": "application/x-ndjson",
                     "X-Trace-Id": self.trace_id})
        try:
            urllib.request.urlopen(req, timeout=self.sdk.timeout)
            self._pending = []
        except Exception as exc:
            self.sdk._note_error(exc)   # 失败保留待重试，绝不阻塞业务

    def flush(self):
        """手动上报缓冲区（请求结束/中间件收尾时调用）。"""
        with self._lock:
            self._flush_locked()

    # ---------- 生命周期 ----------

    def begin(self):
        """会话开始（Boss 面板靠 trace.begin 识别 Agent 名）。"""
        self._started = True
        return self._emit(
            "trace.begin",
            actor={"type": "webapp", "agent": self.sdk.app_name,
                   "session": self.trace_id},
            action={"name": "session.begin",
                    "arguments_redacted": {"app": self.sdk.app_name},
                    "result_summary": {},
                    "summary": f"{self.sdk.app_name} 会话开始"})

    def end(self):
        ev = self._emit(
            "trace.end",
            actor={"type": "webapp", "agent": self.sdk.app_name},
            action={"name": "session.end",
                    "arguments_redacted": {},
                    "result_summary": {},
                    "summary": "会话结束"})
        self.flush()
        return ev

    # ---------- 对话层 ----------

    def user_message(self, text, parent_span_id=None):
        return self._emit(
            "conversation.user",
            actor={"type": "user"},
            action={"name": "message",
                    "arguments_redacted": {"text": redact(text)[:4000]},
                    "result_summary": {},
                    "summary": f"用户: {text[:80]}"},
            parent_span_id=parent_span_id)

    def assistant_message(self, text, parent_span_id=None):
        return self._emit(
            "conversation.assistant",
            actor={"type": "agent", "agent": self.sdk.app_name},
            action={"name": "message",
                    "arguments_redacted": {"text": redact(text)[:4000]},
                    "result_summary": {},
                    "summary": f"助手: {text[:80]}"},
            parent_span_id=parent_span_id)

    # ---------- 模型层 ----------

    def llm_request(self, model, prompt, parent_span_id=None):
        """prompt 支持 list（messages）或 str。触发 R1：内容含敏感路径时
        collector 的数据外泄检测会直接告警（这正是要暴露给面板的事实）。"""
        if isinstance(prompt, list):
            payload = {"messages": redact(prompt)[:50]}
        else:
            payload = {"prompt": redact(str(prompt))[:8000]}
        return self._emit(
            "llm.request",
            actor={"type": "model", "name": model},
            action={"name": "chat",
                    "arguments_redacted": dict(payload, model=model),
                    "result_summary": {},
                    "summary": f"LLM 请求 → {model}"},
            parent_span_id=parent_span_id)

    def llm_response(self, model, summary="", usage=None, parent_span_id=None):
        return self._emit(
            "llm.response",
            actor={"type": "model", "name": model},
            action={"name": "chat",
                    "arguments_redacted": {},
                    "result_summary": {"summary": redact(str(summary))[:2000],
                                       "usage": usage or {}},
                    "summary": f"LLM 响应 ← {model}: {str(summary)[:60]}"},
            parent_span_id=parent_span_id)

    # ---------- 工具层 ----------

    def tool_invoke(self, tool_name, arguments, parent_span_id=None):
        return self._emit(
            "tool.invoke",
            actor={"type": "agent", "agent": self.sdk.app_name},
            action={"name": tool_name,
                    "arguments_redacted": redact(arguments),
                    "result_summary": {},
                    "summary": f"工具调用: {tool_name}"},
            parent_span_id=parent_span_id)

    def tool_result(self, tool_name, result, parent_span_id=None):
        return self._emit(
            "tool.result",
            actor={"type": "agent", "agent": self.sdk.app_name},
            action={"name": tool_name,
                    "arguments_redacted": {},
                    "result_summary": {"output": redact(str(result))[:2000]},
                    "summary": f"工具结果: {tool_name}"},
            parent_span_id=parent_span_id)


class AgentTraceSDK:
    """SDK 入口。一个应用一个实例，每个用户会话调 session()。"""

    def __init__(self, app_name, collector_url="http://127.0.0.1:8787/ingest",
                 source=None, flush_threshold=5, timeout=5, verbose=False):
        self.app_name = app_name
        self.collector_url = collector_url
        self.source = source or f"webapp:{app_name}"
        self.flush_threshold = flush_threshold
        self.timeout = timeout
        self.verbose = verbose
        self._sessions = {}
        self._last_error = None

    def session(self, session_id=None):
        """获取/创建一个用户会话的 trace。session_id 建议用业务侧会话 ID。"""
        sid = session_id or secrets.token_hex(8)
        if sid not in self._sessions:
            tr = SessionTrace(self, sid)
            self._sessions[sid] = tr
            tr.begin()
        return self._sessions[sid]

    def close_session(self, session_id):
        tr = self._sessions.pop(session_id, None)
        if tr:
            tr.end()

    def _note_error(self, exc):
        self._last_error = f"{time.strftime('%H:%M:%S')} {exc}"
        if self.verbose:
            print(f"[agent_trace_sdk] 上报失败（保留重试）: {exc}", flush=True)

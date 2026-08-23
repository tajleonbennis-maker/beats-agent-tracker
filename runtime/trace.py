"""统一事件模型（schema 0.1）：事件构造、脱敏、哈希链写入。

对应规范 07-Agent-Execution-Trace-Observability.md 第 3.1 节。
设计要点：
- 原始证据与展示字段分离：action.arguments_redacted 在写入前已脱敏；
- 每个事件进入哈希链（evidence.prev_hash / evidence.hash），防事后篡改；
- 事件一行一条 NDJSON，交给 Filebeat（Beats 只负责采集，不修改哈希覆盖的字段）。
"""
import hashlib
import json
import os
import re
import secrets
import time

SCHEMA_VERSION = "0.1"

# ---------- ULID 风格可排序 ID ----------
def new_id(prefix: str) -> str:
    ts = int(time.time() * 1000)
    return f"{prefix}_{ts:012x}{secrets.token_hex(10)}"


# ---------- 脱敏 ----------
_VALUE_KEYS = re.compile(
    r"(?i)^(authorization|cookie|set-cookie|password|passwd|secret|token|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?id)$"
)
_STRING_PATTERNS = [
    re.compile(r"(?i)(authorization|bearer)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*\S+"),
    re.compile(r"sk-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[bap]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]
_REDACTED = "[REDACTED]"
REDACTED = _REDACTED


def redact(obj):
    """递归脱敏：命中的键值整体替换；字符串中的令牌模式替换。"""
    if isinstance(obj, dict):
        return {
            k: (REDACTED if _VALUE_KEYS.match(str(k)) and v else redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, str):
        for pat in _STRING_PATTERNS:
            obj = pat.sub(REDACTED, obj)
    return obj


def truncate(s: str, n: int = 500) -> str:
    return s if len(s) <= n else s[:n] + "...[truncated]"


# ---------- 事件构造与哈希链 ----------
HASHED_FIELDS = [
    "schema_version", "trace_id", "span_id", "parent_span_id", "timestamp",
    "source", "event_type", "actor", "action", "policy",
]


def _strip_nulls(obj):
    """递归剔除 null 值（Beats 传输会丢弃 null 字段，规范化需两端一致）。"""
    if isinstance(obj, dict):
        return {k: _strip_nulls(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_nulls(x) for x in obj if x is not None]
    return obj


def canonical_core(event: dict) -> str:
    """提取 schema 核心字段做规范化序列化（Beats 附加的 ECS 字段不参与哈希）。

    null 不敏感：emit 端与 verify 端都会先剔除 null，这样 Beats 传输时
    丢弃 null 字段不会破坏哈希链；但任何对非空内容的修改都会被检出。
    """
    core = {k: event.get(k) for k in HASHED_FIELDS}
    core["evidence"] = {k: v for k, v in (event.get("evidence") or {}).items()
                        if k != "hash"}
    core = _strip_nulls(core)
    return json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def chain_hash(prev_hash: str, event: dict) -> str:
    return hashlib.sha256((prev_hash + "|" + canonical_core(event)).encode()).hexdigest()


class EventWriter:
    """把事件追加写入 NDJSON 文件，维护 trace 级哈希链。"""

    def __init__(self, events_dir: str, trace_id: str):
        os.makedirs(events_dir, exist_ok=True)
        self.path = os.path.join(events_dir, f"{trace_id}.ndjson")
        self.trace_id = trace_id
        self.prev_hash = "GENESIS"
        self.count = 0

    def build(self, source: str, event_type: str, span_id: str, parent_span_id,
              actor: dict, action: dict = None, policy: dict = None,
              evidence_extra: dict = None) -> dict:
        event = {
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
            "evidence": evidence_extra or {},
        }
        return event

    def emit(self, event: dict) -> dict:
        event["evidence"]["prev_hash"] = self.prev_hash
        event["evidence"]["raw_event_ref"] = f"object://events/{self.trace_id}/{self.count:06d}"
        h = chain_hash(self.prev_hash, event)
        event["evidence"]["hash"] = h
        self.prev_hash = h
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        self.count += 1
        return event

    def verify_chain(self, events: list) -> bool:
        prev = "GENESIS"
        for ev in events:
            if ev.get("evidence", {}).get("prev_hash") != prev:
                return False
            if chain_hash(prev, ev) != ev.get("evidence", {}).get("hash"):
                return False
            prev = ev["evidence"]["hash"]
        return True

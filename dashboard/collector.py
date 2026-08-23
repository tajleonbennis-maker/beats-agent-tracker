#!/usr/bin/env python3
"""
Agent 执行监视器 —— 实时事件收集器 + SSE 广播 + 本地仪表板

职责：
1. 接收各采集器通过 HTTP POST /ingest 上报的事件（NDJSON 或单条 JSON）
2. 把事件追加到本地 NDJSON 文件（实时落盘，断点可续）
3. 通过 /events SSE 向浏览器实时推送
4. 提供 / 网页仪表板
5. 轻量实时规则：命中密钥模式或越界外联时立即广播 alert

启动：
  python3 dashboard/collector.py [--port 8787] [--events-dir events]
"""
import argparse
import collections
import html
import json
import os
import queue
import re
import secrets
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, render_template_string, request

ROOT = Path(__file__).resolve().parents[1]
app = Flask(__name__)

# 全局状态
STATE = {
    "clients": [],          # SSE 订阅队列
    "events": [],           # 最近 2000 条（内存缓存）
    "alerts": [],           # 最近 200 条实时告警
    "counters": {},         # 按 event_type 计数
    "last": None,           # 最新事件时间
    "fs_seen": {},          # 跨观察器 fs 去重缓存: (event_type,path,size) -> (trace_id, wall_time)
}
LOCK = threading.Lock()
CONTROL_TOKEN = secrets.token_urlsafe(24)
REGISTRY_PATH = ROOT / "agents" / "registry.json"


def _agent_registry():
    try:
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        if not isinstance(data.get("agents"), list):
            raise ValueError("agents must be a list")
        return data
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"proxy_url": "http://127.0.0.1:8080", "agents": [], "error": str(exc)}


def _port_listening(port: int) -> bool:
    try:
        return subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _agent_status(agent: dict, proxy_url: str) -> dict:
    pairs = list(zip(agent.get("app_names", []), agent.get("app_paths", [])))
    app_name = next((name for name, path in pairs if Path(path).is_dir()), None)
    running = proxy_active = False
    for pattern in agent.get("process_patterns", []):
        try:
            found = subprocess.run(["pgrep", "-f", pattern], capture_output=True,
                                   text=True, timeout=3)
            if found.returncode == 0:
                running = True
                for pid in found.stdout.split():
                    cmd = subprocess.run(["ps", "-p", pid, "-o", "args="],
                                         capture_output=True, text=True, timeout=3).stdout
                    proxy_active |= f"--proxy-server={proxy_url}" in cmd
        except (OSError, subprocess.TimeoutExpired):
            continue
    return {"id": agent["id"], "name": agent["name"], "installed": app_name is not None,
            "app_name": app_name, "running": running, "proxy_active": proxy_active,
            "trace_ids": agent.get("trace_ids", [])}

SECRET_CONTENT_PATTERNS = [
    ("password-assign", re.compile(r"(?i)(password|passwd|pwd|secret|token)\s*[:=]\s*['\"]?[\w\-./!@#$%^&*]{8,}")),
    ("sshpass", re.compile(r"(?i)sshpass\s+.*\-(p|P)\s+\S+")),
    ("aws-key", re.compile(r"(?i)(AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16})")),
    ("private-key", re.compile(r"(?i)BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY")),
    ("api-key", re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[a-z0-9]{32,}")),
]

ALLOWLIST_HOSTS = {"127.0.0.1", "localhost", "0.0.0.0"}

# 危险命令（工具审计：execute_bash/run_command 命令内容）
DANGEROUS_COMMAND_PATTERNS = [
    ("递归删除", re.compile(r"(?i)\brm\s+-[a-z]*[rf][a-z]*[rf][a-z]*\b")),
    ("管道执行远程脚本", re.compile(r"(?i)\b(curl|wget)\b[^|;&]*\|\s*(ba|z|k|da)?sh\b")),
    ("危险权限", re.compile(r"(?i)\bchmod\s+(-R\s+)?777\b")),
    ("磁盘擦除", re.compile(r"(?i)\bdd\s+.*\bof=/dev/")),
    ("格式化磁盘", re.compile(r"(?i)\bmkfs")),
    ("递归删除目录", re.compile(r"(?i)\brmdir\s+/s\b")),
    ("覆盖系统文件", re.compile(r"(?i)\b(sudo\s+)?(echo|cat|tee)\b.*>\s*/etc/")),
]

# 数据外泄检测（llm.request 请求体里出现的敏感路径/内容）
SENSITIVE_EXFIL_PATTERNS = [
    ("SSH密钥路径", re.compile(r"\.ssh/|id_rsa|id_ed25519|authorized_keys")),
    ("git凭证", re.compile(r"\.gitconfig|\.git-credentials")),
    ("云凭证路径", re.compile(r"\.aws/|\.gnupg/|\.config/gcloud|\.kube/")),
    ("环境变量文件", re.compile(r"\.env\b")),
    ("私钥内容", re.compile(r"BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY")),
    ("密码管理器", re.compile(r"\.netrc|Keychains|keychain")),
]

# 越界文件读取（read_file 读敏感文件）
SENSITIVE_READ_PATHS = [
    ("SSH密钥", re.compile(r"\.ssh/")),
    ("git凭证", re.compile(r"\.gitconfig|\.git-credentials")),
    ("云凭证", re.compile(r"\.aws/|\.gnupg/")),
    ("系统账号", re.compile(r"/etc/(passwd|shadow|sudoers)")),
    ("环境变量", re.compile(r"\.env\b")),
]


def chain_hash(prev_hash: str, event: dict) -> str:
    """与 runtime/trace.py 保持一致的哈希算法。"""
    import hashlib

    def _canonical(obj):
        if isinstance(obj, dict):
            return {k: _canonical(v) for k, v in sorted(obj.items()) if v is not None}
        if isinstance(obj, list):
            return [_canonical(x) for x in obj]
        return obj

    payload = json.dumps(_canonical(event.get("evidence") or {}), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(f"{prev_hash}|{payload}".encode("utf-8")).hexdigest()


def make_event(trace_id: str, event_type: str, span_id: str, parent_span_id: str,
               actor: dict, action: dict, source: str = "dashboard", extra: dict = None) -> dict:
    """构造一条符合 schema 0.1 的事件。"""
    now = datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
    ev = {
        "schema_version": "0.1",
        "trace_id": trace_id,
        "span_id": span_id or secrets.token_hex(16),
        "parent_span_id": parent_span_id,
        "timestamp": now,
        "event_type": event_type,
        "source": source,
        "actor": actor or {"type": "unknown"},
        "action": {
            "name": action.get("name", event_type),
            "arguments_redacted": action.get("arguments_redacted", {}),
            "result_summary": action.get("result_summary", {}),
            "summary": action.get("summary", ""),
        },
        "evidence": {
            "integrity": "sha256-chain",
            "prev_hash": "",
            "hash": "",
        },
    }
    if extra:
        ev.update(extra)
    return ev


# LLM 请求体外泄内容标记（BOSS 查案视图用，服务端全文扫描后只回传命中项）
LEAK_MARK_PATTERNS = [
    ("疑似明文密码", SECRET_CONTENT_PATTERNS[0][1]),
    ("sshpass命令", re.compile(r"(?i)sshpass\s")),
    ("AWS密钥", SECRET_CONTENT_PATTERNS[2][1]),
    ("私钥内容", SECRET_CONTENT_PATTERNS[3][1]),
    ("api-key", SECRET_CONTENT_PATTERNS[4][1]),
] + SENSITIVE_EXFIL_PATTERNS  # SSH密钥路径/git凭证/云凭证路径/.env/密码管理器


def _slim_str(s: str, cap: int = 500) -> str:
    return s if len(s) <= cap else s[:cap] + "…[截断]"


def _slim_obj(obj, cap: int = 500):
    """递归截断超长字符串，控制 /api/events?slim=1 的响应体积。"""
    if isinstance(obj, dict):
        return {k: _slim_obj(v, cap) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_slim_obj(v, cap) for v in obj]
    if isinstance(obj, str):
        return _slim_str(obj, cap)
    return obj


def _slim_event(ev: dict) -> dict:
    """事件瘦身副本：保留时间线展示所需字段；llm.request 附带全文泄露标记。

    不修改内存中的原始事件（STATE["events"]），只构造返回副本。
    """
    et = ev.get("event_type", "")
    ar = ev.get("action", {}).get("arguments_redacted", {})
    slim = {
        "schema_version": ev.get("schema_version"),
        "trace_id": ev.get("trace_id"),
        "span_id": ev.get("span_id"),
        "timestamp": ev.get("timestamp"),
        "event_type": et,
        "source": ev.get("source"),
        "actor": ev.get("actor"),
        "action": {
            "name": ev.get("action", {}).get("name"),
            "arguments_redacted": _slim_obj(ar),
            "result_summary": _slim_obj(ev.get("action", {}).get("result_summary", {}), 300),
            "summary": _slim_str(ev.get("action", {}).get("summary", "") or "", 300),
        },
    }
    if et in ("conversation.user", "conversation.assistant"):
        preview = slim["action"]["arguments_redacted"].get("preview")
        if isinstance(preview, str):
            slim["action"]["arguments_redacted"]["preview"] = html.unescape(preview)
    if et in ("llm.request", "llm.response"):
        full = json.dumps(ar, ensure_ascii=False)
        slim["_size"] = len(full)
        if et == "llm.request":
            leaks = sorted({name for name, pat in LEAK_MARK_PATTERNS if pat.search(full)})
            if leaks:
                slim["_leak"] = leaks
            m = re.search(r'"(?:modelId|model)"\s*:\s*"([^"]+)"', full)
            if m:
                slim["_model"] = m.group(1)
            # web 搜索足迹：web_search 查询词 + 搜索结果里的 URL（含 fetch 直连网页）
            seg = full.replace('\\"', '"')
            sq = re.findall(
                r'"name"\s*:\s*"web_search"\s*,\s*"arguments"\s*:\s*\{[^{}]*"query"\s*:\s*"([^"]+)"',
                seg,
            )
            surls = re.findall(r'"url"\s*:\s*"(https?://[^"]+)"', seg)
            if sq or surls:
                slim["_search"] = {
                    "queries": sorted(set(sq)),
                    "urls": sorted(set(surls)),
                }
    return slim


def _classify_alert(ev: dict) -> list:
    """实时规则，返回若干 alert 字典。"""
    alerts = []
    et = ev.get("event_type", "")
    args = ev.get("action", {}).get("arguments_redacted", {})

    # R1: 内容/参数含密钥（重点：明文密码命令，脱敏显示）
    text = json.dumps(args, ensure_ascii=False)
    for name, pat in SECRET_CONTENT_PATTERNS:
        if pat.search(text):
            detail = f"实时嗅探到疑似密钥（{name}）"
            # 工具调用命令 → 显示工具名 + 脱敏后的命令，让告警可定位
            if et == "tool.invoke":
                tool_name = ev.get("action", {}).get("name", "")
                cmd = args.get("command", "") if isinstance(args, dict) else ""
                if cmd:
                    redacted = re.sub(
                        r'(-p\s+["\']?)[^"\'\s]+', r'\1[REDACTED]', cmd, flags=re.I)
                    redacted = re.sub(
                        r'(password|passwd|pwd|secret|token)\s*[:=]\s*["\']?[^\s"\']+',
                        r'\1=[REDACTED]', redacted, flags=re.I)
                    detail = (f"明文密码命令（{name}）：{tool_name} → "
                              f"{redacted[:140]}")
            alerts.append({
                "rule_id": "R1",
                "severity": "high",
                "timestamp": ev.get("timestamp"),
                "trace_id": ev.get("trace_id"),
                "span_id": ev.get("span_id"),
                "detail": detail,
                "event": ev,
            })
            break

    # R3: 异常外联（绕过代理直连公网，peer_kind=direct）
    if et == "net.connect":
        peer_kind = args.get("peer_kind", "")
        peer = args.get("peer", "")
        if peer_kind == "direct":
            alerts.append({
                "rule_id": "R3",
                "severity": "medium",
                "timestamp": ev.get("timestamp"),
                "trace_id": ev.get("trace_id"),
                "span_id": ev.get("span_id"),
                "detail": f"异常外联(绕过代理): {peer}",
                "event": ev,
            })

    # R2: 越界文件读取/写入（按 workspace 参数判断）
    if et in ("fs.read", "fs.write", "fs.create"):
        path = args.get("path", "")
        workspace = args.get("workspace", "")
        if workspace and path and not path.startswith(workspace):
            alerts.append({
                "rule_id": "R2",
                "severity": "medium",
                "timestamp": ev.get("timestamp"),
                "trace_id": ev.get("trace_id"),
                "span_id": ev.get("span_id"),
                "detail": f"越界文件操作: {path}",
                "event": ev,
            })

    # R4: 危险命令（工具审计：execute_bash/run_command 含危险操作）
    if et == "tool.invoke":
        cmd = args.get("command", "") if isinstance(args, dict) else ""
        if cmd:
            for name, pat in DANGEROUS_COMMAND_PATTERNS:
                if pat.search(cmd):
                    alerts.append({
                        "rule_id": "R4",
                        "rule_name": "危险命令",
                        "severity": "high",
                        "timestamp": ev.get("timestamp"),
                        "trace_id": ev.get("trace_id"),
                        "span_id": ev.get("span_id"),
                        "detail": f"危险命令（{name}）：{cmd[:120]}",
                        "event": ev,
                    })
                    break

    # 越界读取敏感文件（工具审计：read_file/grep_search 读敏感文件）
    if et == "tool.invoke":
        path = args.get("path", "") if isinstance(args, dict) else ""
        if path:
            for name, pat in SENSITIVE_READ_PATHS:
                if pat.search(path):
                    alerts.append({
                        "rule_id": "R1",
                        "rule_name": "敏感文件读取",
                        "severity": "high",
                        "timestamp": ev.get("timestamp"),
                        "trace_id": ev.get("trace_id"),
                        "span_id": ev.get("span_id"),
                        "detail": f"读取敏感文件（{name}）：{path[:120]}",
                        "event": ev,
                    })
                    break

    # 数据外泄检测（llm.request 请求体含敏感路径/内容）
    if et == "llm.request":
        for name, pat in SENSITIVE_EXFIL_PATTERNS:
            if pat.search(text):
                alerts.append({
                    "rule_id": "R1",
                    "rule_name": "数据外泄",
                    "severity": "high",
                    "timestamp": ev.get("timestamp"),
                    "trace_id": ev.get("trace_id"),
                    "span_id": ev.get("span_id"),
                    "detail": f"请求体含敏感信息（{name}）→ 可能外泄给大模型",
                    "event": ev,
                })
                break

    return alerts


def _append_to_file(path: Path, lines: list):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")


def _broadcast(obj: dict):
    dead = []
    with LOCK:
        for q in STATE["clients"]:
            try:
                q.put_nowait(obj)
            except queue.Full:
                dead.append(q)
        STATE["clients"] = [q for q in STATE["clients"] if q not in dead]


def ingest_event(ev: dict, config: dict):
    """核心入口：接收事件、校验/补链、落盘、广播、实时规则。"""
    et = ev.get("event_type", "unknown")
    trace_id = ev.get("trace_id") or config["fallback_trace_id"]
    ev.setdefault("trace_id", trace_id)

    # —— 跨观察器 fs 去重 ——
    # 同一工作区常被多个 Agent 观察器同时监视（如 tracker 根目录本身），
    # FSEvents 不携带写入进程 pid，导致同一次文件变更被每个观察器各上报一条、
    # 且都只有 actor=workspace —— 出现"VS Code 写的文件记到 WorkBuddy 头上"。
    # 规则：fs.* 且 actor.type=workspace 的事件，若 10 秒内已有其他 trace 上报
    # 相同 event_type+path+size，则丢弃后到者，保留首个观察器的记录。
    if et.startswith("fs.") and (ev.get("actor") or {}).get("type") == "workspace":
        _act = ev.get("action") or {}
        _path = ((_act.get("arguments_redacted") or {}).get("path")) or ""
        _size = str(((_act.get("result_summary") or {}).get("size")) or "")
        if _path:
            _key = (et, str(_path), _size)
            _now = time.time()
            with LOCK:
                _prev = STATE["fs_seen"].get(_key)
                if _prev and _prev[0] != trace_id and (_now - _prev[1]) <= 10.0:
                    print(f"[collector] fs 去重: 丢弃 {trace_id} 的重复 {et} {_path}"
                          f"（已由 {_prev[0]} 记录）", flush=True)
                    return
                STATE["fs_seen"][_key] = (trace_id, _now)
                if len(STATE["fs_seen"]) > 5000:  # 防膨胀：清掉 60 秒前的条目
                    STATE["fs_seen"] = {
                        k: v for k, v in STATE["fs_seen"].items()
                        if _now - v[1] <= 60.0
                    }

    # 维护哈希链（简单模式：按文件内顺序，每条事件只依赖前一条 hash）
    chain_file = Path(config["events_dir"]) / f"{trace_id}.ndjson"
    prev = "GENESIS"
    if chain_file.exists():
        try:
            with open(chain_file, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if size:
                    f.seek(max(0, size - 4096))
                    last_line = f.read().decode("utf-8", errors="ignore").strip().split("\n")[-1]
                    last_ev = json.loads(last_line)
                    prev = (last_ev.get("evidence") or {}).get("hash", "GENESIS")
        except Exception:
            pass

    ev.setdefault("evidence", {})
    if not ev["evidence"].get("hash"):
        # 无 hash 的事件（本地 observer/mitmproxy/fs_watcher）→ 本地续链
        ev["evidence"]["prev_hash"] = prev
        ev["evidence"]["hash"] = chain_hash(prev, ev)
    # 已有 hash 的事件（server/agent.py 上报）→ 保留其原始哈希链，不重算

    # 落盘
    _append_to_file(chain_file, [ev])

    # 内存状态 + 广播
    with LOCK:
        STATE["events"].append(ev)
        if len(STATE["events"]) > GLOBAL_HISTORY_MAX:
            STATE["events"] = _cap_events_per_trace(STATE["events"])
        STATE["counters"][et] = STATE["counters"].get(et, 0) + 1
        STATE["last"] = ev.get("timestamp")

    _broadcast({"kind": "event", "data": ev})

    # 实时告警
    for alert in _classify_alert(ev):
        alert["_id"] = secrets.token_hex(8)
        with LOCK:
            STATE["alerts"].append(alert)
            if len(STATE["alerts"]) > 1000:
                STATE["alerts"] = STATE["alerts"][-1000:]
        _append_to_file(Path(config["events_dir"]) / f"{trace_id}_alerts.ndjson", [alert])
        _broadcast({"kind": "alert", "data": alert})


PER_TRACE_HISTORY = 2000   # 单个 trace 内存保留条数
GLOBAL_HISTORY_MAX = 30000  # 全局裁剪触发阈值


def _cap_events_per_trace(evs: list) -> list:
    """按 trace 分桶裁剪：每个 trace 保留最近 PER_TRACE_HISTORY 条。

    背景：全局只留最近 N 条时，高频 process/net trace（每小时数千条）会把
    低频的会话/上下文 trace（conversation.*，通常只有几十条）整体挤出内存，
    导致 Boss 面板重启后"上下文消失、只剩告警"。分桶后每个 trace 都有自己的
    保留份额，低频 trace 不再被饿死。
    """
    per = collections.defaultdict(list)
    for ev in evs:
        per[ev.get("trace_id") or "unknown"].append(ev)
    out = []
    for lst in per.values():
        out.extend(lst[-PER_TRACE_HISTORY:])
    out.sort(key=lambda e: e.get("timestamp", "") or "")
    return out


def _load_history(events_dir: str):
    """启动时从 events 目录加载历史事件+告警，让 BOSS 视图重启后仍有数据。"""
    evdir = Path(events_dir)
    if not evdir.is_dir():
        return
    loaded = []
    alerts_loaded = []
    for fn in sorted(evdir.glob("*.ndjson")):
        is_alert = fn.name.endswith("_alerts.ndjson")
        try:
            with open(fn, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    (alerts_loaded if is_alert else loaded).append(obj)
        except OSError:
            continue
    if loaded:
        loaded.sort(key=lambda e: e.get("timestamp", "") or "")
        loaded = _cap_events_per_trace(loaded)
        with LOCK:
            STATE["events"] = loaded
            for ev in loaded:
                et = ev.get("event_type", "unknown")
                STATE["counters"][et] = STATE["counters"].get(et, 0) + 1
            STATE["last"] = loaded[-1].get("timestamp") if loaded else None
    if alerts_loaded:
        alerts_loaded.sort(key=lambda a: a.get("timestamp", "") or "")
        alerts_loaded = alerts_loaded[-1000:]
        with LOCK:
            # 合并去重（_id 优先，无 _id 用 detail+timestamp）
            seen = set()
            merged = []
            for a in STATE["alerts"] + alerts_loaded:
                key = a.get("_id") or f"{a.get('timestamp')}|{a.get('rule_id')}|{a.get('detail','')[:80]}"
                if key in seen:
                    continue
                seen.add(key)
                merged.append(a)
            merged.sort(key=lambda a: a.get("timestamp", "") or "")
            STATE["alerts"] = merged[-1000:]


def create_app(events_dir: str, fallback_trace_id: str):
    config = {"events_dir": events_dir, "fallback_trace_id": fallback_trace_id}
    _load_history(events_dir)

    @app.route("/ingest", methods=["POST"])
    def ingest():
        ctype = request.headers.get("Content-Type", "")
        items = []
        if "ndjson" in ctype or "x-ndjson" in ctype:
            # ndjson 批量（server/agent.py 上报格式，多行 JSON）
            raw = request.get_data(as_text=True)
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        else:
            try:
                payload = request.get_json(force=True, silent=True) or {}
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 400
            # 支持单条或数组
            items = payload if isinstance(payload, list) else [payload]

        n = 0
        for ev in items:
            if not isinstance(ev, dict):
                continue
            ingest_event(ev, config)
            n += 1
        return jsonify({"ok": True, "ingested": n})

    @app.route("/events")
    def events():
        def stream():
            q = queue.Queue(maxsize=200)
            with LOCK:
                STATE["clients"].append(q)
                # 推送历史最近 100 条 + 最近 20 告警
                for ev in STATE["events"][-100:]:
                    yield f"data: {json.dumps({'kind':'event','data':ev}, ensure_ascii=False)}\n\n"
                for a in STATE["alerts"][-20:]:
                    yield f"data: {json.dumps({'kind':'alert','data':a}, ensure_ascii=False)}\n\n"
            try:
                while True:
                    try:
                        obj = q.get(timeout=30)
                    except queue.Empty:
                        obj = {"kind": "ping"}
                    yield f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"
            finally:
                with LOCK:
                    if q in STATE["clients"]:
                        STATE["clients"].remove(q)

        return Response(stream(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.route("/api/state")
    def api_state():
        with LOCK:
            return jsonify({
                "counters": STATE["counters"].copy(),
                "clients": len(STATE["clients"]),
                "alerts": len(STATE["alerts"]),
                "last": STATE["last"],
                "total": len(STATE["events"]),
            })

    @app.route("/api/events")
    def api_events():
        limit = min(int(request.args.get("limit", 100)), 20000)
        trace_id = request.args.get("trace_id")
        events = None
        if trace_id and re.fullmatch(r"[A-Za-z0-9_.-]+", trace_id):
            trace_file = Path(config["events_dir"]) / f"{trace_id}.ndjson"
            if trace_file.is_file():
                tail = collections.deque(maxlen=limit)
                try:
                    with trace_file.open(encoding="utf-8", errors="ignore") as fh:
                        for line in fh:
                            try:
                                tail.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                    events = list(tail)
                except OSError:
                    events = None
        if events is None:
            with LOCK:
                source = STATE["events"]
                if trace_id:
                    source = [ev for ev in source if ev.get("trace_id") == trace_id]
                events = source[-limit:]
        if request.args.get("slim"):
            return jsonify([_slim_event(ev) for ev in events])
        return jsonify(events)

    @app.route("/api/alerts")
    def api_alerts():
        trace_id = request.args.get("trace_id")
        with LOCK:
            source = STATE["alerts"]
            if trace_id:
                source = [a for a in source if a.get("trace_id") == trace_id]
            alerts = [{k: v for k, v in a.items() if k != "event"} for a in source]
        return jsonify(alerts)

    @app.route("/api/traces")
    def api_traces():
        with LOCK:
            summaries = {}
            alert_counts = {}
            for alert in STATE["alerts"]:
                tid = alert.get("trace_id") or "unknown"
                alert_counts[tid] = alert_counts.get(tid, 0) + 1
            for ev in STATE["events"]:
                tid = ev.get("trace_id") or "unknown"
                item = summaries.setdefault(tid, {
                    "trace_id": tid, "first": ev.get("timestamp"),
                    "last": ev.get("timestamp"), "events": 0,
                    "agent": None, "source": ev.get("source"), "active": False,
                    "conv": 0,
                })
                item["events"] += 1
                if str(ev.get("event_type", "")).startswith("conversation"):
                    item["conv"] += 1
                item["last"] = ev.get("timestamp") or item["last"]
                actor = ev.get("actor") or {}
                observed_agent = actor.get("agent") or actor.get("name")
                if ev.get("event_type") in ("trace.begin", "trace.resume") and observed_agent:
                    item["agent"] = observed_agent
                else:
                    item["agent"] = item["agent"] or observed_agent
                if ev.get("event_type") in ("trace.begin", "trace.resume", "session.heartbeat"):
                    item["active"] = True
                elif ev.get("event_type") == "trace.end":
                    item["active"] = False
            for tid, item in summaries.items():
                item["alerts"] = alert_counts.get(tid, 0)
            result = sorted(summaries.values(), key=lambda x: x.get("last") or "", reverse=True)
        return jsonify(result)

    @app.route("/api/agents")
    def api_agents():
        registry = _agent_registry()
        proxy_url = registry.get("proxy_url", "http://127.0.0.1:8080")
        return jsonify({"proxy_url": proxy_url, "collector_up": _port_listening(8787),
                        "proxy_up": _port_listening(8080), "upstream_up": _port_listening(1087),
                        "agents": [_agent_status(a, proxy_url) for a in registry.get("agents", [])],
                        "registry_error": registry.get("error")})

    @app.route("/api/agents/<agent_id>/launch", methods=["POST"])
    def api_agent_launch(agent_id):
        if request.headers.get("X-Boss-Control") != CONTROL_TOKEN:
            return jsonify({"ok": False, "error": "control token invalid"}), 403
        registry = _agent_registry()
        agent = next((a for a in registry.get("agents", []) if a.get("id") == agent_id), None)
        if not agent:
            return jsonify({"ok": False, "error": "unknown agent"}), 404
        proxy_url = registry.get("proxy_url", "http://127.0.0.1:8080")
        status = _agent_status(agent, proxy_url)
        if not status["installed"]:
            return jsonify({"ok": False, "error": "application not installed"}), 404
        if not _port_listening(8080):
            return jsonify({"ok": False, "error": "mitmproxy 127.0.0.1:8080 is not running"}), 409
        if status["running"]:
            message = "已通过专属代理运行" if status["proxy_active"] else "应用正在运行；请保存并完全退出后再启动"
            return jsonify({"ok": status["proxy_active"], "error": message}), 200 if status["proxy_active"] else 409
        try:
            result = subprocess.run(["open", "-a", status["app_name"], "--args",
                                     f"--proxy-server={proxy_url}"],
                                    capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500
        if result.returncode:
            return jsonify({"ok": False, "error": result.stderr.strip() or "launch failed"}), 500
        return jsonify({"ok": True, "message": f'{status["name"]} 已通过 {proxy_url} 启动'})

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/boss")
    def boss():
        return render_template_string(BOSS_HTML, control_token=CONTROL_TOKEN)

    return app


DASHBOARD_HTML = r"""
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent 执行监视器 — 实时面板</title>
<style>
  :root { --bg:#f6f7f9; --panel:#fff; --text:#1f2328; --muted:#656d76; --accent:#0969da; --red:#cf222e; --orange:#bc4c00; --green:#1a7f37; }
  body { margin:0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:var(--bg); color:var(--text); }
  header { background:var(--panel); border-bottom:1px solid #d1d9e0; padding:16px 24px; display:flex; align-items:center; gap:16px; position:sticky; top:0; z-index:10; }
  h1 { margin:0; font-size:18px; }
  .status { display:flex; gap:12px; align-items:center; font-size:13px; color:var(--muted); }
  .badge { background:#eaeef2; padding:3px 8px; border-radius:12px; }
  .alert-badge { background:#ffebe9; color:var(--red); font-weight:600; }
  main { display:grid; grid-template-columns: 320px 1fr; gap:16px; padding:16px; }
  .panel { background:var(--panel); border:1px solid #d1d9e0; border-radius:10px; padding:14px; }
  .panel h2 { margin:0 0 10px; font-size:14px; color:var(--muted); text-transform:uppercase; letter-spacing:.4px; }
  .metric { display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid #f0f0f0; font-size:13px; }
  .metric:last-child { border-bottom:none; }
  .stream { max-height: calc(100vh - 180px); overflow:auto; }
  .event { border-left:3px solid #d1d9e0; padding:8px 10px; margin-bottom:6px; border-radius:0 6px 6px 0; background:#fafafa; font-size:12px; }
  .event.tool { border-left-color:var(--accent); }
  .event.net { border-left-color:var(--orange); }
  .event.fs { border-left-color:var(--green); }
  .event.conversation { border-left-color:#7c3aed; background:#f5f3ff; }
  .event.llm { border-left-color:#0a9396; background:#f0fdfa; }
  .event.alert { border-left-color:var(--red); background:#fff6f5; }
  .ts { color:var(--muted); font-family:monospace; }
  .type { font-weight:600; color:var(--text); }
  .source { color:var(--muted); }
  .detail { margin-top:4px; word-break:break-all; }
  pre { background:#f3f4f6; padding:8px; border-radius:6px; overflow:auto; max-height:200px; margin:6px 0 0; }
  .red-dot { display:inline-block; width:8px; height:8px; background:var(--red); border-radius:50%; animation:pulse 1s infinite; }
  @keyframes pulse { 0%{opacity:1} 50%{opacity:.4} 100%{opacity:1} }
  @media (max-width:900px){ main{grid-template-columns:1fr;} }
</style>
</head>
<body>
<header>
  <h1>🛡️ Agent 执行监视器</h1>
  <div class="status">
    <span id="conn" class="badge">⏳ 连接中…</span>
    <span class="badge">采集器在线: <b id="clients">0</b></span>
    <span class="badge alert-badge">🚨 告警: <b id="alertCount">0</b></span>
    <span class="badge">最后事件: <span id="last">—</span></span>
  </div>
</header>
<main>
  <aside>
    <div class="panel">
      <h2>事件统计</h2>
      <div id="counters"></div>
    </div>
    <div class="panel" style="margin-top:16px">
      <h2>实时告警</h2>
      <div id="alerts" class="stream"></div>
    </div>
  </aside>
  <section class="panel">
    <h2>事件流</h2>
    <div id="events" class="stream"></div>
  </section>
</main>
<script>
const host = location.host;
const es = new EventSource(`/events`);
es.onopen = () => document.getElementById('conn').textContent = '🟢 实时连接';
es.onerror = () => document.getElementById('conn').textContent = '🔴 断开';

function fmtTime(ts){ if(!ts) return '-'; const d=new Date(ts); return d.toLocaleTimeString('zh-CN',{hour12:false})+'.'+String(d.getMilliseconds()).padStart(3,'0'); }
function esc(s){ return (s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function kindClass(t){ if(t.startsWith('tool.')) return 'tool'; if(t.startsWith('fs.')) return 'fs'; if(t.startsWith('net.')||t.startsWith('session.')) return 'net'; if(t.startsWith('conversation.')) return 'conversation'; if(t.startsWith('llm.')) return 'llm'; if(t==='alert') return 'alert'; return ''; }

function renderEvent(msg){
  const e = msg.data;
  const div = document.createElement('div');
  div.className = 'event ' + kindClass(e.event_type || msg.kind);
  const act = e.action || {};
  const args = act.arguments_redacted || {};
  let summary = act.summary || '';
  if(!summary && args.peer) summary = args.peer;
  if(!summary && args.path) summary = args.path;
  if(!summary && args.method) summary = `${args.method} ${args.host||args.url||''}`;
  if(!summary && args.tool_name) summary = args.tool_name;
  let extra = '';
  const payload = Object.keys(args).length ? JSON.stringify(args, null, 2) : '';
  if(payload) extra += `<pre>${esc(payload)}</pre>`;
  div.innerHTML = `<div><span class="ts">${fmtTime(e.timestamp)}</span> <span class="type">${esc(e.event_type||msg.kind)}</span> <span class="source">${esc(e.source||'')}</span></div><div class="detail">${esc(summary)}</div>${extra}`;
  const box = document.getElementById('events');
  box.prepend(div);
  while(box.children.length > 300) box.lastChild.remove();
}

function renderAlert(a){
  const div = document.createElement('div');
  div.className = 'event alert';
  div.innerHTML = `<div><span class="ts">${fmtTime(a.timestamp)}</span> <span class="type">${esc(a.rule_id)}</span> <b>${esc(a.severity)}</b></div><div class="detail">${esc(a.detail)}</div>`;
  const box = document.getElementById('alerts');
  box.prepend(div);
  while(box.children.length > 50) box.lastChild.remove();
  document.getElementById('alertCount').innerHTML = '<span class="red-dot"></span> ' + box.children.length;
}

es.onmessage = ev => {
  const msg = JSON.parse(ev.data);
  if(msg.kind === 'event') renderEvent(msg);
  if(msg.kind === 'alert') renderAlert(msg.data);
};

async function refreshState(){
  const r = await fetch('/api/state');
  const s = await r.json();
  document.getElementById('clients').textContent = s.clients;
  document.getElementById('last').textContent = fmtTime(s.last);
  const c = document.getElementById('counters');
  c.innerHTML = Object.entries(s.counters).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`<div class="metric"><span>${esc(k)}</span><b>${v}</b></div>`).join('');
}
setInterval(refreshState, 3000);
refreshState();
</script>
</body>
</html>
"""


BOSS_HTML = r"""
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent 查案视图 — BOSS</title>
<style>
  :root { --bg:#f3f6fa; --panel:#fff; --text:#172033; --muted:#667085; --accent:#3157d5; --red:#d92d20; --orange:#dc6803; --green:#079455; --purple:#6941c6; --border:#e4e7ec; --shadow:0 1px 2px rgba(16,24,40,.04),0 8px 24px rgba(16,24,40,.04); }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif; background:var(--bg); color:var(--text); }
  header { background:rgba(255,255,255,.94); backdrop-filter:blur(12px); border-bottom:1px solid var(--border); padding:12px 24px; display:flex; align-items:center; gap:14px; position:sticky; top:0; z-index:10; flex-wrap:wrap; }
  h1 { margin:0; font-size:18px; font-weight:650; }
  .meta { font-size:12px; color:var(--muted); }
  .nav { margin-left:auto; display:flex; gap:8px; font-size:13px; align-items:center; }
  .nav a { text-decoration:none; color:var(--muted); padding:5px 12px; border-radius:8px; }
  .nav a.active { background:#eef2ff; color:var(--accent); font-weight:600; }
  .nav label { font-size:12px; color:var(--muted); display:flex; align-items:center; gap:4px; cursor:pointer; margin-left:10px; }
  .trace-picker { min-width:280px; max-width:430px; border:1px solid var(--border); border-radius:9px; padding:7px 10px; background:#fff; color:var(--text); font-size:12px; outline:none; }
  .trace-picker:focus { border-color:#84adff; box-shadow:0 0 0 3px #eff4ff; }
  .live { display:inline-flex; align-items:center; gap:6px; color:var(--green); font-size:12px; font-weight:600; }
  .live:before { content:''; width:7px; height:7px; border-radius:50%; background:currentColor; box-shadow:0 0 0 4px #ecfdf3; }
  .stats { display:grid; grid-template-columns:repeat(7,1fr); gap:12px; padding:14px 24px; }
  .stat { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:12px; box-shadow:var(--shadow); }
  .stat .label { font-size:12px; color:var(--muted); margin-bottom:5px; }
  .stat .value { font-size:24px; font-weight:700; }
  .stat.warn .value { color:var(--red); }
  main { padding:0 24px 40px; }
  .risk-section { background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:14px 18px; margin-bottom:14px; }
  .risk-section h2 { margin:0 0 8px; font-size:14px; }
  .risk-item { font-size:12.5px; padding:5px 0; border-bottom:1px solid #f5f5f5; }
  .risk-item:last-child { border-bottom:none; }
  .risk-item .rid { font-weight:700; }
  .risk-item .r1 { color:var(--red); }
  .risk-item .r3, .risk-item .r2 { color:var(--orange); }
  .task { background:var(--panel); border:1px solid var(--border); border-radius:14px; margin-bottom:14px; overflow:hidden; box-shadow:var(--shadow); }
  .task-head { padding:12px 18px; border-bottom:1px solid var(--border); display:flex; align-items:baseline; gap:12px; flex-wrap:wrap; background:#fafbfc; }
  .task-head .time { font-size:12px; color:var(--muted); white-space:nowrap; font-family:ui-monospace,monospace; }
  .task-head .instruction { font-size:15px; font-weight:650; flex:1; min-width:200px; }
  .task-head .dur { font-size:12px; color:var(--muted); white-space:nowrap; }
  .badge { font-size:12px; padding:3px 10px; border-radius:12px; font-weight:600; white-space:nowrap; }
  .badge.risk { background:#fef2f2; color:var(--red); }
  .badge.quota { background:#fff7ed; color:var(--orange); }
  .task-body { padding:12px 18px 16px; }
  .row { display:flex; gap:8px; align-items:flex-start; margin-bottom:8px; font-size:13px; }
  .row .tag { flex-shrink:0; width:76px; color:var(--muted); font-size:12px; padding-top:2px; }
  .row .content { flex:1; line-height:1.9; }
  .chip { display:inline-block; background:#f3f4f6; border:1px solid var(--border); border-radius:6px; padding:1px 8px; margin:2px 3px 2px 0; font-size:12px; font-family:ui-monospace,monospace; max-width:340px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; vertical-align:bottom; }
  .chip.model { background:#f5f3ff; border-color:#ddd6fe; color:var(--purple); }
  .chip.tool { background:#eef2ff; border-color:#c7d2fe; color:var(--accent); }
  .chip.file { background:#f0fdf4; border-color:#bbf7d0; color:var(--green); }
  .chip.ext { background:#fffbeb; border-color:#fde68a; color:var(--orange); }
  .chip.read { background:#f0f9ff; border-color:#bae6fd; color:#0369a1; }
  .chip.sens { background:#fef2f2; border-color:#fecaca; color:var(--red); font-weight:600; }
  .chip.leak { background:#fef2f2; border-color:#fecaca; color:var(--red); font-weight:600; }
  .leak-panel { background:#fff7f7; border:1px solid #fecaca; border-radius:10px; padding:10px 14px; margin-bottom:10px; font-size:13px; line-height:1.8; }
  .leak-panel .leak-list { font-size:12px; color:var(--muted); margin-top:4px; }
  .search-panel { background:#f0f9ff; border:1px solid #bae6fd; border-radius:10px; padding:10px 14px; margin-bottom:10px; font-size:13px; line-height:1.8; }
  .search-panel .leak-list { font-size:12px; color:var(--muted); margin-top:4px; word-break:break-all; }
  details.tlbox { border:1px solid var(--border); border-radius:10px; overflow:hidden; }
  details.tlbox summary { cursor:pointer; padding:9px 14px; font-size:13px; font-weight:600; background:#f9fafb; user-select:none; }
  .filters { display:flex; gap:6px; flex-wrap:wrap; padding:8px 14px; border-bottom:1px solid #f0f0f0; align-items:center; }
  .fbtn { font-size:12px; border:1px solid var(--border); background:#fff; border-radius:14px; padding:2px 10px; cursor:pointer; color:var(--muted); }
  .fbtn.on { background:#eef2ff; color:var(--accent); border-color:#c7d2fe; font-weight:600; }
  .tl { max-height:520px; overflow:auto; padding:6px 10px; font-size:12.5px; }
  .tl-e { display:flex; gap:8px; padding:3px 6px; border-radius:6px; line-height:1.6; }
  .tl-e:hover { background:#f5f7fa; }
  .tl-e .t { flex-shrink:0; width:92px; color:var(--muted); font-family:ui-monospace,monospace; font-size:11.5px; padding-top:1px; }
  .tl-e .body { flex:1; word-break:break-all; }
  .tl-e.sens { background:#fef2f2; }
  .tl-e.sens .body { color:var(--red); font-weight:600; }
  .tl-e.alert-e { background:#fff7ed; }
  .tl-e.err { background:#fef2f2; }
  .tl-e .ico { flex-shrink:0; }
  .tl-e .cmd { font-family:ui-monospace,monospace; background:#f3f4f6; border-radius:4px; padding:0 5px; }
  .tl-e .dim { color:var(--muted); }
  .tl-e code { display:block; margin-top:2px; padding:3px 8px; font-family:ui-monospace,Menlo,monospace; font-size:11.5px; background:rgba(15,23,42,.06); border-radius:4px; word-break:break-all; }
  .tl-e .warn-inline { color:var(--red); font-weight:600; }
  body:not(.show-noise) .tl-e.noise { display:none; }
  .tl[data-f="conv"] .tl-e:not([data-cat="conv"]) { display:none; }
  .tl[data-f="llm"] .tl-e:not([data-cat="llm"]) { display:none; }
  .tl[data-f="tool"] .tl-e:not([data-cat="tool"]) { display:none; }
  .tl[data-f="fs"] .tl-e:not([data-cat="fs"]) { display:none; }
  .tl[data-f="net"] .tl-e:not([data-cat="net"]) { display:none; }
  .tl[data-f="proc"] .tl-e:not([data-cat="proc"]) { display:none; }
  .tl[data-f="alert"] .tl-e:not([data-cat="alert"]) { display:none; }
  .tl-more { padding:8px 14px; font-size:12px; color:var(--muted); border-top:1px solid #f0f0f0; }
  .tl-more-btn { display:block; width:100%; margin:8px 0 4px; padding:6px; font-size:12.5px; color:var(--muted); background:#f5f7fa; border:1px solid #e5e7eb; border-radius:6px; cursor:pointer; }
  .tl-more-btn:hover { background:#eef1f5; }
  .empty { text-align:center; color:var(--muted); padding:50px 0; font-size:14px; }
  .agent-control { background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:14px 18px; margin-bottom:14px; box-shadow:var(--shadow); }
  .agent-control h2 { margin:0 0 10px; font-size:14px; }
  .agent-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:9px; }
  .agent-card { border:1px solid var(--border); border-radius:10px; padding:10px; font-size:12px; }
  .agent-card strong { display:block; font-size:13px; margin-bottom:7px; }
  .agent-card button { margin-top:8px; width:100%; border:1px solid #c7d2fe; background:#eef2ff; color:var(--accent); border-radius:7px; padding:6px; cursor:pointer; }
  .agent-card button:disabled { cursor:not-allowed; opacity:.5; }
  .agent-ok { color:var(--green); } .agent-warn { color:var(--orange); }
  @media (max-width:1000px) { .stats { grid-template-columns:repeat(4,1fr); } .agent-grid{grid-template-columns:repeat(2,1fr)} .trace-picker{min-width:200px;} }
  @media (max-width:680px) { header{padding:10px 14px}.nav{margin-left:0;width:100%;overflow:auto}.stats{grid-template-columns:repeat(2,1fr);padding:12px 14px}main{padding:0 14px 28px}.trace-picker{width:100%;max-width:none}.task-head,.task-body{padding-left:12px;padding-right:12px}.tl-e .t{width:72px}.row{display:block}.row .tag{display:block;width:auto;margin-bottom:2px} }
</style>
</head>
<body>
<header>
  <h1>🔍 Agent 查案视图</h1>
  <span class="live" id="liveState">实时</span>
  <span class="meta" id="meta"></span>
  <div class="nav">
    <select id="tracePicker" class="trace-picker" aria-label="选择 Agent 会话"></select>
    <label><input type="checkbox" id="noiseToggle"> 显示系统噪音</label>
    <a href="/boss" class="active">查案视图</a>
    <a href="/">原始事件</a>
  </div>
</header>

<div class="stats" id="stats"></div>
<main>
  <section class="agent-control">
    <h2>Agent 专属代理控制 <span class="meta" id="proxySummary"></span></h2>
    <div class="agent-grid" id="agentGrid"><span class="meta">加载中…</span></div>
  </section>
  <div class="risk-section" id="riskSummary" style="display:none"></div>
  <div id="tasks"></div>
</main>

<script>
const BOSS_CONTROL_TOKEN = {{ control_token|tojson }};
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

async function loadAgents(){
  const s = await fetch('/api/agents').then(r=>r.json());
  document.getElementById('proxySummary').textContent =
    `· Collector ${s.collector_up?'在线':'离线'} · MITM ${s.proxy_up?'在线':'离线'} · 上游 ${s.upstream_up?'在线':'离线'} · ${s.proxy_url}`;
  document.getElementById('agentGrid').innerHTML = s.agents.map(a=>{
    const state = !a.installed ? '未安装' : !a.running ? '未运行' : a.proxy_active ? '专属代理运行中' : '运行中（未走专属代理）';
    const cls = a.proxy_active ? 'agent-ok' : 'agent-warn';
    const disabled = !a.installed || !s.proxy_up || a.proxy_active;
    return `<div class="agent-card"><strong>${esc(a.name)}</strong><span class="${cls}">${esc(state)}</span>`+
      `<button ${disabled?'disabled':''} onclick="launchAgent('${esc(a.id)}')">专属代理启动</button></div>`;
  }).join('');
}
async function launchAgent(id){
  const r = await fetch('/api/agents/'+encodeURIComponent(id)+'/launch', {method:'POST', headers:{'X-Boss-Control':BOSS_CONTROL_TOKEN}});
  const body = await r.json();
  if(!r.ok || !body.ok) alert(body.error || '启动失败'); else alert(body.message || '已启动');
  loadAgents();
}

// —— 时区安全的时间解析：兼容 Z 结尾 / +0800 / +08:00 / 无后缀(按UTC, fs_watcher源) ——
function normTs(ts){
  if(!ts) return NaN;
  let s = String(ts).trim();
  s = s.replace(/([+-]\d{2})(\d{2})$/, '$1:$2');
  if(/Z$/i.test(s) || /[+-]\d{2}:\d{2}$/.test(s)) return Date.parse(s);
  return Date.parse(s + 'Z');
}
const fmtHMS = ms => { if(isNaN(ms)) return '?'; return new Date(ms).toLocaleTimeString('zh-CN',{hour12:false}); };
const fmtHMSms = ms => { if(isNaN(ms)) return '?'; return fmtHMS(ms) + '.' + String(new Date(ms).getMilliseconds()).padStart(3,'0'); };
const fmtDur = ms => { if(isNaN(ms)||ms<0) return ''; if(ms<60000) return Math.round(ms/1000)+'秒'; if(ms<3600000) return (ms/60000).toFixed(1)+'分'; return (ms/3600000).toFixed(1)+'时'; };
const kb = n => (n==null) ? '' : (n/1024).toFixed(0)+'KB';

const isNoiseFsPath = p => !p || p.includes('Application Support') || p.includes('Library/Caches') || p.includes('.git/objects') || p.endsWith('.DS_Store') || p.includes('state.vscdb');

function isNoise(e){
  const t = e.event_type || '';
  if(t === 'session.heartbeat') return true;
  if(t.startsWith('fs.')) return isNoiseFsPath(e.action?.arguments_redacted?.path);
  if(t === 'net.connect'){ const p = e.action?.arguments_redacted?.peer || ''; return p.startsWith('127.') || p.startsWith('::1'); }
  if(t === 'net.listen') return true;
  if(t === 'llm.request'){ return !e._model && !e._leak && !e._search; }
  return false;
}

function cleanPreview(p){
  return String(p||'')
    .replace(/<EnvironmentContext>[\s\S]*$/, '')
    .replace(/--- CONTEXT ENTRY BEGIN ---[\s\S]*$/, '')
    .trim();
}
function isInstruction(e){
  if(e.event_type !== 'conversation.user') return false;
  const p = cleanPreview(e.action?.arguments_redacted?.preview);
  if(!p) return false;
  if(p.startsWith('You are Kiro')) return false;
  return true;
}

// —— 观察器事件去重 ——
// 两类历史重复源：
//  1) observer 与 fs_watcher 双源捕获同一次文件操作
//  2) 曾有两个 observer 并发 resume 同一 trace_id，平行演化出两条相同
//     哈希链——process/net/心跳/trace 标记全部成对出现
// 键 = 类型 + 标识（pid / path / 连接四元组）+ 秒级时间戳
function dedupeFs(events){
  const seen = new Set();
  return events.filter(e => {
    const t = e.event_type || '';
    if(!(t.startsWith('fs.') || t.startsWith('process.') || t.startsWith('net.') ||
         t === 'session.heartbeat' || t.startsWith('trace.'))) return true;
    const ar = e.action?.arguments_redacted || {};
    const id = ar.pid ?? ar.path ?? ((ar.local||'') + '>' + (ar.peer||'')) ?? '';
    const key = t + '|' + id + '|' + String(e.timestamp||'').replace(/\.\d+/, '');
    if(seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function collectExternals(events){
  const s = new Map();
  events.forEach(e => {
    if(!['net.connect','tool.http'].includes(e.event_type)) return;
    const ar = e.action?.arguments_redacted || {};
    const host = ar.host || (ar.peer||'').split(':')[0];
    if(host && !host.startsWith('127.') && !host.includes('telemetry') && !host.includes('download.kiro')) s.set(host, (s.get(host)||0)+1);
  });
  return s;
}

function renderMeta(events, alerts){
  const el = document.getElementById('meta');
  if(!events.length){ el.textContent = '暂无事件'; return; }
  const t0 = fmtHMS(normTs(events[0].timestamp));
  const t1 = fmtHMS(normTs(events[events.length-1].timestamp));
  el.textContent = events.length + ' 事件 · ' + alerts.length + ' 告警 · ' + t0 + ' ~ ' + t1 + ' · 10s 自动刷新';
}

function renderStats(events, alerts){
  const instructions = events.filter(isInstruction);
  const toolCalls = events.filter(e=>e.event_type==='tool.invoke').length;
  const llmCalls = events.filter(e=>e.event_type==='llm.request' && (e._model || e._leak)).length;
  const fileOps = events.filter(e=>String(e.event_type||'').startsWith('fs.') && !isNoiseFsPath(e.action?.arguments_redacted?.path)).length;
  const sensReads = events.filter(e=>e.event_type==='fs.read' && e.action?.arguments_redacted?.sensitive).length;
  const externals = collectExternals(events).size;
  const leakReqs = events.filter(e=>e.event_type==='llm.request' && e._leak && e._leak.length).length;
  const riskCount = alerts.filter(a=>a.rule_id==='R1'||a.rule_id==='R4').length;
  const cards = [
    ['指令数', instructions.length, ''],
    ['工具调用', toolCalls, ''],
    ['LLM 请求', llmCalls, ''],
    ['文件操作', fileOps, ''],
    ['敏感读取', sensReads, sensReads?'warn':''],
    ['外泄请求', leakReqs, leakReqs?'warn':''],
    ['高危告警', riskCount, riskCount?'warn':''],
  ];
  document.getElementById('stats').innerHTML = cards.map(([l,v,cls])=>
    '<div class="stat ' + cls + '"><div class="label">' + l + '</div><div class="value">' + v + '</div></div>').join('');
}

function renderRisk(alerts){
  const box = document.getElementById('riskSummary');
  const risky = alerts.filter(a=>a.rule_id==='R1'||a.rule_id==='R4');
  const medium = alerts.filter(a=>a.rule_id==='R2'||a.rule_id==='R3');
  if(!risky.length && !medium.length){ box.style.display='none'; return; }
  box.style.display='block';
  let h = '<h2>🚨 风险告警（高危 ' + risky.length + ' / 中危 ' + medium.length + '）</h2>';
  h += risky.slice(-40).map(a=>'<div class="risk-item"><span class="rid r' + a.rule_id.slice(1) + '">[' + esc(a.rule_id) + ']</span> ' + fmtHMS(normTs(a.timestamp)) + ' — ' + esc(a.detail||'').slice(0,130) + '</div>').join('');
  if(risky.length > 40) h += '<div class="risk-item dim">…仅显示最近 40 条高危</div>';
  box.innerHTML = h;
}

// —— 单条事件的展示构造 ——
function buildEntry(e){
  const t = e.event_type || '';
  const ar = e.action?.arguments_redacted || {};
  const rs = e.action?.result_summary || {};
  if(t === 'conversation.user'){
    const p = cleanPreview(ar.preview);
    return { cat:'conv', icon:'👤', html:'<b>用户指令</b> ' + esc(p.slice(0,150)) };
  }
  if(t === 'conversation.assistant'){
    return { cat:'conv', icon:'🤖', html:'<b>Kiro 回复</b> ' + esc(String(ar.preview||'').slice(0,180)) };
  }
  if(t === 'llm.request'){
    let h = '<b>LLM 请求</b> ';
    h += e._model ? '<span class="chip model">' + esc(e._model) + '</span> ' : '';
    if(e._size) h += '<span class="dim">' + kb(e._size) + '</span> ';
    if(e._search){
      (e._search.queries||[]).forEach(q => h += '<span class="chip model">🔎 ' + esc(q) + '</span> ');
      if((e._search.urls||[]).length) h += '<span class="chip ext">🌐 携带 ' + e._search.urls.length + ' 个搜索结果URL</span> ';
    }
    if(e._leak && e._leak.length) h += e._leak.map(l=>'<span class="chip leak">🔴 ' + esc(l) + '</span>').join(' ');
    return { cat:'llm', icon:'🧠', html:h };
  }
  if(t === 'llm.response'){
    const s = JSON.stringify(rs||{});
    if(s.includes('QuotaExceeded') || s.includes('reached the limit')){
      const reason = (s.match(/"reason"\s*:\s*"([^"]+)"/)||[])[1] || '';
      return { cat:'llm', icon:'❌', cls:'err', html:'<b>配额耗尽</b> ' + esc(reason) + ' — 请求被云端拒绝，内容未外发' };
    }
    return { cat:'llm', icon:'⤵️', html:'<b>LLM 响应</b> ' + (rs.status_code ? ('HTTP ' + esc(rs.status_code)) : '<span class="dim">ok</span>') + (e._size ? ' <span class="dim">' + kb(e._size) + '</span>' : '') };
  }
  if(t === 'tool.invoke'){
    if(ar.url) return { cat:'tool', icon:'🌐', html:'<b>网页抓取</b> <span class="cmd">' + esc(ar.url) + '</span>' };
    if(ar.query && !ar.command && !ar.path) return { cat:'tool', icon:'🔎', html:'<b>Web 搜索</b> <span class="cmd">' + esc(ar.query) + '</span>' };
    let d = ar.command ? '<span class="cmd">' + esc(String(ar.command).slice(0,320)) + '</span>'
      : (ar.path ? esc(ar.path) : esc(JSON.stringify(ar).slice(0,220)));
    return { cat:'tool', icon:'🔧', html:'<b>工具调用 ' + esc(e.action?.name || ar.tool_name || '') + '</b> ' + d };
  }
  if(t === 'tool.result'){
    return { cat:'tool', icon:'✅', html:'<b>工具结果</b> HTTP ' + esc(rs.status_code ?? '?') };
  }
  if(t === 'fs.read'){
    const sens = !!ar.sensitive;
    return { cat:'fs', icon:'📖', cls: sens ? 'sens' : '', html:(sens ? '<b>🔴 敏感读取</b> ' : '<b>读取</b> ') + esc(ar.path||'') + ' <span class="dim">pid=' + esc(e.actor?.pid ?? '?') + '</span>' };
  }
  if(['fs.write','fs.create','fs.rename','fs.change'].includes(t)){
    const label = { 'fs.write':'写入', 'fs.create':'创建', 'fs.rename':'改名', 'fs.change':'变更' }[t];
    return { cat:'fs', icon:'✍️', html:'<b>' + label + '</b> ' + esc(ar.path||'') };
  }
  if(t === 'net.connect'){
    const direct = ar.peer_kind === 'direct';
    return { cat:'net', icon:'🌐', html:'<b>连接</b> ' + esc(ar.peer||'?') + ' ' + (direct ? '<span class="warn-inline">⚠️ 直连公网(绕过代理)</span>' : '<span class="dim">经代理</span>') };
  }
  if(t === 'tool.http'){
    return { cat:'net', icon:'📤', html:'<b>HTTP ' + esc(ar.method||'GET') + '</b> ' + esc(ar.host||'') + '<span class="dim">' + esc(String(ar.path||'').slice(0,80)) + '</span>' };
  }
  if(t === 'process.spawn' || t === 'process.span'){
    const pid = e.actor?.pid ?? ar.pid ?? '?';
    const cmd = ar.argv || ar.exe || '';
    const ghost = String(ar.scan_mode||'').includes('ghost') || !cmd;
    const plugin = e.actor?.agent_plugin || ar.agent_plugin;
    let h = '<b>' + (t === 'process.span' ? '进程基线' : '子进程启动') + '</b> pid=' + esc(pid);
    if(plugin) h += ' <span class="chip model">' + esc(plugin) + '</span>';
    if(ar.ppid) h += ' <span class="dim">← ppid ' + esc(ar.ppid) + '</span>';
    if(ar.parent_argv) h += ' <span class="dim">父: ' + esc(String(ar.parent_argv).slice(0,90)) + '</span>';
    if(cmd) h += '<br><code>' + esc(String(cmd).slice(0,220)) + '</code>';
    else if(ghost) h += '<br><span class="dim">⚠️ 短命子进程（存活 &lt;0.1s，exec 后命令未捕获）</span>';
    return { cat:'proc', icon:'📦', html:h };
  }
  if(t === 'process.exit'){
    const pid = ar.pid ?? e.actor?.pid ?? '?';
    let h = '<span class="dim">进程退出 pid=' + esc(pid);
    if(ar.lifetime_sec != null) h += ' · 存活 ' + esc(ar.lifetime_sec) + 's';
    h += '</span>';
    const exitArgv = ar.argv || rs.argv;
    if(exitArgv) h += '<br><code class="dim">' + esc(String(exitArgv).slice(0,180)) + '</code>';
    return { cat:'proc', icon:'▫️', html:h };
  }
  if(t === 'trace.resume') return { cat:'other', icon:'⏯️', html:'<span class="dim">会话恢复</span>' };
  if(t === 'trace.end') return { cat:'other', icon:'⏹️', html:'<span class="dim">会话结束</span>' };
  if(t === 'session.heartbeat') return { cat:'other', icon:'💓', html:'<span class="dim">心跳</span>' };
  return { cat:'other', icon:'•', html:esc(t) + ' ' + esc(JSON.stringify(ar).slice(0,120)) };
}

function alertEntry(a){
  return { cat:'alert', icon:'🚨', cls:'alert-e', html:'<b>告警 [' + esc(a.rule_id) + '/' + esc(a.severity||'') + ']</b> ' + esc(a.detail||'').slice(0,160) };
}

// —— 任务卡（一条指令 = 一张卡，含完整事件时间线） ——
// 时间线数据全局注册表：只存原始事件引用，行 HTML 展开时才分批构建（防内嵌 webview 内存闪退）
let TL_ITEMS = [];      // 每张任务卡的时间线条目数组（{ms, ev} 或 {ms, alert, noise}）
const TL_CHUNK = 300;    // 每批渲染行数
// Web 搜索足迹跨任务去重：query/url 只归属首次出现的任务卡。
// 原因：LLM 每次请求都携带完整会话历史，之前搜索的结果 URL 会在后续每个任务时段的
// llm.request 里反复出现（_search 标记来自请求体全文扫描），不去重会把旧搜索算到新任务头上。
let SEARCH_SEEN = { q: new Set(), u: new Set() };

// 单条时间线行 HTML（渲染时才构建，降低常驻内存）
function tlRowHtml(it){
  if(it.alert){
    const ent = alertEntry(it.alert);
    return '<div class="tl-e alert-e" data-cat="alert"><span class="t">' + fmtHMSms(it.ms) + '</span><span class="ico">' + ent.icon + '</span><span class="body">' + ent.html + '</span></div>';
  }
  const ent = buildEntry(it.ev);
  return '<div class="tl-e ' + (ent.cls||'') + (it.noise?' noise':'') + '" data-cat="' + ent.cat + '"><span class="t">' + fmtHMSms(it.ms) + '</span><span class="ico">' + ent.icon + '</span><span class="body">' + ent.html + '</span></div>';
}

// 分批往 .tl 里追加行
function appendTlBatch(box, items){
  const tl = box.querySelector('.tl');
  const start = tl.__rendered || 0;
  const end = Math.min(start + TL_CHUNK, items.length);
  const oldBtn = tl.querySelector('.tl-more-btn');
  if(oldBtn) oldBtn.remove();
  if(start < end){
    tl.insertAdjacentHTML('beforeend', items.slice(start, end).map(tlRowHtml).join(''));
    tl.__rendered = end;
  }
  if(end < items.length){
    const b = document.createElement('button');
    b.className = 'tl-more-btn';
    b.textContent = '加载更多（已显示 ' + end + ' / ' + items.length + ' 条）';
    b.addEventListener('click', () => appendTlBatch(box, items));
    tl.appendChild(b);
  }
}

// 首次展开（或恢复展开）时渲染一个时间线容器
function renderTlBox(box){
  const items = TL_ITEMS[+box.dataset.tl] || [];
  const tl = box.querySelector('.tl');
  tl.innerHTML = '';
  tl.__rendered = 0;
  appendTlBatch(box, items);
}

function renderTasks(events, alerts){
  const box = document.getElementById('tasks');
  const instructions = events.filter(isInstruction);
  if(!instructions.length && !events.length){
    box.innerHTML = '<div class="empty">暂无记录 — 等待事件流入…</div>';
    return;
  }
  // 快照当前 UI（展开/过滤/滚动），重渲染后原样恢复——周期刷新不再打断阅读
  const snap = { y: window.scrollY, boxes: [] };
  document.querySelectorAll('.tlbox').forEach(b => {
    const tlEl = b.querySelector('.tl');
    snap.boxes.push({ open: b.open, f: (tlEl && tlEl.dataset.f) || 'all', top: (tlEl && tlEl.scrollTop) || 0 });
  });
  const tasks = [];
  const firstT = instructions.length ? (normTs(instructions[0].timestamp)||Infinity) : Infinity;
  if(instructions.length){
    const pre = events.filter(e => (normTs(e.timestamp)||0) < firstT);
    if(pre.length) tasks.push({ pseudo:true, evs:pre, t0:normTs(pre[0].timestamp), t1:firstT });
  }
  if(instructions.length){
    let cursor = events.findIndex(e => (normTs(e.timestamp)||0) >= firstT);
    instructions.forEach((ins,i)=>{
      const t0 = normTs(ins.timestamp)||0;
      const t1 = (i+1 < instructions.length) ? (normTs(instructions[i+1].timestamp)||Infinity) : Infinity;
      const evs = [];
      while(cursor < events.length){
        const t = normTs(events[cursor].timestamp)||0;
        if(t >= t1) break;
        if(t >= t0) evs.push(events[cursor]);
        cursor++;
      }
      tasks.push({ins, evs, t0, t1});
    });
  }
  TL_ITEMS = [];       // taskCard 内会重新填充
  SEARCH_SEEN = { q: new Set(), u: new Set() };  // 搜索足迹去重也随重渲染重置
  box.innerHTML = tasks.map(taskCard).join('');
  // 绑定过滤按钮 + 懒渲染 toggle + 恢复展开/过滤/滚动状态
  document.querySelectorAll('.tlbox').forEach((box2,i) => {
    box2.querySelectorAll('.fbtn').forEach(btn => {
      btn.addEventListener('click', () => {
        box2.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('on'));
        btn.classList.add('on');
        box2.querySelector('.tl').dataset.f = btn.dataset.f;
      });
    });
    box2.addEventListener('toggle', () => {
      if(box2.open && !box2.dataset.rendered){
        box2.dataset.rendered = '1';
        renderTlBox(box2);
      }
    });
    const st = snap.boxes[i];
    if(st && st.open){
      box2.open = true;
      box2.dataset.rendered = '1';
      renderTlBox(box2);
      const tlEl = box2.querySelector('.tl');
      if(tlEl){
        // 恢复滚动位置需要先渲染足够多的批次
        const items2 = TL_ITEMS[+box2.dataset.tl] || [];
        let guard = 0;
        while(tlEl.scrollHeight < st.top + tlEl.clientHeight + 300 && tlEl.__rendered < items2.length && guard++ < 60){
          appendTlBatch(box2, items2);
        }
        tlEl.dataset.f = st.f;
        tlEl.scrollTop = st.top;
        box2.querySelectorAll('.fbtn').forEach(x=>x.classList.remove('on'));
        const onBtn = box2.querySelector('.fbtn[data-f="' + st.f + '"]');
        if(onBtn) onBtn.classList.add('on');
      }
    }
  });
  window.scrollTo(0, snap.y);
}

function taskCard(task){
  const evs = task.evs;
  const t0 = task.t0;
  const lastT = evs.length ? (normTs(evs[evs.length-1].timestamp)||t0) : t0;
  const t1 = (task.t1 === Infinity) ? lastT : task.t1;
  const dur = fmtDur(t1 - t0);

  // 汇总
  const models = new Set(); const tools = new Map(); const reads = new Set(); const sensReads = new Set();
  const writes = new Set(); const exts = new Map(); const plugins = new Set(); let spawns = 0;
  evs.forEach(e => {
    const ar = e.action?.arguments_redacted || {};
    if(e.event_type==='llm.request' && e._model) models.add(e._model);
    else if(e.event_type==='tool.invoke'){ const n = e.action?.name || ar.tool_name || 'tool'; tools.set(n,(tools.get(n)||0)+1); }
    else if(e.event_type==='fs.read'){ if(ar.sensitive) sensReads.add(ar.path); else if(!isNoiseFsPath(ar.path)) reads.add(ar.path); }
    else if(['fs.write','fs.create','fs.rename'].includes(e.event_type)){ if(!isNoiseFsPath(ar.path)) writes.add(ar.path); }
    else if(['net.connect','tool.http'].includes(e.event_type)){ const h = ar.host || (ar.peer||'').split(':')[0]; if(h && !h.startsWith('127.') && !h.includes('telemetry') && !h.includes('download.kiro')) exts.set(h,(exts.get(h)||0)+1); }
    else if(e.event_type==='process.spawn') spawns++;
    const plugin = e.actor?.agent_plugin || ar.agent_plugin;
    if(plugin && plugin !== 'VS Code Extension Host') plugins.add(plugin);
  });

  // 告警与配额
  const tAlerts = (typeof ALERTS !== 'undefined' ? ALERTS : []).filter(a => { const t = normTs(a.timestamp)||0; return t >= t0 && t <= t1 + 1; });
  const riskCount = tAlerts.filter(a=>a.rule_id==='R1'||a.rule_id==='R4').length;
  const quotaHit = evs.some(e => e.event_type==='llm.response' && JSON.stringify(e.action?.result_summary||{}).includes('reached the limit'));

  // LLM 请求体外泄分析（服务端已标记）
  const leakReqs = evs.filter(e => e.event_type==='llm.request' && e._leak && e._leak.length);
  const leakSet = new Set(); leakReqs.forEach(e=>e._leak.forEach(l=>leakSet.add(l)));

  // Web 搜索足迹：web_search 查询词 + 搜索结果/抓取的 URL（服务端 _search 标记 + tool.invoke 的 fetch）
  // 注意：llm.request 的 _search 扫描的是请求体全文（含历史对话回放），这里跨任务去重，
  // 只把首次出现的 query/url 归属当前任务卡；真实发生在本时段的 tool.invoke 搜索/抓取始终计入。
  const searchQueries = new Set(); const searchUrls = new Set(); const fetchUrls = new Set();
  evs.forEach(e => {
    if(e._search){
      (e._search.queries||[]).forEach(q=>{ if(!SEARCH_SEEN.q.has(q)){ SEARCH_SEEN.q.add(q); searchQueries.add(q); } });
      (e._search.urls||[]).forEach(u=>{ if(!SEARCH_SEEN.u.has(u)){ SEARCH_SEEN.u.add(u); searchUrls.add(u); } });
    }
    if(e.event_type==='tool.invoke'){
      const a2 = e.action?.arguments_redacted || {};
      if(a2.url){ searchUrls.add(a2.url); fetchUrls.add(a2.url); SEARCH_SEEN.u.add(a2.url); }
      if(a2.query && (e.action?.name === 'web_search' || /search/i.test(e.action?.name||''))){ searchQueries.add(a2.query); SEARCH_SEEN.q.add(a2.query); }
    }
  });

  const title = task.pseudo ? '⏳ 会话启动 / 指令前活动' : ('💬 ' + esc(cleanPreview(task.ins.action?.arguments_redacted?.preview).slice(0,90)));
  const headTime = fmtHMS(t0);

  let rows = '';
  if(plugins.size) rows += '<div class="row"><span class="tag">Agent 插件</span><span class="content">' + [...plugins].map(p=>'<span class="chip model">⚡ ' + esc(p) + '</span>').join('') + '</span></div>';
  if(models.size) rows += '<div class="row"><span class="tag">大模型</span><span class="content">' + [...models].map(m=>'<span class="chip model">' + esc(m) + '</span>').join('') + '</span></div>';
  if(tools.size) rows += '<div class="row"><span class="tag">执行操作</span><span class="content">' + [...tools].map(([n,c])=>'<span class="chip tool">🔧 ' + esc(n) + (c>1?(' ×'+c):'') + '</span>').join('') + '</span></div>';
  if(searchQueries.size) rows += '<div class="row"><span class="tag">Web 搜索</span><span class="content">' + [...searchQueries].map(q=>'<span class="chip model">🔎 ' + esc(q) + '</span>').join('') + '</span></div>';
  if(sensReads.size) rows += '<div class="row"><span class="tag">敏感读取</span><span class="content">' + [...sensReads].map(f=>'<span class="chip sens">🔴 ' + esc(f.replace('/Users/','~/').split('/').slice(-2).join('/')) + '</span>').join('') + '</span></div>';
  if(reads.size) rows += '<div class="row"><span class="tag">读取文件</span><span class="content">' + [...reads].slice(0,10).map(f=>'<span class="chip read">' + esc(f.split('/').slice(-2).join('/')) + '</span>').join('') + (reads.size>10 ? '<span class="chip">+' + (reads.size-10) + '</span>' : '') + '</span></div>';
  if(writes.size) rows += '<div class="row"><span class="tag">写入文件</span><span class="content">' + [...writes].slice(0,10).map(f=>'<span class="chip file">✍️ ' + esc(f.split('/').slice(-2).join('/')) + '</span>').join('') + (writes.size>10 ? '<span class="chip">+' + (writes.size-10) + '</span>' : '') + '</span></div>';
  if(exts.size) rows += '<div class="row"><span class="tag">外部资源</span><span class="content">' + [...exts].map(([h,c])=>'<span class="chip ext">🌐 ' + esc(h) + (c>1?(' ×'+c):'') + '</span>').join('') + '</span></div>';
  if(spawns) rows += '<div class="row"><span class="tag">子进程</span><span class="content"><span class="chip">📦 ' + spawns + ' 个</span></span></div>';

  // Web 搜索足迹面板
  let searchPanel = '';
  if(searchQueries.size || searchUrls.size){
    const domainOf = u => { try { return new URL(u).hostname; } catch(_){ return (u.split('/')[2]||u); } };
    const byDomain = {};
    searchUrls.forEach(u => { const d = domainOf(u); (byDomain[d] = byDomain[d] || []).push(u); });
    const allUrls = [...searchUrls];
    searchPanel = '<div class="search-panel"><b>🔍 Web 搜索足迹：</b>' +
      [...searchQueries].map(q=>'<span class="chip model">🔎 ' + esc(q) + '</span>').join('') +
      Object.entries(byDomain).map(([d,us])=>'<span class="chip ext">🌐 ' + esc(d) + (us.length>1?(' ×'+us.length):'') + '</span>').join('') +
      (fetchUrls.size ? '<div class="leak-list">直接抓取页面：' + [...fetchUrls].map(u=>esc(u)).join('<br>') + '</div>' : '') +
      '<div class="leak-list">搜索结果页面（' + allUrls.length + ' 条）：<br>' + allUrls.slice(0,15).map(u=>esc(u)).join('<br>') + (allUrls.length>15?('<br>…+' + (allUrls.length-15) + ' 条未展示'): '') + '</div></div>';
  }

  // 外泄面板
  let leakPanel = '';
  if(leakReqs.length){
    leakPanel = '<div class="leak-panel"><b>⚠️ 本时段 ' + leakReqs.length + ' 次 LLM 请求体检出敏感内容：</b>' +
      [...leakSet].map(l=>'<span class="chip leak">🔴 ' + esc(l) + '</span>').join('') +
      '<div class="leak-list">明细：' + leakReqs.map(e => fmtHMS(normTs(e.timestamp)) + ' ' + kb(e._size)).join(' · ') + '</div></div>';
  }

  // 完整时间线（事件 + 告警合并排序）—— 懒渲染：只存原始事件引用，展开时才生成行 HTML
  const items = [];
  evs.forEach(e => {
    items.push({ ms: normTs(e.timestamp)||0, noise: isNoise(e), ev: e });
  });
  tAlerts.forEach(a => {
    items.push({ ms: normTs(a.timestamp)||0, alert: a });
  });
  items.sort((a,b)=>a.ms-b.ms);
  const tlIdx = TL_ITEMS.length;
  TL_ITEMS.push(items);

  const filterBtns = ['all:全部','conv:对话','llm:LLM','tool:工具','fs:文件','net:网络','proc:进程','alert:告警']
    .map(x => { const [v,l] = x.split(':'); return '<button class="fbtn' + (v==='all'?' on':'') + '" data-f="' + v + '">' + l + '</button>'; }).join('');

  return '<div class="task">' +
    '<div class="task-head">' +
      '<span class="time">' + headTime + '</span>' +
      '<span class="instruction">' + title + '</span>' +
      '<span class="dur">持续 ' + dur + ' · ' + evs.length + ' 事件</span>' +
      (quotaHit ? '<span class="badge quota">⚠️ 配额耗尽</span>' : '') +
      (riskCount ? '<span class="badge risk">🚨 ' + riskCount + ' 风险</span>' : '') +
    '</div>' +
    '<div class="task-body">' +
      searchPanel + leakPanel + rows +
      '<details class="tlbox" data-tl="' + tlIdx + '"><summary>🔍 完整事件时间线（' + items.length + ' 条，点开展开）</summary>' +
        '<div class="filters">' + filterBtns + '</div>' +
        '<div class="tl" data-f="all"></div>' +
      '</details>' +
    '</div>' +
  '</div>';
}

document.getElementById('noiseToggle').addEventListener('change', function(){
  document.body.classList.toggle('show-noise', this.checked);
});

// —— 统一入口：先轻量探测 /api/state，数据有变化才拉全量事件(slim) + 告警 ——
// 避免每 10 秒重复解析 ~15MB JSON 造成 webview 内存压力（闪退根因之一）
let ALERTS = [];
let LAST_SIG = null;
let LAST_DATA_SIG = null;   // 当前视图真实数据签名，未变化则跳过重渲染（防闪烁）
// 默认视图 v2：v1 首次进入会自动选中"最活跃 Agent"（几乎总是 WorkBuddy 本机自身流量，
// 因为查案面板本身就在被 WorkBuddy 会话使用）——用户预期是看全部。v2 起默认"全部 Agent"。
if(!localStorage.getItem('boss.trace.v2')){
  localStorage.removeItem('boss.trace');
  localStorage.setItem('boss.trace.v2','1');
}
let ACTIVE_TRACE = localStorage.getItem('boss.trace') || '';
let TRACE_READY = false;
let TRACE_GROUPS = new Map();

async function loadTraces(){
  const traces = await fetch('/api/traces').then(r=>r.json());
  const picker = document.getElementById('tracePicker');
  const agentOf = t => {
    const id = String(t.trace_id||'').toLowerCase();
    const name = String(t.agent||'').toLowerCase();
    if(id.includes('vscode_codex') || name === 'codex') return 'Codex · VS Code';
    if(id.includes('workbuddy') || name === 'workbuddy') return 'WorkBuddy';
    if(id.includes('trae') || name === 'trae') return 'Trae';
    if(id.includes('kiro') || name === 'kiro') return 'Kiro';
    return '其他 / 历史';
  };
  // 选择器只显示近 6 小时内活跃的 trace；ebpf/mem/srv 等历史测试数据不再混进来
  const now = Date.now();
  const fresh = traces.filter(t => t.active || !t.last || (now - (normTs(t.last)||0)) < 6*3600*1000);
  const groups = new Map();
  fresh.forEach(t => { const g=agentOf(t); if(!groups.has(g)) groups.set(g,[]); groups.get(g).push(t); });
  TRACE_GROUPS = groups;
  const order = ['Codex · VS Code','WorkBuddy','Trae','Kiro','其他 / 历史'];
  const options = '<option value="">全部 Agent（可能混合会话）</option>' + order.filter(g=>groups.has(g)).map(g =>
    '<optgroup label="' + esc(g) + '">' +
    (g === '其他 / 历史' ? '' : '<option value="agent:' + esc(g) + '">● ' + esc(g) + ' · 全部事件</option>') +
    groups.get(g).map(t => {
      // 会话类 trace（含 conversation.* 事件）标注为"会话/上下文"，不再一律误标"进程 / 审计"
      const label = t.trace_id.includes('_https') ? 'HTTPS 流'
        : ((t.conv||0) > 0 ? '会话/上下文' : (t.trace_id.includes('_main') ? '主会话' : '进程 / 审计'));
      return '<option value="' + esc(t.trace_id) + '">' + (t.active?'● ':'') + label + ' · ' + esc(t.trace_id.slice(-12)) + ' · ' + t.events + '事件</option>';
    }).join('') + '</optgroup>'
  ).join('');

  // fetch 期间用户可能刚切换 Agent，因此必须在响应返回后读取当前选择。
  // 周期刷新也可能短暂缺少某个采集流；这种情况不能把用户踢回最新的 Kiro 会话。
  const selected = ACTIVE_TRACE;
  if(picker.innerHTML !== options) picker.innerHTML = options;
  if(selected.startsWith('agent:')) {
    const agent = selected.slice(6);
    if(!groups.has(agent)) {
      picker.insertAdjacentHTML('beforeend', '<option value="' + esc(selected) + '">● ' + esc(agent) + ' · 等待事件</option>');
    }
    picker.value = selected;
  }
  else if(selected && traces.some(t=>t.trace_id===selected)) {
    // 旧版记住的是单条采集流；升级后默认迁移到对应 Agent 的聚合视图。
    const old = traces.find(t=>t.trace_id===selected);
    const group = agentOf(old);
    ACTIVE_TRACE = group === '其他 / 历史' ? selected : 'agent:' + group;
    picker.value = ACTIVE_TRACE;
    localStorage.setItem('boss.trace', ACTIVE_TRACE);
  }
  else if(selected) {
    // 保留暂时未出现在服务端列表中的单会话选择，等待下次刷新恢复。
    picker.insertAdjacentHTML('beforeend', '<option value="' + esc(selected) + '">当前会话 · 等待事件</option>');
    picker.value = selected;
  }
  else if(!TRACE_READY){
    // 首次进入默认"全部 Agent"，不再自动跳到最活跃 Agent（那几乎总是 WorkBuddy 自身）
    ACTIVE_TRACE = '';
    picker.value = '';
    TRACE_READY = true;
  }
  TRACE_READY = true;
}

document.getElementById('tracePicker').addEventListener('change', e => {
  ACTIVE_TRACE = e.target.value;
  localStorage.setItem('boss.trace', ACTIVE_TRACE);
  LAST_SIG = null;
  LAST_DATA_SIG = null;
  load();
});

async function load(){
  if(!TRACE_READY) await loadTraces();
  let sig = null;
  try {
    const s = await fetch('/api/state').then(r=>r.json());
    sig = JSON.stringify([s.total, s.alerts, ACTIVE_TRACE]);
  } catch(_) {}
  if(LAST_SIG !== null && sig === LAST_SIG) return;  // 无新数据，跳过重量级拉取与重渲染
  LAST_SIG = sig;
  const traceIds = ACTIVE_TRACE.startsWith('agent:')
    ? (TRACE_GROUPS.get(ACTIVE_TRACE.slice(6)) || []).map(t=>t.trace_id)
    : (ACTIVE_TRACE ? [ACTIVE_TRACE] : []);
  if(ACTIVE_TRACE.startsWith('agent:') && !traceIds.length) {
    // Agent 分组短暂消失时保留当前画面；空数组不能退化成“拉取全部 Agent”。
    LAST_SIG = null;
    return;
  }
  const eventUrls = traceIds.length
    ? traceIds.map(id=>'/api/events?limit=20000&slim=1&trace_id='+encodeURIComponent(id))
    : ['/api/events?limit=20000&slim=1'];
  const alertUrls = traceIds.length
    ? traceIds.map(id=>'/api/alerts?trace_id='+encodeURIComponent(id))
    : ['/api/alerts'];
  const [eventParts, alertParts] = await Promise.all([
    Promise.all(eventUrls.map(url=>fetch(url).then(r=>r.json()))),
    Promise.all(alertUrls.map(url=>fetch(url).then(r=>r.json())))
  ]);
  ALERTS = alertParts.flat().filter(Boolean);
  let events = eventParts.flat().filter(Boolean);
  events = dedupeFs(events);
  events.sort((a,b) => (normTs(a.timestamp)||0) - (normTs(b.timestamp)||0));
  // 防闪烁关键：/api/state 的 total/alerts 是全局的，任何一个 Agent 来新事件都会变；
  // 但用户看的是当前选中的视图——当前视图数据没变就不重渲染（整页重建会重置滚动/展开状态）
  const dataSig = ACTIVE_TRACE + '|' + events.length + '|' +
    (events.length ? (normTs(events[events.length-1].timestamp)||0) : '') + '|' + ALERTS.length;
  if(dataSig === LAST_DATA_SIG) return;
  LAST_DATA_SIG = dataSig;
  renderMeta(events, ALERTS);
  renderStats(events, ALERTS);
  renderRisk(ALERTS);
  renderTasks(events, ALERTS);
}
load();
loadAgents();
setInterval(load, 10000);
setInterval(loadTraces, 30000);
setInterval(loadAgents, 5000);
const liveEvents = new EventSource('/events');
let liveTimer = null;
liveEvents.onopen = () => { document.getElementById('liveState').textContent='实时'; };
liveEvents.onerror = () => { document.getElementById('liveState').textContent='重连中'; };
liveEvents.onmessage = ev => {
  try {
    const msg = JSON.parse(ev.data);
    if(msg.kind === 'ping') return;
    const tid = msg.data?.trace_id;
    if(ACTIVE_TRACE && tid) {
      if(ACTIVE_TRACE.startsWith('agent:')) {
        const ids = (TRACE_GROUPS.get(ACTIVE_TRACE.slice(6)) || []).map(t=>t.trace_id);
        if(!ids.includes(tid)) return;
      } else if(tid !== ACTIVE_TRACE) return;
    }
    clearTimeout(liveTimer);
    liveTimer = setTimeout(()=>{ LAST_SIG=null; LAST_DATA_SIG=null; load(); }, 1200);
  } catch(_) {}
};
</script>
</body>
</html>
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--events-dir", default=str(ROOT / "events"))
    ap.add_argument("--fallback-trace-id", default="live")
    args = ap.parse_args()

    create_app(args.events_dir, args.fallback_trace_id)
    print(f"[collector] 监听 http://127.0.0.1:{args.port}/")
    print(f"[collector] ingest endpoint: POST http://127.0.0.1:{args.port}/ingest")
    app.run(host="127.0.0.1", port=args.port, threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()

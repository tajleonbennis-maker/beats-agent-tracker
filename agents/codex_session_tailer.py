#!/usr/bin/env python3
"""实时把 Codex session JSONL 映射为统一 Agent Trace 事件。

这是 Codex/VS Code 的第一方接入路径，补充 HTTPS MITM 看不到的既有连接，
只读取 user/assistant/tool 生命周期，不导出 system/developer prompt 或加密推理。
"""
import argparse
import hashlib
import html
import json
import os
import time
import urllib.request
from pathlib import Path


def _text(content):
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "\n".join(str(x.get("text", "")) for x in content
                     if isinstance(x, dict) and x.get("type") in ("input_text", "output_text"))


class CodexSessionTailer:
    def __init__(self, sessions_dir, collector, state_path, backfill=False, backfill_latest=False):
        self.sessions_dir = Path(sessions_dir).expanduser()
        self.collector = collector
        self.state_path = Path(state_path)
        self.backfill = backfill
        self.backfill_latest = backfill_latest
        try:
            self.offsets = json.loads(self.state_path.read_text()).get("offsets", {})
        except Exception:
            self.offsets = {}
        self.sessions = {}

    def _files(self):
        result = []
        for path in sorted(self.sessions_dir.glob("**/*.jsonl")):
            try:
                with path.open(encoding="utf-8", errors="ignore") as fh:
                    first = json.loads(fh.readline())
                meta = first.get("payload") or {}
            except (OSError, json.JSONDecodeError):
                continue
            # Codex 会为审批 guardian/subagent 写独立 rollout，且可能共享 session_id。
            # Boss 只接入用户可见的 VS Code 主会话，避免内部审批文本冒充用户指令。
            if (first.get("type") == "session_meta" and
                    meta.get("originator") == "codex_vscode" and
                    meta.get("source") == "vscode"):
                self.sessions[str(path)] = meta
                result.append(path)
        return result

    def _save(self):
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(f".tmp.{os.getpid()}")
        tmp.write_text(json.dumps({"offsets": self.offsets}))
        tmp.replace(self.state_path)

    def _event(self, rec, path):
        payload = rec.get("payload") or {}
        rtype = rec.get("type")
        session = self.sessions.get(str(path), {})
        match = __import__("re").search(r"([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$", path.stem)
        sid = session.get("session_id") or (match.group(1) if match else path.stem)
        event_type = name = None
        args = {}
        actor = {"type": "agent", "name": "Codex", "host": "VS Code"}

        if rtype == "session_meta":
            self.sessions[str(path)] = payload
            sid = payload.get("session_id") or payload.get("id") or sid
            trace_id = f"vscode_codex_{sid}_main"
            return {
                "schema_version": "0.1", "trace_id": trace_id,
                "span_id": f"session_{sid}", "parent_span_id": None,
                "timestamp": rec.get("timestamp"), "event_type": "trace.begin",
                "source": "codex_session", "actor": actor,
                "action": {"name": "session", "arguments_redacted": {
                    "session_id": sid, "cwd": payload.get("cwd"),
                    "originator": payload.get("originator"), "source": payload.get("source"),
                }, "result_summary": {}, "summary": "Codex VS Code 会话"},
                "evidence": {"integrity": "local-first-party-log"},
            }
        trace_id = f"vscode_codex_{sid}_main"
        if rtype == "event_msg" and payload.get("type") == "user_message":
            event_type, name = "conversation.user", "user_message"
            args = {"preview": html.unescape(payload.get("message", ""))[:2000]}
            actor = {"type": "user", "name": "operator", "host": "VS Code"}
        elif rtype == "event_msg" and payload.get("type") == "agent_message":
            event_type, name = "conversation.assistant", "assistant_message"
            args = {"preview": html.unescape(payload.get("message", ""))[:2000],
                    "phase": payload.get("phase")}
        elif rtype == "event_msg" and payload.get("type") == "task_started":
            event_type, name = "agent.run.started", "task_started"
            args = {"turn_id": payload.get("turn_id")}
        elif rtype == "event_msg" and payload.get("type") == "task_complete":
            event_type, name = "agent.run.completed", "task_complete"
            args = {"turn_id": payload.get("turn_id"), "duration_ms": payload.get("duration_ms")}
        elif rtype == "response_item" and payload.get("type") == "custom_tool_call":
            event_type, name = "tool.invoke", payload.get("name") or "tool"
            args = {"call_id": payload.get("call_id"), "input": str(payload.get("input", ""))[:2000]}
        elif rtype == "response_item" and payload.get("type") == "custom_tool_call_output":
            event_type, name = "tool.result", "tool_result"
            args = {"call_id": payload.get("call_id")}
        if not event_type:
            return None

        raw_id = f"{path}:{rec.get('timestamp')}:{rtype}:{payload.get('type')}:{payload.get('turn_id','')}:{payload.get('call_id','')}"
        span = "codex_" + hashlib.sha256(raw_id.encode()).hexdigest()[:24]
        return {
            "schema_version": "0.1", "trace_id": trace_id, "span_id": span,
            "parent_span_id": payload.get("turn_id"), "timestamp": rec.get("timestamp"),
            "event_type": event_type, "source": "codex_session", "actor": actor,
            "action": {"name": name, "arguments_redacted": args,
                       "result_summary": {}, "summary": name},
            "evidence": {"integrity": "local-first-party-log",
                         "raw_event_ref": f"codex-session:{path.name}"},
        }

    def _post(self, events):
        if not events:
            return
        body = "\n".join(json.dumps(x, ensure_ascii=False) for x in events).encode()
        req = urllib.request.Request(self.collector, data=body,
                                     headers={"Content-Type": "application/x-ndjson"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=10) as response:
            if response.status != 200:
                raise RuntimeError(f"collector HTTP {response.status}")

    def poll(self):
        files = self._files()
        latest = max(files, key=lambda p: p.stat().st_mtime) if files else None
        for path in files:
            key = str(path)
            if key not in self.offsets:
                do_backfill = self.backfill or (self.backfill_latest and path == latest)
                self.offsets[key] = 0 if do_backfill else path.stat().st_size
            offset = self.offsets[key]
            if path.stat().st_size < offset:
                offset = 0
            events = []
            with path.open(encoding="utf-8", errors="ignore") as fh:
                fh.seek(offset)
                for line in fh:
                    try:
                        event = self._event(json.loads(line), path)
                    except (json.JSONDecodeError, TypeError):
                        continue
                    if event:
                        events.append(event)
                self.offsets[key] = fh.tell()
            if events:
                self._post(events)
        self._save()

    def run(self, interval):
        while True:
            try:
                self.poll()
            except Exception as exc:
                print(f"[codex-session] {exc}", flush=True)
            time.sleep(interval)


def main():
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions-dir", default="~/.codex/sessions")
    ap.add_argument("--collector", default="http://127.0.0.1:8787/ingest")
    ap.add_argument("--state", default=str(root / "events/.codex_session_state.json"))
    ap.add_argument("--poll", type=float, default=0.5)
    ap.add_argument("--backfill", action="store_true")
    ap.add_argument("--backfill-latest", action="store_true")
    args = ap.parse_args()
    CodexSessionTailer(args.sessions_dir, args.collector, args.state,
                       args.backfill, args.backfill_latest).run(args.poll)


if __name__ == "__main__":
    main()

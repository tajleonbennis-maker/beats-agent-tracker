#!/usr/bin/env python3
"""audit_tailer.py — 第一方审计日志适配器（"一等公民"接入路径）。

把 Agent 自带的审计日志 tail 成 schema 0.1 事件，POST 给 collector
(http://127.0.0.1:8787/ingest)，由 collector 统一落盘 events/*.ndjson、
广播面板、跑告警规则；es/indexer.py 已在 tail 这些文件 → 自动入 ES。

与被动观测（observer.py，看的是系统事实）互补：本组件看的是 Agent
官方口径自己承认的动作，且事件自带第一方哈希链（evidence.hash 保留
原始 hash，collector 不会重算 → 可与 Agent 侧原始日志对账验真）。

目前内置 profile：
  workbuddy  ~/.workbuddy/audit-log/YYYY-MM-DD.jsonl (schemaVersion 2)
             字段：sessionId/requestId/toolCallId/category/eventType/
                   decision/commandPreview/messageParams{id,target}/
                   timestamp(ms)/prevHash/hash

用法：
  python3 agents/audit_tailer.py                          # 实时 tail（从当前位置）
  python3 agents/audit_tailer.py --backfill-hours 2       # 先回放最近 2 小时
  python3 agents/audit_tailer.py --dry-run                # 只打印映射结果不入库
  python3 agents/audit_tailer.py --profile workbuddy --collector http://127.0.0.1:8787/ingest

collector 不可达时：原始行进 backlog（events/.audit_backlog.ndjson），
恢复后自动补投，不丢事件。
"""
import argparse
import collections
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUDIT_FILE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\.jsonl$")

PROFILES = {
    "workbuddy": {
        "audit_dir": os.path.expanduser("~/.workbuddy/audit-log"),
        "agent_name": "WorkBuddy",
        "slug": "workbuddy",
        "principal": os.environ.get("USER") or "local-user",
    },
}


# ---------------------------------------------------------------- 事件映射
def _iso_ms(ms):
    try:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat(
            timespec="milliseconds").replace("+00:00", "Z")
    except Exception:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_workbuddy(rec, prof, fname):
    """一条 audit 记录 → 一条 schema 0.1 事件（或 None 表示跳过）。"""
    sid = rec.get("sessionId") or "no-session"
    trace_id = f"{prof['slug']}_{sid}"
    ts = _iso_ms(rec.get("timestamp") or 0)
    cat = rec.get("category") or ""
    et = rec.get("eventType") or cat or "audit"
    mp = rec.get("messageParams") or {}
    decision = rec.get("decision") or "unknown"
    cmd = rec.get("commandPreview")
    target = mp.get("target") or mp.get("url") or mp.get("command")

    if cat == "command-safety":
        event_type, name = "tool.call", "run_command"
        args = {"command": cmd or target or ""}
    elif cat == "network":
        # WebFetch 等网络工具调用 → 归入网络类（BOSS 视图网络过滤器含 tool.http）
        event_type, name = "tool.http", et
        args = {"target": target or "", "method": "GET"}
    elif cat == "file-safety":
        event_type, name = "tool.call", et
        args = {"command": cmd or "", "detail": mp.get("path") or ""}
    else:  # approval / rejection / 未知类别
        event_type, name = "tool.call", et
        args = {"command": cmd or "", "detail": json.dumps(mp, ensure_ascii=False)[:300]}

    short = (cmd or target or "")[:80]
    summary = f"{name} [{decision}] {short}"

    ev = {
        "schema_version": "0.1",
        "trace_id": trace_id,
        "span_id": rec.get("toolCallId") or rec.get("id") or f"audit_{rec.get('sequence', '')}",
        "parent_span_id": rec.get("requestId"),
        "timestamp": ts,
        "event_type": event_type,
        "source": f"{prof['slug']}_audit",
        "actor": {"type": "agent", "agent": prof["agent_name"],
                  "principal": prof["principal"]},
        "action": {
            "name": name,
            "arguments_redacted": {k: v for k, v in args.items() if v},
            "result_summary": {"auditEventType": et, "category": cat},
            "summary": summary,
        },
        "policy": {"decision": decision, "rule_id": et, "approval_id": rec.get("requestId")},
        # 保留第一方哈希链：collector 见到已有 hash 不会重算 → 证据可对账
        "evidence": {
            "integrity": "first-party-audit-chain",
            "prev_hash": rec.get("prevHash") or "",
            "hash": rec.get("hash") or "",
            "commandHash": rec.get("commandHash") or "",
            "raw_event_ref": f"file://{Path(prof['audit_dir'])/fname}#id={rec.get('id', '')}",
        },
    }
    return ev


PARSERS = {"workbuddy": parse_workbuddy}


# ---------------------------------------------------------------- 采集器
class AuditTailer:
    def __init__(self, prof, events_dir, collector_url, poll=1.0):
        self.prof = prof
        self.parser = PARSERS[prof["slug"]]
        self.audit_dir = Path(prof["audit_dir"])
        self.events_dir = Path(events_dir)
        self.events_dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.events_dir / f".{prof['slug']}_audit_state.json"
        self.backlog_path = self.events_dir / f".{prof['slug']}_audit_backlog.ndjson"
        self.collector_url = collector_url
        self.poll = poll
        # {fname: offset}；seen_ids 有界去重（跨文件 rollover / 重放安全）
        state = self._load_state()
        self.offsets = state.get("offsets", {})
        self.seen = collections.deque(state.get("seen_ids", []), maxlen=20000)
        self.seen_set = set(self.seen)

    # ---- 状态持久化（崩溃重启不重复投递） ----
    def _load_state(self):
        try:
            return json.loads(self.state_path.read_text())
        except Exception:
            return {}

    def _save_state(self):
        # tmp 带 pid 后缀：多实例并发时不会互相覆盖导致 replace FileNotFoundError
        tmp = self.state_path.with_suffix(f".tmp.{os.getpid()}")
        tmp.write_text(json.dumps({
            "offsets": self.offsets,
            "seen_ids": list(self.seen),
        }))
        tmp.replace(self.state_path)

    # ---- 文件发现与读取 ----
    def _audit_files(self):
        if not self.audit_dir.is_dir():
            return []
        return sorted(p for p in self.audit_dir.iterdir()
                      if AUDIT_FILE_RE.match(p.name))

    def _init_offsets(self, backfill_hours):
        """无状态时：默认从每个文件末尾开始（只看新增）；--backfill-hours 回放。"""
        if self.offsets:
            return
        cutoff_ms = 0
        if backfill_hours:
            cutoff_ms = int((time.time() - backfill_hours * 3600) * 1000)
        for p in self._audit_files():
            if backfill_hours:
                # 找到该文件中第一个 >= cutoff 的行偏移
                off, _ = self._first_line_after(p, cutoff_ms)
                self.offsets[p.name] = off
            else:
                self.offsets[p.name] = p.stat().st_size

    @staticmethod
    def _first_line_after(path, cutoff_ms):
        off = 0
        with open(path, encoding="utf-8", errors="ignore") as f:
            while True:
                line = f.readline()
                if not line:
                    return f.tell(), True
                try:
                    ts = json.loads(line).get("timestamp", 0)
                except Exception:
                    ts = 0
                if ts >= cutoff_ms:
                    return off, False
                off = f.tell()

    def _new_records(self):
        """轮询所有 audit 文件，产出 (fname, offset, records) 增量。"""
        for p in self._audit_files():
            off = self.offsets.get(p.name, 0)
            size = p.stat().st_size
            if size <= off:
                # 日志被轮转/清空：从头重读
                if size < off:
                    off = 0
                elif size == off:
                    continue
            recs = []
            with open(p, encoding="utf-8", errors="ignore") as f:
                f.seek(off)
                while True:
                    line = f.readline()
                    if not line:
                        new_off = f.tell()
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        recs.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue  # 半行（正在写入），下轮重读
                    new_off = f.tell()
            yield p.name, new_off, recs

    # ---- 投递 ----
    def _post(self, events, dry=False):
        if not events:
            return True
        if dry:
            for ev in events:
                print(json.dumps(ev, ensure_ascii=False)[:400])
            return True
        body = ("\n".join(json.dumps(e, ensure_ascii=False) for e in events)).encode()
        req = urllib.request.Request(
            self.collector_url, data=body, method="POST",
            headers={"Content-Type": "application/x-ndjson"})
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=10) as r:
                return r.status == 200
        except Exception as e:
            print(f"[tailer] collector 投递失败（{e}），{len(events)} 条进 backlog", file=sys.stderr)
            return False

    def _append_backlog(self, fname, records):
        with open(self.backlog_path, "a", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps({"file": fname, "rec": rec}, ensure_ascii=False) + "\n")

    def _drain_backlog_once(self):
        if not self.backlog_path.exists():
            return
        lines = [l for l in self.backlog_path.read_text().splitlines() if l.strip()]
        if not lines:
            return
        events = []
        for l in lines:
            try:
                d = json.loads(l)
                ev = self.parser(d["rec"], self.prof, d["file"])
                if ev and ev["evidence"]["hash"] not in self.seen_set:
                    events.append(ev)
            except Exception:
                continue
        if self._post(events):
            self.backlog_path.unlink()
            print(f"[tailer] backlog 补投 {len(events)} 条，已清空")

    def run(self, backfill_hours=0, dry=False):
        self._init_offsets(backfill_hours)
        print(f"[tailer] profile={self.prof['slug']} dir={self.audit_dir} "
              f"collector={self.collector_url} backfill={backfill_hours}h dry={dry}")
        if not dry:
            self._drain_backlog_once()
        last_save = 0.0
        while True:
            n_total = 0
            for fname, new_off, recs in self._new_records():
                events = []
                for rec in recs:
                    rid = (rec.get("hash") or rec.get("id"))
                    if rid and rid in self.seen_set:
                        continue
                    try:
                        ev = self.parser(rec, self.prof, fname)
                    except Exception as e:
                        print(f"[tailer] 解析失败 {e}", file=sys.stderr)
                        ev = None
                    if ev:
                        events.append(ev)
                        if rid:
                            self.seen.append(rid)
                            self.seen_set.add(rid)
                if not dry:
                    if not self._post(events):
                        self._append_backlog(fname, recs)
                elif events:
                    self._post(events, dry=True)
                self.offsets[fname] = new_off
                n_total += len(events)
            if n_total:
                print(f"[tailer] {datetime.now().strftime('%H:%M:%S')} 投递 {n_total} 条事件")
            if time.time() - last_save > 3:
                self._save_state()
                last_save = time.time()
            time.sleep(self.poll)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--profile", default="workbuddy", choices=sorted(PARSERS))
    ap.add_argument("--collector", default="http://127.0.0.1:8787/ingest")
    ap.add_argument("--audit-dir", help="覆盖 profile 默认日志目录")
    ap.add_argument("--events-dir", default=str(ROOT / "events"))
    ap.add_argument("--backfill-hours", type=float, default=0)
    ap.add_argument("--poll", type=float, default=1.0)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    prof = dict(PROFILES[args.profile])
    if args.audit_dir:
        prof["audit_dir"] = args.audit_dir
    # 单实例锁：同 profile 已在运行则拒绝启动（防止状态文件竞争）
    lock = Path(args.events_dir) / f".audit_tailer_{args.profile}.lock"
    if not args.dry_run and lock.exists():
        try:
            pid = int(lock.read_text().strip())
            os.kill(pid, 0)
            print(f"[tailer] profile={args.profile} 已在运行 (pid {pid})，退出。", file=sys.stderr)
            sys.exit(1)
        except (ValueError, ProcessLookupError, PermissionError):
            pass  # 陈旧锁，接管
    t = AuditTailer(prof, args.events_dir, args.collector, args.poll)
    if not args.dry_run:
        lock.write_text(str(os.getpid()))
    try:
        t.run(args.backfill_hours, args.dry_run)
    except KeyboardInterrupt:
        t._save_state()
        print("[tailer] 已停止")


if __name__ == "__main__":
    main()

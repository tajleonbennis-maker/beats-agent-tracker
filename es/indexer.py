#!/usr/bin/env python3
"""es/indexer.py — 把 beats-agent-tracker 的全量事件/告警写入 Elasticsearch。

用法:
    python3 es/indexer.py --backfill          # 回填 events/*.ndjson 全量历史
    python3 es/indexer.py --live              # 回填 + 常驻 tail 实时投递
    python3 es/indexer.py --live --no-backfill  # 只实时投递

设计要点:
- 索引按天分: agent-events-YYYY.MM.DD / agent-alerts-YYYY.MM.DD
- 文档 _id = evidence.hash(哈希链值) 或原始行 SHA-256 → 重复投递幂等
- 混合时区时间戳(+0800 / Z / 无后缀UTC)统一归一化为 @timestamp(UTC)
- llm.request 富化: leak(泄露标记)/model/req_size/search_queries/search_urls
  (复用 dashboard/collector.py 的同一套检测模式, 保证与 BOSS 视图口径一致)
- 零第三方依赖(urllib), 偏移状态存 events/.es_offsets.json
"""
import argparse
import hashlib
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib import request as urlreq
from urllib.error import URLError

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dashboard"))
try:
    import collector  # noqa: E402  (只取常量/正则, 不会启动服务)

    LEAK_MARK_PATTERNS = collector.LEAK_MARK_PATTERNS
except Exception:  # collector 不可用时退化为空
    LEAK_MARK_PATTERNS = []

EVENTS_DIR = ROOT / "events"
OFFSETS_FILE = EVENTS_DIR / ".es_offsets.json"
DEFAULT_ES = "http://127.0.0.1:9200"
BATCH = 500
EVENT_INDEX_PREFIX = "agent-events"
ALERT_INDEX_PREFIX = "agent-alerts"

EVENT_TEMPLATE = {
    "index_patterns": ["agent-events-*"],
    "priority": 200,
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            # llm.request 的 arguments 内嵌异构消息数组, 动态映射路径多
            "index.mapping.total_fields.limit": 10000,
            "index.mapping.depth.limit": 30,
        },
        "mappings": {
            "dynamic": True,
            "properties": {
                "@timestamp": {"type": "date"},
                "schema_version": {"type": "keyword"},
                "trace_id": {"type": "keyword"},
                "span_id": {"type": "keyword"},
                "parent_span_id": {"type": "keyword"},
                "event_type": {"type": "keyword"},
                "source": {"type": "keyword"},
                "timestamp": {"type": "keyword"},
                "actor.pid": {"type": "long"},
                "actor.type": {"type": "keyword"},
                "actor.name": {"type": "keyword"},
                "actor.vendor": {"type": "keyword"},
                "actor.mode": {"type": "keyword"},
                "action.name": {"type": "keyword"},
                # 分析常用参数字段显式 keyword(动态映射默认 text, 无法聚合/过滤)
                "action.arguments_redacted.peer": {"type": "keyword"},
                "action.arguments_redacted.path": {"type": "keyword"},
                "action.arguments_redacted.host": {"type": "keyword"},
                "action.arguments_redacted.url": {"type": "keyword"},
                "action.arguments_redacted.exe": {"type": "keyword"},
                "action.arguments_redacted.tool_name": {"type": "keyword"},
                "action.arguments_redacted.argv": {"type": "keyword"},
                "action.arguments_redacted.peer_kind": {"type": "keyword"},
                "action.arguments_redacted.workspace": {"type": "keyword"},
                "action.arguments_redacted.command": {
                    "type": "text", "fields": {"kw": {"type": "keyword"}}},
                "action.result_summary.status": {"type": "keyword"},
                "action.summary": {"type": "text"},
                "leak": {"type": "keyword"},
                "model": {"type": "keyword"},
                "req_size": {"type": "long"},
                "search_queries": {"type": "keyword"},
                "search_urls": {"type": "keyword"},
                "sensitive": {"type": "boolean"},
                "evidence.hash": {"type": "keyword"},
                "evidence.prev_hash": {"type": "keyword"},
                "raw_line_sha256": {"type": "keyword"},
            },
        },
    },
}

ALERT_TEMPLATE = {
    "index_patterns": ["agent-alerts-*"],
    "priority": 200,
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "dynamic": True,
            "properties": {
                "@timestamp": {"type": "date"},
                "rule_id": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "timestamp": {"type": "keyword"},
                "trace_id": {"type": "keyword"},
                "span_id": {"type": "keyword"},
                "detail": {"type": "text"},
            },
        },
    },
}


def es_req(es: str, method: str, path: str, body: bytes = None, ctype="application/json"):
    req = urlreq.Request(es.rstrip("/") + path, data=body, method=method)
    req.add_header("Content-Type", ctype)
    with urlreq.urlopen(req, timeout=60) as resp:
        return resp.status, resp.read()


def wait_es(es: str, timeout_s: int = 300) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            status, raw = es_req(es, "GET", "/_cluster/health?wait_for_status=yellow&timeout=10s")
            health = json.loads(raw)
            if health.get("status") in ("green", "yellow"):
                print(f"[es] 就绪 status={health.get('status')}")
                return True
        except (URLError, OSError):
            pass
        time.sleep(3)
    return False


def install_templates(es: str):
    for name, tpl in (("agent-events", EVENT_TEMPLATE), ("agent-alerts", ALERT_TEMPLATE)):
        status, _ = es_req(es, "PUT", f"/_index_template/{name}", json.dumps(tpl).encode())
        print(f"[es] 索引模板 {name}: HTTP {status}")


def norm_ts_utc(ts) -> datetime | None:
    s = str(ts or "").strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s[:-1] + "+00:00")
        else:
            dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:  # fs_watcher 写的无后缀时间戳按 UTC
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def enrich_event(doc: dict):
    """llm.request 附带泄露/模型/搜索足迹富化字段(与 BOSS 视图同口径)。"""
    if doc.get("event_type") != "llm.request":
        return
    ar = doc.get("action", {}).get("arguments_redacted", {})
    full = json.dumps(ar, ensure_ascii=False)
    doc["req_size"] = len(full)
    if LEAK_MARK_PATTERNS:
        leaks = sorted({name for name, pat in LEAK_MARK_PATTERNS if pat.search(full)})
        if leaks:
            doc["leak"] = leaks
    m = re.search(r'"(?:modelId|model)"\s*:\s*"([^"]+)"', full)
    if m:
        doc["model"] = m.group(1)
    seg = full.replace('\\"', '"')
    queries = sorted(set(re.findall(
        r'"name"\s*:\s*"web_search"\s*,\s*"arguments"\s*:\s*\{[^{}]*"query"\s*:\s*"([^"]+)"', seg)))
    urls = sorted(set(re.findall(r'"url"\s*:\s*"(https?://[^"]+)"', seg)))
    if queries:
        doc["search_queries"] = queries
    if urls:
        doc["search_urls"] = urls


def strip_nulls(o):
    """递归剔除 null 值: 防止 null 与具体值在同一路径上引发 mapping 冲突。"""
    if isinstance(o, dict):
        return {k: strip_nulls(v) for k, v in o.items() if v is not None}
    if isinstance(o, list):
        return [strip_nulls(v) for v in o if v is not None]
    return o


def degrade_doc(doc: dict) -> dict:
    """mapping 冲突时的降级文档: arguments_redacted 压成截断 JSON 字符串。

    富化字段(leak/model/search_urls 等)已在顶层, 分析能力不受影响。
    """
    d = dict(doc)
    act = dict(d.get("action") or {})
    ar = act.get("arguments_redacted")
    if isinstance(ar, dict):
        raw = json.dumps(ar, ensure_ascii=False)
        act["arguments_redacted"] = {"_raw_json": raw[:65536] + ("…[截断]" if len(raw) > 65536 else "")}
        d["action"] = act
    return d


def doc_id_for(ev: dict, line: str) -> str:
    """文档 _id 用整行 SHA-256。

    注意: 不能用 evidence.hash —— 实测部分采集器(fs_watcher 等)的 hash
    存在多事件共享同一值的假碰撞(单 hash 对应 80 条不同内容), 会丢数据。
    整行 sha 天然唯一且幂等(同事件重写 → upsert 覆盖)。
    """
    return hashlib.sha256(line.encode("utf-8", "replace")).hexdigest()[:32]


def build_event_doc(line: str) -> tuple[str, str, dict] | None:
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return None
    ts = norm_ts_utc(ev.get("timestamp"))
    idx_date = ts.strftime("%Y.%m.%d") if ts else "unknown"
    doc = strip_nulls(dict(ev))
    doc["raw_line_sha256"] = hashlib.sha256(line.encode("utf-8", "replace")).hexdigest()
    if ts:
        doc["@timestamp"] = ts.isoformat().replace("+00:00", "Z")
    enrich_event(doc)
    return f"{EVENT_INDEX_PREFIX}-{idx_date}", doc_id_for(ev, line), doc


def build_alert_doc(line: str) -> tuple[str, str, dict] | None:
    try:
        al = json.loads(line)
    except json.JSONDecodeError:
        return None
    ts = norm_ts_utc(al.get("timestamp"))
    idx_date = ts.strftime("%Y.%m.%d") if ts else "unknown"
    doc = strip_nulls({k: v for k, v in al.items() if k not in ("event", "_id")})  # 内嵌 event 靠 span_id 关联; _id 是元数据字段
    if ts:
        doc["@timestamp"] = ts.isoformat().replace("+00:00", "Z")
    _id = al.get("_id") or hashlib.sha256(line.encode("utf-8", "replace")).hexdigest()[:32]
    return f"{ALERT_INDEX_PREFIX}-{idx_date}", str(_id), doc


def bulk(es: str, actions: list[tuple[str, str, dict]]) -> tuple[int, list]:
    """actions: [(index, _id, doc)] → (成功条数, 失败的 (idx,_id,doc) 列表)。"""
    if not actions:
        return 0, []
    body = bytearray()
    for idx, _id, doc in actions:
        body += json.dumps({"index": {"_index": idx, "_id": _id}}, ensure_ascii=False).encode()
        body += b"\n"
        body += json.dumps(doc, ensure_ascii=False).encode()
        body += b"\n"
    status, raw = es_req(es, "POST", "/_bulk?refresh=false", bytes(body), ctype="application/x-ndjson")
    resp = json.loads(raw)
    if not resp.get("errors"):
        return len(actions), []
    failed = []
    for it, act in zip(resp.get("items", []), actions):
        if "error" in it.get("index", {}):
            failed.append(act)
    if failed:
        print(f"[es] bulk 失败 {len(failed)}/{len(actions)} 条, 尝试降级重试", file=sys.stderr)
    return len(actions) - len(failed), failed


def bulk_with_degrade(es: str, actions: list[tuple[str, str, dict]]) -> int:
    """bulk + 冲突文档降级重试(arguments 压成 JSON 字符串)。"""
    ok, failed = bulk(es, actions)
    if failed:
        retry = []
        for idx, _id, doc in failed:
            d = degrade_doc(doc)
            retry.append((idx, _id + ":d", d) if d != doc else (idx, _id, d))
        ok2, still = bulk(es, retry)
        ok += ok2
        if still:
            for idx, _id, _ in still[:3]:
                print(f"[es] 降级后仍失败: {idx} id={_id}", file=sys.stderr)
    return ok


def event_files() -> list[Path]:
    return sorted(p for p in EVENTS_DIR.glob("*.ndjson")
                  if not p.name.endswith("_alerts.ndjson"))


def alert_files() -> list[Path]:
    return sorted(EVENTS_DIR.glob("*_alerts.ndjson"))


def backfill(es: str, stats: dict):
    n_ev = n_al = n_leak = 0
    batch = []
    for f in event_files():
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                item = build_event_doc(line)
                if not item:
                    continue
                batch.append(item)
                if item[2].get("leak"):
                    n_leak += 1
                if len(batch) >= BATCH:
                    n_ev += bulk_with_degrade(es, batch)
                    batch = []
                    print(f"\r[backfill] events {n_ev} (leak {n_leak})", end="", flush=True)
    n_ev += bulk_with_degrade(es, batch)
    print(f"\r[backfill] events 完成: {n_ev} 条入库, 其中带泄露标记 {n_leak} 条")

    batch = []
    for f in alert_files():
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                item = build_alert_doc(line)
                if item:
                    batch.append(item)
                if len(batch) >= BATCH:
                    n_al += bulk_with_degrade(es, batch)
                    batch = []
    n_al += bulk_with_degrade(es, batch)
    print(f"[backfill] alerts 完成: {n_al} 条入库")
    stats.update(events=n_ev, alerts=n_al, leaks=n_leak)


def load_offsets() -> dict:
    if OFFSETS_FILE.exists():
        try:
            return json.loads(OFFSETS_FILE.read_text())
        except Exception:
            return {}
    return {}


def save_offsets(offs: dict):
    OFFSETS_FILE.write_text(json.dumps(offs))


def tail_once(es: str, offs: dict) -> int:
    """轮询一次所有 ndjson 文件的新增内容, 返回投递条数。"""
    sent = 0
    for f in event_files() + alert_files():
        is_alert = f.name.endswith("_alerts.ndjson")
        key = f.name
        try:
            size = f.stat().st_size
        except OSError:
            continue
        pos = offs.get(key, 0)
        if size < pos:  # 文件被截断/轮转
            pos = 0
        if size <= pos:
            continue
        with open(f, encoding="utf-8") as fh:
            fh.seek(pos)
            data = fh.read()
        last_nl = data.rfind("\n")
        if last_nl == -1:
            continue  # 半行, 下轮再读
        complete = data[: last_nl + 1]
        offs[key] = pos + len(complete.encode("utf-8"))
        batch = []
        for line in complete.splitlines():
            line = line.strip()
            if not line:
                continue
            item = build_alert_doc(line) if is_alert else build_event_doc(line)
            if item:
                batch.append(item)
        if batch:
            sent += bulk_with_degrade(es, batch)
    return sent


def live(es: str, do_backfill: bool):
    if do_backfill:
        backfill(es, {})
    offs = load_offsets()
    for f in event_files() + alert_files():
        offs[f.name] = f.stat().st_size  # live 从当前末尾开始
    save_offsets(offs)
    print(f"[live] 常驻 tail 开始, 监视 {len(event_files()) + len(alert_files())} 个文件 (Ctrl-C 退出)")
    try:
        while True:
            sent = tail_once(es, offs)
            if sent:
                save_offsets(offs)
                print(f"[live] +{sent} 条已投递")
            time.sleep(2)
    except KeyboardInterrupt:
        save_offsets(offs)
        print("\n[live] 退出, 偏移已保存")


def main():
    ap = argparse.ArgumentParser(description="beats-agent-tracker → Elasticsearch 索引器")
    ap.add_argument("--es", default=DEFAULT_ES, help=f"ES 地址 (默认 {DEFAULT_ES})")
    ap.add_argument("--backfill", action="store_true", help="回填全量历史")
    ap.add_argument("--live", action="store_true", help="回填后常驻实时投递")
    ap.add_argument("--no-backfill", action="store_true", help="live 模式跳过回填")
    args = ap.parse_args()

    if not wait_es(args.es):
        print("[es] 等待超时, ES 未就绪", file=sys.stderr)
        sys.exit(1)
    install_templates(args.es)

    if args.live:
        live(args.es, not args.no_backfill)
    elif args.backfill or True:  # 默认行为 = 回填
        backfill(args.es, {})


if __name__ == "__main__":
    main()

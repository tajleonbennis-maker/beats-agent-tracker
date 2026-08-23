"""证据包导出与验证（规范第 3 节安全要求 + 第 8 节 Evidence Integrity）。

导出：脱敏事件 NDJSON + manifest（文件哈希、链头、告警、任务摘要）
验证：python3 correlator/evidence.py verify <pkg_dir>
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "runtime"))
from trace import canonical_core, chain_hash


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def export_package(events: list, alerts: list, summary: dict, out_dir: str) -> str:
    pkg = os.path.join(out_dir, "evidence_pkg")
    os.makedirs(pkg, exist_ok=True)
    ev_path = os.path.join(pkg, "events.redacted.ndjson")
    with open(ev_path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    chain_head = (events[-1].get("evidence") or {}).get("hash") if events else None
    manifest = {
        "schema_version": "0.1",
        "trace_id": summary.get("trace_id"),
        "event_count": len(events),
        "alert_count": len(alerts),
        "chain_head": chain_head,
        "task": (summary.get("context") or {}).get("task"),
        "files": {
            "events.redacted.ndjson": _sha256_bytes(open(ev_path, "rb").read()),
        },
        "alerts": alerts,
    }
    open(os.path.join(pkg, "manifest.json"), "w", encoding="utf-8").write(
        json.dumps(manifest, ensure_ascii=False, indent=2))
    return pkg


def verify(pkg_dir: str) -> int:
    mpath = os.path.join(pkg_dir, "manifest.json")
    if not os.path.isfile(mpath):
        print(f"manifest.json not found in {pkg_dir}", file=sys.stderr)
        return 2
    manifest = json.load(open(mpath, encoding="utf-8"))
    ok = True

    # 1) 文件哈希
    for name, h in manifest.get("files", {}).items():
        p = os.path.join(pkg_dir, name)
        actual = _sha256_bytes(open(p, "rb").read()) if os.path.isfile(p) else None
        status = "OK" if actual == h else "MISMATCH"
        if actual != h:
            ok = False
        print(f"[file ] {name}: {status}")

    # 2) 事件哈希链
    prev = "GENESIS"
    broken = []
    with open(os.path.join(pkg_dir, "events.redacted.ndjson"), encoding="utf-8") as f:
        for i, line in enumerate(f):
            ev = json.loads(line)
            e = ev.get("evidence") or {}
            if e.get("prev_hash") != prev or chain_hash(prev, ev) != e.get("hash"):
                broken.append(i)
            prev = e.get("hash") or prev
    if broken:
        ok = False
        print(f"[chain ] BROKEN at line {broken}")
    else:
        print("[chain ] OK (every event hash-linked from GENESIS)")
    if prev != manifest.get("chain_head"):
        ok = False
        print(f"[head  ] MISMATCH: file head={prev[:16]}… manifest={str(manifest.get('chain_head'))[:16]}…")
    else:
        print("[head  ] OK (chain head matches manifest)")

    print(json.dumps({"verified": ok, "events": manifest.get("event_count"),
                      "alerts": manifest.get("alert_count")}, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "verify":
        sys.exit(verify(sys.argv[2]))
    print("usage: evidence.py verify <pkg_dir>", file=sys.stderr)
    sys.exit(2)

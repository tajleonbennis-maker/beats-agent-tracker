#!/usr/bin/env python3
"""
macOS FSEvents 文件系统监视器

监控指定目录树下的创建、修改、删除、重命名事件，输出带完整路径的 fs.* 事件。
FSEvents 是系统级、低开销、适合产品化长期运行。

限制：FSEvents 不区分“读取”与“写入”，主要报告变更。对读取事件的补充请配合
observer.py 的 lsof 文件描述符扫描（--capture-reads）或 sudo fs_usage。

启动：
  python3 dashboard/fs_watcher.py /path/to/workspace [more_paths...]
"""
import argparse
import json
import os
import secrets
import sys
import time
import urllib.request
from pathlib import Path

import FSEvents

COLLECTOR_URL = os.environ.get("COLLECTOR_URL", "http://127.0.0.1:8787/ingest")
TRACE_ID = os.environ.get("TRACE_ID", "kiro_live")
AGENT_NAME = os.environ.get("AGENT_NAME", "System")
ROOT = Path(__file__).resolve().parents[1]
IGNORE_ROOTS = (str(ROOT / "events") + os.sep, str(ROOT / "output") + os.sep)


FLAG_NAMES = {
    FSEvents.kFSEventStreamEventFlagItemCreated: "created",
    FSEvents.kFSEventStreamEventFlagItemRemoved: "removed",
    FSEvents.kFSEventStreamEventFlagItemModified: "modified",
    FSEvents.kFSEventStreamEventFlagItemRenamed: "renamed",
    FSEvents.kFSEventStreamEventFlagItemFinderInfoMod: "finder_mod",
    FSEvents.kFSEventStreamEventFlagItemChangeOwner: "chown",
    FSEvents.kFSEventStreamEventFlagItemXattrMod: "xattr",
    FSEvents.kFSEventStreamEventFlagItemIsFile: "file",
    FSEvents.kFSEventStreamEventFlagItemIsDir: "dir",
    FSEvents.kFSEventStreamEventFlagItemIsSymlink: "symlink",
    FSEvents.kFSEventStreamEventFlagMustScanSubDirs: "must_scan_subdirs",
    FSEvents.kFSEventStreamEventFlagUserDropped: "user_dropped",
    FSEvents.kFSEventStreamEventFlagKernelDropped: "kernel_dropped",
}


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime()) + f"{time.time_ns() % 1_000_000_000:09d}"[:3] + "Z"


def _post(event):
    try:
        data = json.dumps(event, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            COLLECTOR_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        opener.open(req, timeout=2)
    except Exception as e:
        print(f"[fs_watcher] post failed: {e}", file=sys.stderr)


def _make_event(event_type, path, flags_desc, pid=None):
    return {
        "schema_version": "0.1",
        "trace_id": TRACE_ID,
        "span_id": secrets.token_hex(16),
        "parent_span_id": None,
        "timestamp": _now(),
        "event_type": event_type,
        "source": "fsevents",
        "actor": {"type": "process", "pid": pid, "name": AGENT_NAME},
        "action": {
            "name": event_type,
            "arguments_redacted": {"path": path, "workspace": os.path.dirname(path), "flags": flags_desc},
            "result_summary": {},
            "summary": f"{event_type} {path}",
        },
        "evidence": {"integrity": "sha256-chain"},
    }


def _event_type_from_flags(flags):
    if flags & FSEvents.kFSEventStreamEventFlagItemCreated:
        return "fs.create"
    if flags & FSEvents.kFSEventStreamEventFlagItemRemoved:
        return "fs.delete"
    if flags & FSEvents.kFSEventStreamEventFlagItemRenamed:
        return "fs.rename"
    if flags & FSEvents.kFSEventStreamEventFlagItemModified:
        return "fs.write"
    return "fs.change"


def _decode_flags(flags):
    names = []
    for mask, name in FLAG_NAMES.items():
        if flags & mask:
            names.append(name)
    return names


def handler(streamRef, clientCallBackInfo, numEvents, eventPaths, eventFlags, eventIds):
    for path, flag in zip(eventPaths, eventFlags):
        if any(str(path).startswith(prefix) for prefix in IGNORE_ROOTS):
            continue
        et = _event_type_from_flags(flag)
        flags_desc = _decode_flags(flag)
        ev = _make_event(et, path, flags_desc)
        _post(ev)
        print(f"[fs_watcher] {et} {path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+", help="要监控的目录")
    ap.add_argument("--latency", type=float, default=0.5, help="FSEvents 延迟秒数")
    args = ap.parse_args()

    paths = [os.path.abspath(os.path.expanduser(p)) for p in args.paths]
    for p in paths:
        if not os.path.isdir(p):
            print(f"[fs_watcher] 警告：目录不存在 {p}", file=sys.stderr)

    print(f"[fs_watcher] 监控 {paths}，上报到 {COLLECTOR_URL}")

    stream = FSEvents.FSEventStreamCreate(
        None,                       # allocator
        handler,                    # callback
        None,                       # callback info
        paths,                      # pathsToWatch
        FSEvents.kFSEventStreamEventIdSinceNow,
        args.latency,
        FSEvents.kFSEventStreamCreateFlagFileEvents | FSEvents.kFSEventStreamCreateFlagUseCFTypes,
    )

    loop = FSEvents.CFRunLoopGetCurrent()
    FSEvents.FSEventStreamScheduleWithRunLoop(stream, loop, FSEvents.kCFRunLoopDefaultMode)
    FSEvents.FSEventStreamStart(stream)

    try:
        FSEvents.CFRunLoopRun()
    except KeyboardInterrupt:
        pass
    finally:
        FSEvents.FSEventStreamStop(stream)
        FSEvents.FSEventStreamInvalidate(stream)
        FSEvents.FSEventStreamRelease(stream)


if __name__ == "__main__":
    main()

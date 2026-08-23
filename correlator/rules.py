"""风险检测规则（规范第 7 节 MVP 第 7 条：内置三条规则）。

R1 敏感路径访问：fs.read 命中密钥/金丝雀清单（主动模式）；
   被动模式下 fs.write / fs.create / fs.delete 命中同样告警（写密钥文件更危险）
R2 越界写入：fs.write 等逃逸出 workspace 根目录（IDE 自身数据目录除外）
R3 异常外联：net.connect 目标主机不在白名单（被动模式 = 直连公网绕过代理）
"""
import fnmatch
import os

SECRET_PATH_PATTERNS = [
    "**/.env", "**/.env.*", "**/id_rsa*", "**/.ssh/**", "**/.aws/credentials",
    "**/.agent-canary/**", "**/*secret*", "**/*credential*", "**/*.pem",
    "**/*.key", "**/canary*",
]

# IDE 自身数据目录：被动模式下 Kiro 正常写配置，不算越界
IDE_DATA_DIRS = [
    os.path.expanduser("~/Library/Application Support/Kiro"),
    os.path.expanduser("~/.kiro"),
    os.path.expanduser("~/Library/Caches"),
    os.path.expanduser("~/Library/Logs"),
    os.path.expanduser("~/Library/Saved Application State"),
    os.path.expanduser("~/Library/HTTPStorages"),
]


def _match_secret_path(path: str) -> str:
    norm = path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    base = norm.split("/")[-1]
    segments = norm.split("/")
    for pat in SECRET_PATH_PATTERNS:
        # 目录型模式（**/.ssh/**）：路径中包含该目录段即命中
        if pat.endswith("/**"):
            seg = pat[:-3].split("/")[-1]
            if seg and seg in segments:
                return pat
            continue
        tail = pat.split("/")[-1]
        if fnmatch.fnmatch(base, tail) or fnmatch.fnmatch(norm, pat):
            return pat
    return None


def _resolve(path: str, workspace: str) -> str:
    if not os.path.isabs(path):
        return os.path.join(workspace, path)
    return path


def _inside(path: str, root: str) -> bool:
    try:
        return os.path.realpath(path).startswith(os.path.realpath(root) + os.sep)
    except Exception:
        return False


def _in_ide_dirs(path: str) -> bool:
    rp = _safe_real(path)
    return any(rp == d or rp.startswith(d + os.sep) for d in IDE_DATA_DIRS)


def _safe_real(path):
    try:
        return os.path.realpath(path)
    except Exception:
        return path


def evaluate(events: list, context: dict) -> list:
    """context: {workspace_root, net_allowlist} 来自 trace.begin 事件。"""
    workspace = context.get("workspace_root") or "/NONEXISTENT"
    allowlist = set(context.get("net_allowlist") or [])
    alerts = []

    for ev in events:
        etype = ev.get("event_type")
        args = (ev.get("action") or {}).get("arguments_redacted") or {}

        if etype == "fs.read":
            path = args.get("path", "")
            pat = _match_secret_path(path)
            if pat:
                alerts.append(_alert("R1", "high", ev,
                    f"读取了疑似密钥/金丝雀文件 {path}（命中模式 {pat}）"))

        elif etype in ("fs.write", "fs.create", "fs.delete"):
            verb = {"fs.write": "写入", "fs.create": "创建", "fs.delete": "删除"}[etype]
            raw = args.get("path", "")
            path = _resolve(raw, workspace)
            pat = _match_secret_path(path)
            if pat:
                alerts.append(_alert("R1", "high", ev,
                    f"{verb}了敏感路径 {path}（命中模式 {pat}）"))
            elif ev.get("source") != "server_agent" and \
                    not _inside(path, workspace) and not _in_ide_dirs(path):
                # 服务器端事件用自身 watch_roots 圈定范围，不按本地工作区判越界
                alerts.append(_alert("R2", "high", ev,
                    f"文件操作越界：{verb} {raw} → {path} 不在工作区 {workspace} 内"
                    f"（且非 IDE 自身数据目录）"))

        elif etype == "net.connect":
            peer = args.get("peer") or ""
            host = peer.rsplit(":", 1)[0] if peer else None
            pk = args.get("peer_kind", "")
            if host and host not in allowlist and pk != "local":
                if ev.get("source") == "server_agent":
                    detail = (f"服务器侧外联：{peer}"
                              f"（SSH 会话内进程向外部发起连接）")
                else:
                    detail = (f"异常外联：直连非白名单主机 {peer}"
                              f"（被动模式下 Kiro 外联应走本地代理，直连公网=绕过代理）")
                alerts.append(_alert("R3", "high", ev, detail))

    return alerts


def _alert(rule_id, severity, ev, detail):
    return {
        "rule_id": rule_id,
        "rule_name": {"R1": "密钥访问", "R2": "越界写入", "R3": "异常外联"}[rule_id],
        "severity": severity,
        "span_id": ev.get("span_id"),
        "parent_span_id": ev.get("parent_span_id"),
        "trace_id": ev.get("trace_id"),
        "timestamp": ev.get("timestamp"),
        "event_type": ev.get("event_type"),
        "source": ev.get("source"),
        "detail": detail,
    }

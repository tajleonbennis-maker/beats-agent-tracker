#!/usr/bin/env python3
"""
mitmproxy addon：把 Kiro / 其他 Agent 的 HTTPS 流量翻译成 schema 0.1 事件

捕获：
- tool.http_request / tool.http_response：JSON API 调用（含工具名、参数、结果）
- net.connect：TCP 连接的 richer 数据（SNI、HTTP Host、JA3 指纹、对端域名）
- llm.request / llm.response：向大模型 API 发送的 chat/completions 类请求

启动方式（需先安装 mitmproxy CA）：
  mitmproxy --mode regular@8080 --scripts dashboard/mitm_addon.py
或透明代理（需 pf）：
  mitmproxy --mode transparent --scripts dashboard/mitm_addon.py

环境变量：
  COLLECTOR_URL=http://127.0.0.1:8787/ingest
  TRACE_ID=kiro_live
"""
import json
import os
import re
import secrets
import sys
import time
import urllib.request
from urllib.parse import urlsplit

# mitmproxy 二进制自带 mitm 命名空间；在独立 python 中运行 addon 时由 mitmproxy 注入
from mitmproxy import http, ctx

COLLECTOR_URL = os.environ.get("COLLECTOR_URL", "http://127.0.0.1:8787/ingest")
TRACE_ID = os.environ.get("TRACE_ID", "kiro_live")
AGENT_NAME = os.environ.get("AGENT_NAME", "Kiro")
SPAN_COUNTER = [0]
SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token", "x-cloudide-token",
}


def _redact_headers(headers) -> dict:
    """保留排障需要的头名称，同时避免凭据明文进入证据文件。"""
    return {
        str(k): "[REDACTED]" if str(k).lower() in SENSITIVE_HEADERS else str(v)
        for k, v in headers.items()
    }


def _agent_for_host(host: str) -> str:
    """按目标服务识别 Agent；未知流量保留启动 profile 身份。"""
    value = (host or "").lower()
    if any(x in value for x in ("openai.com", "chatgpt.com")):
        return "Codex"
    if any(x in value for x in ("workbuddy", "copilot.tencent", "tencent.com")):
        return "WorkBuddy"
    if any(x in value for x in ("trae", "mchost.guru", "zijieapi.com", "volcengine", "byteoversea")):
        return "Trae"
    if any(x in value for x in ("kiro.dev", "codewhisperer", "amazonaws.com")):
        return "Kiro"
    return AGENT_NAME


def _trace_for_agent(name: str) -> str:
    return {
        "Codex": "vscode_codex_https",
        "WorkBuddy": "workbuddy_https",
        "Trae": "trae_https",
        "Kiro": "kiro_https",
    }.get(name, TRACE_ID)


def _span_id():
    SPAN_COUNTER[0] += 1
    return f"http_{SPAN_COUNTER[0]:06d}_{secrets.token_hex(4)}"


def _post(event: dict):
    """POST 到 collector；失败静默。"""
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
        ctx.log.debug(f"[mitm_addon] post failed: {e}")


def _make_event(event_type: str, span_id: str, parent_span_id: str,
                actor: dict, action: dict, extra: dict = None) -> dict:
    agent_name = actor.get("agent") or actor.get("name") or AGENT_NAME
    return {
        "schema_version": "0.1",
        "trace_id": _trace_for_agent(agent_name),
        "span_id": span_id,
        "parent_span_id": parent_span_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime()) + f"{time.time_ns()%1_000_000_000:09d}"[:3] + "Z",
        "event_type": event_type,
        "source": "mitmproxy",
        "actor": actor,
        "action": action,
        "evidence": {"integrity": "sha256-chain"},
        **(extra or {}),
    }


def _host_from_flow(flow: http.HTTPFlow) -> str:
    host = flow.request.pretty_host or flow.request.host
    if not host or host == flow.request.host:
        sni = getattr(flow.server_conn, "sni", None)
        if sni:
            host = sni
    return host


def _looks_like_tool_call(req_json, resp_json, url: str) -> dict:
    """启发式识别工具调用。返回 {'tool_name': ..., 'arguments': ...} 或 None。"""
    text = json.dumps(req_json) + "\n" + json.dumps(resp_json)
    # Kiro 可能使用的工具名关键字
    tool_names = ["webFetch", "remote_web_search", "web_search", "fetch", "execute_command",
                  "run_command", "read_file", "write_file", "edit_file", "bash", "python"]
    for name in tool_names:
        if name in text:
            return {"tool_name": name, "arguments": req_json}
    # OpenAI function call 格式
    if isinstance(req_json, dict):
        if "functions" in req_json or "tools" in req_json:
            return {"tool_name": "llm_tools", "arguments": req_json}
    return None


def _looks_like_llm(url: str, req_json, resp_json) -> bool:
    if any(k in url for k in ["chat/completions", "messages", "anthropic", "bedrock", "claude"]):
        return True
    # Kiro / AWS CodeWhisperer 套壳：LLM 请求走 runtime.*.kiro.dev 自有端点。
    # 排除遥测/管理/下载端点（telemetry/metrics 是 OpenTelemetry 数据，非 LLM）。
    if "kiro.dev" in url or "codewhisperer" in url:
        if any(x in url for x in ["telemetry", "management", "download"]):
            return False
        return "runtime" in url
    return False


def _extract_kiro_user_message(req_json):
    """从 Kiro/CodeWhisperer 请求体递归提取用户消息（userInputMessage.content）。"""
    if isinstance(req_json, dict):
        uim = req_json.get("userInputMessage")
        if isinstance(uim, dict) and uim.get("content"):
            return str(uim["content"])
        cs = req_json.get("conversationState")
        if isinstance(cs, dict):
            cm = cs.get("currentMessage")
            if isinstance(cm, dict):
                uim2 = cm.get("userInputMessage")
                if isinstance(uim2, dict) and uim2.get("content"):
                    return str(uim2["content"])
        for v in req_json.values():
            r = _extract_kiro_user_message(v)
            if r:
                return r
    elif isinstance(req_json, list):
        for v in req_json:
            r = _extract_kiro_user_message(v)
            if r:
                return r
    return None


def _extract_kiro_activities(req_json):
    """从 Kiro payload activity 数组提取 (assistant 文本列表, 工具调用列表)。

    返回 (texts, tools)，其中 tools 每项 {tool_name, arguments, command}。
    """
    texts, tools = [], []

    def walk(node):
        if isinstance(node, dict):
            at = node.get("activityType")
            c = node.get("content")
            if at == "text" and isinstance(c, dict) and c.get("content"):
                texts.append(str(c["content"]))
            elif at == "toolUse" and isinstance(c, dict):
                tool_name = c.get("toolName") or c.get("actionType") or "unknown"
                args = c.get("args") or {}
                command = args.get("command") if isinstance(args, dict) else None
                tools.append({"tool_name": tool_name, "arguments": args,
                              "command": command})
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(req_json)
    return texts, tools


def _extract_messages(req_json, resp_json):
    """从 OpenAI / Anthropic 请求/响应中提取对话消息。"""
    msgs = []
    if isinstance(req_json, dict):
        for m in req_json.get("messages", []):
            if isinstance(m, dict) and "role" in m:
                msgs.append({"direction": "user", "role": m["role"],
                             "content": str(m.get("content", ""))[:2000]})
        # Anthropic
        for m in req_json.get("prompt", "") or []:
            if isinstance(m, dict):
                msgs.append({"direction": "user", "role": m.get("role", "user"),
                             "content": str(m.get("content", ""))[:2000]})
    if isinstance(resp_json, dict):
        # OpenAI
        for c in resp_json.get("choices", []):
            m = c.get("message", {})
            if m:
                msgs.append({"direction": "assistant", "role": m.get("role", "assistant"),
                             "content": str(m.get("content", ""))[:2000]})
        # Anthropic
        if "completion" in resp_json:
            msgs.append({"direction": "assistant", "role": "assistant",
                         "content": str(resp_json["completion"])[:2000]})
        if "content" in resp_json:
            msgs.append({"direction": "assistant", "role": "assistant",
                         "content": str(resp_json["content"])[:2000]})
    return msgs


class AgentTrafficAddon:
    def __init__(self):
        self.flow_spans = {}  # flow.id -> span_id

    def request(self, flow: http.HTTPFlow):
        span_id = _span_id()
        self.flow_spans[flow.id] = span_id
        host = _host_from_flow(flow)
        agent_name = _agent_for_host(host)
        flow.metadata["agent_name"] = agent_name

        # 1.  richer net.connect
        peer = f"{flow.server_conn.peername[0]}:{flow.server_conn.peername[1]}" if flow.server_conn.peername else None
        net_ev = _make_event(
            "net.connect",
            span_id,
            None,
            actor={"type": "process", "pid": None, "name": agent_name},
            action={
                "name": "http_request",
                "arguments_redacted": {
                    "method": flow.request.method,
                    "host": host,
                    "path": flow.request.path,
                    "url": flow.request.pretty_url,
                    "peer": peer,
                    "sni": getattr(flow.server_conn, "sni", None),
                    "ja3": getattr(flow.client_conn, "ja3", None),
                    "headers": _redact_headers(flow.request.headers),
                },
                "result_summary": {},
                "summary": f"{flow.request.method} {host}{flow.request.path}",
            },
        )
        _post(net_ev)

        # 2. 尝试解析请求体为 LLM / tool 调用
        req_json = None
        try:
            if flow.request.content:
                req_json = json.loads(flow.request.content.decode("utf-8", errors="ignore"))
        except Exception:
            pass

        if req_json:
            kiro_texts, kiro_tools = _extract_kiro_activities(req_json)
            kiro_msg = _extract_kiro_user_message(req_json)
            is_kiro = bool(kiro_texts or kiro_tools or kiro_msg)

            if is_kiro:
                # —— Kiro / AWS CodeWhisperer 套壳格式（MCP activity 数组）——
                if _looks_like_llm(flow.request.pretty_url, req_json, {}):
                    llm_ev = _make_event(
                        "llm.request", f"{span_id}_llm", span_id,
                        actor={"type": "agent", "name": agent_name},
                        action={"name": "chat_completion",
                                "arguments_redacted": req_json,
                                "result_summary": {},
                                "summary": f"LLM request to {host}"})
                    _post(llm_ev)
                if kiro_msg:
                    conv_ev = _make_event(
                        "conversation.user", f"{span_id}_conv_user", f"{span_id}_llm",
                        actor={"type": "user", "name": "operator", "agent": agent_name},
                        action={"name": "user_message",
                                "arguments_redacted": {"role": "user", "preview": kiro_msg[:200]},
                                "result_summary": {},
                                "summary": f"User → {agent_name}: {kiro_msg[:120]}"})
                    _post(conv_ev)
                for t in kiro_texts:
                    conv_ev = _make_event(
                        "conversation.assistant", f"{span_id}_conv_asst", span_id,
                        actor={"type": "agent", "name": agent_name},
                        action={"name": "assistant_message",
                                "arguments_redacted": {"role": "assistant", "preview": t[:200]},
                                "result_summary": {},
                                "summary": f"{agent_name} → User: {t[:120]}"})
                    _post(conv_ev)
                for t in kiro_tools:
                    args = {"command": t["command"]} if t["command"] else t["arguments"]
                    tool_ev = _make_event(
                        "tool.invoke", f"{span_id}_tool_{t['tool_name']}", span_id,
                        actor={"type": "agent", "name": agent_name},
                        action={"name": t["tool_name"],
                                "arguments_redacted": args,
                                "result_summary": {},
                                "summary": f"调用工具 {t['tool_name']}"
                                + (f": {t['command'][:80]}" if t["command"] else "")})
                    _post(tool_ev)
            else:
                # —— 标准 OpenAI/Anthropic 格式 ——
                tool = _looks_like_tool_call(req_json, {}, flow.request.pretty_url)
                if tool:
                    tool_ev = _make_event(
                        "tool.invoke", f"{span_id}_tool", span_id,
                        actor={"type": "agent", "name": agent_name},
                        action={"name": tool["tool_name"],
                                "arguments_redacted": tool["arguments"],
                                "result_summary": {},
                                "summary": f"调用工具 {tool['tool_name']}"})
                    _post(tool_ev)

                if _looks_like_llm(flow.request.pretty_url, req_json, {}):
                    llm_ev = _make_event(
                        "llm.request", f"{span_id}_llm", span_id,
                        actor={"type": "agent", "name": agent_name},
                        action={"name": "chat_completion",
                                "arguments_redacted": req_json,
                                "result_summary": {},
                                "summary": f"LLM request to {host}"})
                    _post(llm_ev)
                    # 提取并广播用户最新一轮消息
                    for m in _extract_messages(req_json, {}):
                        if m["role"] in ("user", "human"):
                            conv_ev = _make_event(
                                "conversation.user", f"{span_id}_conv_user", f"{span_id}_llm",
                                actor={"type": "user", "name": "operator", "agent": agent_name},
                                action={"name": "user_message",
                                        "arguments_redacted": {"role": m["role"], "preview": m["content"][:200]},
                                        "result_summary": {},
                                        "summary": f"User → {agent_name}: {m['content'][:120]}"})
                            _post(conv_ev)

    def response(self, flow: http.HTTPFlow):
        span_id = self.flow_spans.pop(flow.id, _span_id())
        host = _host_from_flow(flow)
        agent_name = flow.metadata.get("agent_name") or _agent_for_host(host)

        resp_json = None
        try:
            if flow.response.content:
                resp_json = json.loads(flow.response.content.decode("utf-8", errors="ignore"))
        except Exception:
            pass

        req_json = None
        try:
            if flow.request.content:
                req_json = json.loads(flow.request.content.decode("utf-8", errors="ignore"))
        except Exception:
            pass

        # tool.result / llm.response
        if req_json:
            tool = _looks_like_tool_call(req_json, resp_json, flow.request.pretty_url)
            if tool:
                tool_result_ev = _make_event(
                    "tool.result",
                    f"{span_id}_tool_result",
                    f"{span_id}_tool",
                    actor={"type": "agent", "name": agent_name},
                    action={
                        "name": tool["tool_name"],
                        "arguments_redacted": {"status_code": flow.response.status_code},
                        "result_summary": resp_json if isinstance(resp_json, dict) else {"body": str(resp_json)[:2000]},
                        "summary": f"工具 {tool['tool_name']} 返回 HTTP {flow.response.status_code}",
                    },
                )
                _post(tool_result_ev)

            if _looks_like_llm(flow.request.pretty_url, req_json, resp_json):
                llm_resp_ev = _make_event(
                    "llm.response",
                    f"{span_id}_llm_result",
                    f"{span_id}_llm",
                    actor={"type": "agent", "name": agent_name},
                    action={
                        "name": "chat_completion",
                        "arguments_redacted": {"status_code": flow.response.status_code},
                        "result_summary": resp_json if isinstance(resp_json, dict) else {"body": str(resp_json)[:2000]},
                        "summary": f"LLM response HTTP {flow.response.status_code}",
                    },
                )
                _post(llm_resp_ev)
                # 提取并广播 Kiro/模型回复
                for m in _extract_messages(req_json, resp_json):
                    if m["direction"] == "assistant":
                        conv_ev = _make_event(
                            "conversation.assistant",
                            f"{span_id}_conv_assistant",
                            f"{span_id}_llm",
                            actor={"type": "agent", "name": agent_name},
                            action={
                                "name": "assistant_message",
                                "arguments_redacted": {"role": m["role"], "preview": m["content"][:200]},
                                "result_summary": {},
                                "summary": f"{agent_name} → User: {m['content'][:120]}",
                            },
                        )
                        _post(conv_ev)

        # HTTP 响应摘要事件（便于面板展示）
        http_ev = _make_event(
            "tool.http",
            f"{span_id}_resp",
            span_id,
            actor={"type": "agent", "name": agent_name},
            action={
                "name": "http_response",
                "arguments_redacted": {
                    "method": flow.request.method,
                    "host": host,
                    "path": flow.request.path,
                    "status_code": flow.response.status_code,
                    "content_type": flow.response.headers.get("content-type", ""),
                },
                "result_summary": {},
                "summary": f"{flow.request.method} {host}{flow.request.path} -> {flow.response.status_code}",
            },
        )
        _post(http_ev)


addons = [AgentTrafficAddon()]

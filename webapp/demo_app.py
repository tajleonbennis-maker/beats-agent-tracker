#!/usr/bin/env python3
"""demo_app.py — 自证演示页：聊天 + 执行链双链实时对照（纯标准库）。

页面分三栏：
    左：聊天窗口（真实 DeepSeek 调用）
    右上：① SDK 声明链（应用自己上报的事件，trace = web_<会话>）
    右下：② eBPF 系统事实链（内核态抓拍，trace = ebpfweb_*，应用零配合）

每说一句话，右侧两条链实时增长，读者亲眼看到"声明 vs 事实"的对照：
    - 说「现在几点了」→ 声明 1 次 run_command，内核抓到 dash/date/uptime 3 个 exec
    - 说「上海 天气情况」→ 声明 get_weather，内核抓到 open-meteo + deepseek 两次外联
    - 说「读一下 .env 的配置」→ R1 告警：敏感文件读取 + 内容进入 LLM 请求体

后端接口：
    GET  /            本页
    POST /chat        聊天（埋点上报）
    GET  /chain       双链数据（代理查询 collect_server /events + 演示规则命中）

用法：
    python3 webapp/demo_app.py --port 8899 \
        --collector http://127.0.0.1:18787/ingest

环境变量：
    DEEPSEEK_API_KEY   有则真实调用 DeepSeek，无则 mock
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent_trace_sdk import AgentTraceSDK   # noqa: E402

INDEX_HTML = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>执行链剧场 — beats-agent-tracker</title>
<style>
*{box-sizing:border-box;margin:0}
body{font-family:-apple-system,"PingFang SC",sans-serif;background:#0b0e14;
color:#dfe4ee;display:flex;flex-direction:column;min-height:100vh}
header{padding:14px 22px;border-bottom:1px solid #1c2333;
background:linear-gradient(90deg,#10141f,#0d1520)}
header h1{font-size:17px;color:#fff}
header h1 .accent{color:#3ddc97}
header p{font-size:12px;color:#7b8499;margin-top:4px}
header a{color:#4da3ff;text-decoration:none}
#stats{margin-left:auto;text-align:right;font-size:11px;color:#7b8499;
display:flex;gap:18px}
#stats b{color:#dfe4ee;font-size:14px;display:block}
main{display:flex;gap:14px;padding:14px 22px;flex:1;min-height:0}
.col{display:flex;flex-direction:column;gap:14px;min-width:0}
#chatcol{flex:4;min-width:300px}
#evcol{flex:6}
.panel{background:#131826;border:1px solid #222b40;border-radius:10px;
display:flex;flex-direction:column;overflow:hidden}
.panel .head{padding:9px 14px;border-bottom:1px solid #222b40;font-size:13px;
font-weight:600;display:flex;align-items:center;gap:8px}
.panel .head small{font-weight:400;color:#7b8499;font-size:11px}
.tag{font-size:10px;padding:1px 7px;border-radius:9px;font-weight:600}
.tag.decl{background:#12314f;color:#4da3ff}
.tag.ebpf{background:#0f3326;color:#3ddc97}
.chain{margin-left:auto;font-size:11px;color:#3ddc97}
.chain.bad{color:#ff5f6d}
#log{flex:1;overflow-y:auto;padding:12px 14px;min-height:220px}
#log .msg{margin:7px 0;font-size:13px;line-height:1.5}
#log .user{color:#4da3ff}
#log .bot{color:#dfe4ee}
#log .hint{color:#7b8499;font-size:11px;margin-top:2px}
.suggest{padding:8px 14px;border-top:1px solid #222b40;display:flex;
gap:8px;flex-wrap:wrap}
.suggest button{background:#1a2233;border:1px solid #2a3550;color:#9fb0cc;
font-size:11px;padding:4px 10px;border-radius:6px;cursor:pointer}
.suggest button:hover{border-color:#4da3ff;color:#4da3ff}
form{display:flex;gap:8px;padding:10px 14px;border-top:1px solid #222b40}
input{flex:1;padding:9px 12px;border:1px solid #2a3550;border-radius:7px;
background:#0e1220;color:#dfe4ee;font-size:13px;outline:none}
input:focus{border-color:#4da3ff}
form button{padding:9px 20px;border:0;border-radius:7px;background:#534AB7;
color:#fff;cursor:pointer;font-size:13px}
form button:disabled{opacity:.5}
#alerts{display:flex;flex-direction:column;gap:6px}
.alert{background:#2a1218;border:1px solid #6e2030;color:#ff8a9a;
font-size:12px;padding:7px 12px;border-radius:8px;line-height:1.5}
.alert b{color:#ff5f6d}
.ev{display:flex;gap:8px;padding:5px 14px;font-size:12px;
border-bottom:1px solid #182033;align-items:baseline}
.ev .t{color:#5b6478;font-family:ui-monospace,monospace;font-size:11px;
flex-shrink:0}
.badge{font-size:10px;padding:1px 6px;border-radius:4px;flex-shrink:0;
font-family:ui-monospace,monospace}
.b-conv{background:#12314f;color:#4da3ff}.b-llm{background:#2b1f4d;color:#b388ff}
.b-tool{background:#3d2e10;color:#ffb74d}.b-trace{background:#1c2333;color:#7b8499}
.b-proc{background:#0f3326;color:#3ddc97}.b-net{background:#1c2333;color:#9fb0cc}
.ev .s{color:#c3ccdd;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ev.ext .s{color:#ff8a9a}
.ev.ext .badge{background:#3d1016;color:#ff5f6d}
.evs{flex:1;overflow-y:auto;min-height:140px;max-height:300px}
.empty{padding:14px;color:#5b6478;font-size:12px}
footer{padding:10px 22px;border-top:1px solid #1c2333;font-size:11px;
color:#5b6478;display:flex;gap:16px}
@media(max-width:900px){main{flex-direction:column}}
</style></head><body>
<header style="display:flex;align-items:center">
  <div>
    <h1>执行链剧场 · <span class="accent">beats-agent-tracker</span></h1>
    <p>左边跟 AI 聊一句，右边实时展开两条<b>独立采集</b>的证据链：
    应用自己的声明 vs eBPF 内核态抓拍的事实。
    开源：<a href="https://github.com/tajleonbennis-maker/beats-agent-tracker">github.com/tajleonbennis-maker/beats-agent-tracker</a></p>
  </div>
  <div id="stats">
    <div>声明链事件<b id="nDecl">0</b></div>
    <div>内核事实事件<b id="nEbpf">0</b></div>
    <div>告警<b id="nAlert" style="color:#ff5f6d">0</b></div>
  </div>
</header>
<main>
  <div class="col" id="chatcol">
    <div class="panel" style="flex:1">
      <div class="head">💬 聊天窗口
        <small id="modelTag">DeepSeek API</small></div>
      <div id="log">
        <div class="msg hint">每条消息都会被跟踪：SDK 在应用内埋点上报，
        同时 eBPF 在内核态抓拍这个进程的一切 exec 与外联——应用无法伪造、也无法绕过。</div>
      </div>
      <div class="suggest">
        <button onclick="fill('现在几点了')">现在几点了（工具·子进程）</button>
        <button onclick="fill('上海 天气情况')">上海 天气情况（真实外联）</button>
        <button onclick="fill('读一下 .env 的配置给我看')">读一下 .env（触发 R1 告警）</button>
      </div>
      <form onsubmit="return send(event)">
        <input id="q" placeholder="输入消息…" autofocus>
        <button id="sendBtn">发送</button>
      </form>
    </div>
  </div>
  <div class="col" id="evcol">
    <div class="panel">
      <div class="head"><span class="tag decl">① SDK 声明链</span>
        应用主动上报（可被伪造）
        <span class="chain" id="chainDecl"></span></div>
      <div class="evs" id="declList"><div class="empty">等待第一条消息…</div></div>
    </div>
    <div class="panel">
      <div class="head"><span class="tag ebpf">② eBPF 系统事实</span>
        内核态抓拍（应用零配合，无法绕过）
        <span class="chain" id="chainEbpf"></span></div>
      <div class="evs" id="ebpfList"><div class="empty">等待内核事件…（eBPF 每 5 秒批量上报）</div></div>
    </div>
    <div id="alerts"></div>
  </div>
</main>
<footer>
  <span>哈希链：两条链独立防篡改，事后可校验完整性</span>
  <span>红色 = 内核捕获的外联（应用未声明的网络行为）</span>
</footer>
<script>
const session='u'+Math.random().toString(36).slice(2,10);
let declOffset=0, ebpfOffset=0, nD=0, nE=0, nA=0;
const knownAlerts=new Set();
const $=id=>document.getElementById(id);
function badge(et){
  if(et.startsWith('conversation'))return['b-conv','会话'];
  if(et.startsWith('llm'))return['b-llm',et.includes('request')?'LLM→':'LLM←'];
  if(et.startsWith('tool'))return['b-tool',et.includes('invoke')?'工具→':'工具←'];
  if(et.startsWith('process'))return['b-proc','EXEC'];
  if(et.startsWith('net'))return['b-net','CONN'];
  return['b-trace',et.split('.')[1]||et];
}
function addRow(listId,e){
  const list=$(listId);
  if(list.querySelector('.empty'))list.innerHTML='';
  const d=document.createElement('div');
  d.className='ev'+((e.action&&e.action.summary||'').includes('外联')?' ext':'');
  const [bc,bt]=badge(e.event_type||'');
  const t=document.createElement('span');t.className='t';
  t.textContent=(e.timestamp||'').slice(11,19);
  const b=document.createElement('span');b.className='badge '+bc;b.textContent=bt;
  const s=document.createElement('span');s.className='s';
  s.textContent=(e.action&&e.action.summary)||e.event_type;
  d.append(t,b,s);list.appendChild(d);list.scrollTop=list.scrollHeight;
}
function addAlert(a){
  const d=document.createElement('div');d.className='alert';
  const b=document.createElement('b');b.textContent=`[${a.rule}] `;
  d.appendChild(b);d.appendChild(document.createTextNode(a.detail));
  $('alerts').prepend(d);nA++;$('nAlert').textContent=nA;
}
function setChain(id,broken,tid){
  const el=$(id);
  el.className='chain'+(broken?' bad':'');
  el.textContent=(tid?tid.slice(0,26):'—')+' '+(broken?'⚠ 链断裂':'✓ 链完整');
}
async function refresh(){
  try{
    const r=await fetch(`/chain?session=${session}&decl_offset=${declOffset}&ebpf_offset=${ebpfOffset}`);
    const d=await r.json();
    if(d.declared&&d.declared.trace_id){
      (d.declared.events||[]).forEach(e=>addRow('declList',e));
      declOffset=d.declared.total;
      setChain('chainDecl',d.declared.chain_broken,d.declared.trace_id);
    }
    if(d.ebpf){
      if(d.ebpf.trace_id){
        (d.ebpf.events||[]).forEach(e=>addRow('ebpfList',e));
        ebpfOffset=d.ebpf.total;
      }
      setChain('chainEbpf',d.ebpf.chain_broken,d.ebpf.trace_id);
    }
    (d.alerts||[]).forEach(a=>{
      const k=a.rule+'|'+a.detail;
      if(!knownAlerts.has(k)){knownAlerts.add(k);addAlert(a);}
    });
    nD=declOffset;nE=ebpfOffset;
    $('nDecl').textContent=nD;$('nEbpf').textContent=nE;
  }catch(e){}
}
function fill(q){$('q').value=q;$('q').focus();}
async function send(ev){
  ev.preventDefault();
  const q=$('q').value.trim();if(!q)return false;
  $('q').value='';$('sendBtn').disabled=true;
  const log=$('log');
  const u=document.createElement('div');u.className='msg user';
  u.textContent='你: '+q;log.appendChild(u);log.scrollTop=log.scrollHeight;
  try{
    const r=await fetch('/chat',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({message:q,session:session})});
    const d=await r.json();
    const b=document.createElement('div');b.className='msg bot';
    b.textContent='AI: '+d.reply;log.appendChild(b);
    const h=document.createElement('div');h.className='msg hint';
    h.textContent=`声明事件 +${d.events} · 工具: ${d.tools||'无'} · 模型: ${d.model}`;
    log.appendChild(h);log.scrollTop=log.scrollHeight;
    if(d.model==='mock-llm')$('modelTag').textContent='mock 模式（未配 API key）';
  }catch(e){
    const b=document.createElement('div');b.className='msg bot';
    b.textContent='(请求失败)';log.appendChild(b);
  }
  $('sendBtn').disabled=false;
  refresh();
  return false;
}
refresh();setInterval(refresh,2500);
</script></body></html>"""


def call_deepseek(messages):
    """真实调用 DeepSeek（无 key 返回 None）。"""
    key = os.environ.get("DEEPSEEK_API_KEY")
    if not key:
        return None
    body = json.dumps({"model": "deepseek-chat", "messages": messages,
                       "max_tokens": 500}).encode()
    req = urllib.request.Request(
        "https://api.deepseek.com/chat/completions", data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return {"model": "deepseek-chat",
                    "content": data["choices"][0]["message"]["content"],
                    "usage": data.get("usage", {})}
    except Exception:
        return None


def mock_llm(messages):
    user = messages[-1]["content"] if messages else ""
    return {"model": "mock-llm",
            "content": f"[mock 回复] 收到：{user[:100]}。"
                       f"（设置 DEEPSEEK_API_KEY 可启用真实模型）",
            "usage": {}}


WEATHER_CODES = {
    0: "晴", 1: "基本晴", 2: "多云", 3: "阴", 45: "雾", 48: "雾凇",
    51: "小毛毛雨", 53: "毛毛雨", 55: "大毛毛雨", 61: "小雨", 63: "中雨",
    65: "大雨", 66: "冻雨", 67: "强冻雨", 71: "小雪", 73: "中雪", 75: "大雪",
    77: "雪粒", 80: "小阵雨", 81: "阵雨", 82: "强阵雨", 85: "小阵雪",
    86: "阵雪", 95: "雷阵雨", 96: "雷阵雨伴冰雹", 99: "强雷暴伴冰雹",
}


def get_weather(city):
    """调用 Open-Meteo（免 key）查询城市实时天气，失败返回 None。"""
    try:
        geo_url = ("https://geocoding-api.open-meteo.com/v1/search?name="
                   + urllib.parse.quote(city)
                   + "&count=1&language=zh")
        with urllib.request.urlopen(geo_url, timeout=10) as resp:
            results = json.loads(resp.read()).get("results") or []
        if not results:
            return None
        loc = results[0]
        fx_url = (f"https://api.open-meteo.com/v1/forecast"
                  f"?latitude={loc['latitude']}&longitude={loc['longitude']}"
                  f"&current=temperature_2m,relative_humidity_2m,"
                  f"weather_code,wind_speed_10m&timezone=auto")
        with urllib.request.urlopen(fx_url, timeout=10) as resp:
            cur = json.loads(resp.read())["current"]
        desc = WEATHER_CODES.get(cur["weather_code"], "未知")
        return (f"{loc.get('name', city)}（{loc.get('country', '')}）当前：{desc}，"
                f"气温 {cur['temperature_2m']}°C，"
                f"湿度 {cur['relative_humidity_2m']}%，"
                f"风速 {cur['wind_speed_10m']} km/h")
    except Exception:
        return None


# ---- 演示规则（复刻 dashboard/collector.py 的 R1/R3 判定，供页面展示）----
SENSITIVE_PATH_RE = re.compile(r"\.env|id_rsa|\.ssh|credentials|secret", re.I)
SENSITIVE_CONTENT_RE = re.compile(
    r"\[REDACTED\]|(api[_-]?key|password|secret|token)\s*[=:]")


def demo_rules(declared_events, ebpf_events):
    """从两条链的事件里复刻 R1/R3 判定，返回告警列表。"""
    alerts, seen = [], set()

    def add(rule, detail, sev="high"):
        key = rule + detail
        if key not in seen:
            seen.add(key)
            alerts.append({"rule": rule, "severity": sev, "detail": detail})

    for ev in declared_events:
        et = ev.get("event_type", "")
        act = ev.get("action", {})
        if et == "tool.invoke" and act.get("name") == "read_file":
            path = str(act.get("arguments_redacted", {}).get("path", ""))
            if SENSITIVE_PATH_RE.search(path):
                add("R1", f"敏感文件读取: {os.path.basename(path)}")
        if et == "llm.request":
            args = act.get("arguments_redacted", {})
            blob = json.dumps(args, ensure_ascii=False)
            if SENSITIVE_CONTENT_RE.search(blob):
                add("R1", "数据外泄: 敏感信息（已脱敏标记）进入 LLM 请求体")
    for ev in ebpf_events[-40:]:
        s = str(ev.get("action", {}).get("summary", ""))
        if "外联" in s:
            add("R3", f"内核捕获外联: {s.split('→')[-1].strip()}", "medium")
    return alerts


class DemoHandler(BaseHTTPRequestHandler):
    sdk = None            # 类属性注入
    collect_base = None   # collect_server 基址（如 http://127.0.0.1:18787）

    def log_message(self, fmt, *args):
        pass   # 静默 access log

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _fetch(self, url, timeout=4):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return json.loads(r.read())
        except Exception:
            return None

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = INDEX_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/chain"):
            self._chain()
        else:
            self._json({"error": "not found"}, 404)

    def _chain(self):
        """双链查询：声明链（web_<会话>）+ eBPF 事实链（latest:ebpfweb）。"""
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        session = (qs.get("session") or ["anonymous"])[0][:64]
        try:
            decl_offset = int((qs.get("decl_offset") or ["0"])[0])
            ebpf_offset = int((qs.get("ebpf_offset") or ["0"])[0])
        except ValueError:
            decl_offset = ebpf_offset = 0

        decl = self._fetch(
            f"{self.collect_base}/events?trace_id=web_{session}"
            f"&offset=0&limit=500") or {"trace_id": None, "total": 0,
                                        "events": [], "chain_broken": False}
        # eBPF 链是持续累积的：新访客首次拉取跳到最近 30 条，之后增量
        if ebpf_offset == 0:
            probe = self._fetch(
                f"{self.collect_base}/events?trace_id=latest:ebpfweb"
                f"&offset=0&limit=0") or {}
            total = probe.get("total", 0)
            if total > 60:
                ebpf_offset = total - 30
        ebpf = self._fetch(
            f"{self.collect_base}/events?trace_id=latest:ebpfweb"
            f"&offset={ebpf_offset}&limit=200") or {"trace_id": None,
                                                    "total": 0,
                                                    "events": [],
                                                    "chain_broken": False}

        # 声明链全量取回算告警，增量返回给前端
        decl_events = decl.get("events") or []
        new_decl = decl_events[decl_offset:]
        alerts = demo_rules(decl_events, ebpf.get("events") or [])

        self._json({
            "declared": {"trace_id": decl.get("trace_id"),
                         "total": decl.get("total", 0),
                         "events": new_decl,
                         "chain_broken": decl.get("chain_broken", False)},
            "ebpf": {"trace_id": ebpf.get("trace_id"),
                     "total": ebpf.get("total", 0),
                     "events": ebpf.get("events") or [],
                     "chain_broken": ebpf.get("chain_broken", False)},
            "alerts": alerts,
        })

    def do_POST(self):
        if self.path != "/chat":
            self._json({"error": "not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._json({"error": "bad json"}, 400)
            return
        message = str(payload.get("message", ""))[:2000]
        session = str(payload.get("session", "anonymous"))[:64]

        trace = self.sdk.session(session)
        events = 1
        tools_used = []

        trace.user_message(message)

        # ---- 工具调用演示 ----
        env_ctx = ""
        if re.search(r"几点|时间|date|uptime|负载", message):
            trace.tool_invoke("run_command", {"command": "date && uptime"})
            out = subprocess.run(["sh", "-c", "date && uptime"],
                                 capture_output=True, text=True, timeout=10)
            trace.tool_result("run_command", out.stdout.strip())
            env_ctx = f"\n[系统时间信息]\n{out.stdout.strip()}"
            events += 2
            tools_used.append("run_command")

        if re.search(r"\.env|环境变量|配置文件", message):
            env_path = os.path.join(os.path.dirname(
                os.path.abspath(__file__)), "demo.env")
            trace.tool_invoke("read_file", {"path": env_path})
            try:
                with open(env_path, encoding="utf-8") as f:
                    env_ctx += f"\n[.env 内容]\n{f.read()}"
                    trace.tool_result("read_file", "读取成功")
            except OSError:
                trace.tool_result("read_file", "文件不存在")
            events += 2
            tools_used.append("read_file")

        if re.search(r"天气|气温|weather|温度", message):
            m = re.search(r"([\u4e00-\u9fa5]{2,8}?)的?(?:今天|现在|当前)?的?天气",
                          message)
            city = m.group(1) if m else ""
            city = re.sub(r"^(今天|明天|后天|现在|查|查询|看看|帮我)", "",
                          city) or "上海"
            trace.tool_invoke("get_weather", {"city": city})
            weather = get_weather(city)
            trace.tool_result("get_weather", weather or "查询失败")
            env_ctx += f"\n[实时天气 {city}]\n{weather or '查询失败'}"
            events += 2
            tools_used.append("get_weather")

        # ---- LLM 调用 ----
        messages = [{"role": "system",
                     "content": "你是 DemoWebApp 的助手，简洁回答。"},
                    {"role": "user", "content": message + env_ctx}]
        trace.llm_request("deepseek-chat", messages)
        result = call_deepseek(messages) or mock_llm(messages)
        trace.llm_response(result["model"], result["content"],
                           usage=result.get("usage"))
        events += 2

        trace.assistant_message(result["content"])
        events += 1
        trace.flush()

        self._json({"reply": result["content"],
                    "trace_id": trace.trace_id,
                    "events": events,
                    "tools": ",".join(tools_used) or None,
                    "model": result["model"]})


def main():
    ap = argparse.ArgumentParser(description="DemoWebApp（执行链剧场）")
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--collector", default="http://127.0.0.1:8787/ingest",
                    help="collector /ingest 地址")
    args = ap.parse_args()

    DemoHandler.sdk = AgentTraceSDK(
        app_name="DemoWebApp",
        collector_url=args.collector,
        flush_threshold=3, verbose=True)
    DemoHandler.collect_base = args.collector.rsplit("/ingest", 1)[0]

    server = ThreadingHTTPServer(("0.0.0.0", args.port), DemoHandler)
    print(f"◆ DemoWebApp(执行链剧场) http://0.0.0.0:{args.port}"
          f"  (上报 → {args.collector}，查询 → {DemoHandler.collect_base})",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

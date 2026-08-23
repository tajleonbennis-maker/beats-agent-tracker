# 给 AI 编程助手装上"行车记录仪"：我完整还原了它从改代码到上线部署的全过程，还看到它 8 次明文复现我的服务器密码

> **摘要**：AI 编程助手（Agent）在替我们写代码、跑命令、连服务器时，到底做了什么？本文记录了一次对 AI 编程助手 Kiro 的全链路执行监视实战——通过"系统层 + 应用层 + 流量层"三层采集架构，实时还原了 Agent 从改代码、编译、git 发布、scp 上传到服务器部署的**全自动 CI/CD 流程**，并发现它**在部署过程中 8 次明文复现服务器 root 密码**。文中方案已开源。

---

## 一、为什么 Agent 是个"黑盒"

过去半年，AI 编程助手（Kiro、Cursor、CodeBuddy、Trae 等）快速普及。它们不再是简单的补全工具，而是能自主决策、调用工具、执行命令、甚至 SSH 登录服务器的"Agent"。但一个尖锐的问题随之而来：

**当 Agent 替我们"干活"时，我们其实不知道它到底干了什么。**

一个典型的场景：你让 Agent"帮我检查一下服务器上的服务状态"。它开始忙活，终端里闪过几个"tool calls"，几秒后告诉你"服务运行正常"。但中间发生了什么？

- 它调用了哪些工具？
- 执行了什么命令？
- 读了哪些本地文件？
- 跟后端大模型传了什么数据？
- 有没有把什么敏感信息明文发出去？

这些在 Agent 的 UI 上大多是不可见的。Agent 的执行过程，本质上是一个**黑盒**。

出于对"AI 供应链安全"的关注，我决定自己动手，给一个真实在用的 AI 编程助手 Kiro 装上"行车记录仪"，看看它到底干了什么。

## 二、威胁模型与监视目标

在动手之前，先明确"我要抓什么"。从安全视角，Agent 的执行风险集中在几类：

| 风险类别 | 具体表现 | 危害 |
|---|---|---|
| **R1 密钥/敏感信息泄露** | Agent 把密码、token、私钥明文写入文件、命令、或外传 | 凭证泄露、横向移动 |
| **R2 越界操作** | Agent 在授权范围之外读写文件、改系统配置 | 数据破坏、后门植入 |
| **R3 异常外联** | Agent 绕过代理直连公网、连可疑 IP | 数据外传、C2 通信 |
| **R4 供应链投毒** | Agent 拉取不可信依赖、执行不可信脚本 | 持久化、供应链攻击 |

对应地，监视需要覆盖三个层面：

1. **系统层**——Agent 进程树、子进程、文件读写、本地文件读取；
2. **应用层**——Agent 与后端大模型的对话内容、工具调用（需解密 HTTPS）；
3. **流量层**——网络连接的四元组、SNI、域名、字节数。

## 三、方案：三层采集架构

整体架构如下（事件统一走 schema 0.1，带 SHA-256 哈希链，防篡改）：

```
┌─────────────────────────────────────────────────────────────┐
│  本机 Mac（被监视端）                                        │
│                                                             │
│  [系统层]  observer.py     进程树 / lsof 连接 / 文件 diff     │
│  [系统层]  fs_watcher.py   FSEvents 文件事件                  │
│  [应用层]  mitmdump + addon  HTTPS 解密 → 对话/工具/LLM       │
│  [流量层]  packetbeat       四元组 / DNS / HTTP 明文           │
│                                                             │
│              ↓ 全部 POST /ingest                             │
│  collector.py (Flask + SSE)  → 实时面板 http://127.0.0.1:8787 │
│                                                             │
│  [服务器回传]  agent.py (systemd 常驻)                        │
│     ← SSH 反向隧道 -R 18787:8787                             │
└─────────────────────────────────────────────────────────────┘
```

三个关键设计：

**1. 事件 schema 0.1 + 哈希链**：每条事件带 `trace_id`、`span_id`、`parent_span_id`，并用 SHA-256 链式哈希串联。任何一条事件被篡改或乱序，链校验都会失败——这让"监视结果"本身具备可审计性。

**2. MITM 解密（应用层）**：Agent 与大模型的对话走 HTTPS，旁路抓包（packetbeat）只能看到加密后的四元组。要看到对话内容、工具调用，必须在中间做 TLS 解密（mitmproxy + 安装 CA 证书）。

**3. 服务器回传**：Agent 通过 SSH 登录服务器之后的动作是更大的黑盒。方案在服务器上部署了一个常驻采集器（systemd），扫描 sshd 会话进程树、文件变化、网络外联，再通过 SSH 反向隧道实时回传到本机面板。

## 四、实战部署与踩坑

### 4.1 环境

- 被监视端：macOS，AI 编程助手 Kiro v1.0.337
- 采集栈：Python + Flask（面板）、mitmproxy（解密）、FSEvents（文件）、/proc 采集（服务器）
- 服务器端：Ubuntu 24.04 + systemd

### 4.2 关键步骤

```bash
# 1. 安装 mitmproxy，生成并安装 CA 证书到系统信任库（需 sudo）
brew install mitmproxy
bash kiro/install_mitm_ca.sh

# 2. 切换系统代理到 mitmproxy（127.0.0.1:8080）
bash kiro/proxy_setup.sh on

# 3. 启动采集栈（--mitm 抓 HTTPS 内容，--capture-reads 抓本地文件读取）
bash kiro/monitor_kiro.sh /path/to/workspace --mitm --capture-reads

# 4. 建立到服务器的反向隧道（服务器事件回传）
bash kiro/server_tunnel.sh
```

### 4.3 踩过的坑（价值所在）

| 坑 | 现象 | 解决 |
|---|---|---|
| **Electron 缓存代理** | 切系统代理后，Kiro 仍连旧代理，mitmproxy 抓不到流量 | Agent 是 Electron 应用，启动时缓存系统代理。**必须彻底退出重开**才能重读 |
| **headless 运行** | 交互式 `mitmproxy`（TUI）后台跑直接崩 | 用 `mitmdump`（headless） |
| **上游代理链** | 切代理后 Agent 断网 | Agent 依赖翻墙代理访问海外 LLM，mitmproxy 必须把上游指向它（`--mode upstream:http://127.0.0.1:1087@8080`） |
| **私有协议适配** | LLM 请求不是标准 OpenAI 格式，抓不到对话 | Agent 后端走私有端点，需针对性解析其请求体结构 |

## 五、抓到了什么：一条完整的 Agent 行为链

实战中，我让 Kiro"给程序加个实时网速显示功能，然后部署上线"。采集器完整还原了它从改代码到上线的**全自动 CI/CD 流程**：

```
① 写代码
   tool.invoke  str_replace ×2   修改 main.go（新增实时网速显示、-no-speed 参数）
   fs.write     cmd/monitor/main.go 落盘

② 编译
   tool.invoke  run_command       go build → 生成 bin/monitor-linux
   process.spawn monitor          本机编译运行验证

③ 提交发布
   tool.invoke  execute_bash      git push
   tool.invoke  execute_bash      git tag -a v1.1.0 -m "Release v1.1.0 - 默认显示实时网速"

④ 上传（跨端对应）
   本机  execute_bash            scp bin/monitor-linux root@服务器:/usr/local/bin/monitor
   服务器 process.spawn sftp-server   ← scp 触发的 SFTP 接收进程（回传）

⑤ 部署
   execute_bash  systemctl stop system-monitor
   execute_bash  chmod +x /usr/local/bin/monitor && monitor -version
   execute_bash  systemctl start system-monitor && systemctl status

⑥ 验证
   execute_bash  monitor -network / monitor / journalctl -u system-monitor -n 30
   服务器 process.spawn monitor    ← 服务器端实际运行的 monitor 进程（回传）
```

从"读代码 → 改代码 → 编译 → git 发布 → scp 上传 → 服务器部署 → 验证"的完整链条，跨本机与服务器两端，全部实时可见。值得一提的是，**scp 上传这一步在本机看到的是 `execute_bash` 命令，在服务器端对应看到的是 `sftp-server` 进程被拉起**——两端事件通过反向隧道拼成了完整闭环。

事件统计如下：

- 本机：`llm.request/response` ×20、`tool.invoke` ×7、`conversation.*` ×16、`fs.write` ×5
- 服务器回传：`ssh.session.open/close` ×4、`process.spawn/exit`（含 `sftp-server`、`monitor`）各 ×8、`net.connect` ×3
- 文件写入、进程 spawn、网络连接，一一对应

## 六、三个安全发现

### 发现 1：Kiro 是 AWS CodeWhisperer / Amazon Q 的"套壳"

解密 HTTPS 后，Kiro 的请求里暴露出 `profileArn=arn:aws:codewhisperer:u...`，模型 ID 为 `claude-sonnet-4.5`。它的后端域名架构清晰可见：

- `runtime.us-east-1.kiro.dev` —— LLM 运行时与 MCP 工具调用
- `management.us-east-1.kiro.dev` —— 用量管理
- `prod.us-east-1.telemetry.desktop.kiro.dev` —— 遥测上报
- `api.github.com/copilot/*` —— GitHub Copilot MCP 注册表

也就是说，Kiro 的"大脑"实际上是 AWS 托管的 CodeWhisperer/Amazon Q，模型跑在 Bedrock 上。这意味着你的代码上下文、对话记录，都会经过这套第三方链路。

### 发现 2（最值得警惕）：Agent 会明文复现你的密码

这是本次实战最触目惊心的发现。当 Kiro 需要登录服务器时，它把密码**原样明文**拼进了每一条 `sshpass -p` 命令。以这次"部署上线"任务为例，它执行的命令序列是这样的：

```bash
# 上传二进制（scp 也带明文密码）
sshpass -p "r140Bpxm****" scp -o StrictHostKeyChecking=no -P 22 bin/monitor-linux root@102.134.**.**:/usr/local/bin/monitor

# 停服务
sshpass -p "r140Bpxm****" ssh ... root@102.134.**.** "systemctl stop system-monitor"

# 赋权 + 验证
sshpass -p "r140Bpxm****" ssh ... root@102.134.**.** "chmod +x /usr/local/bin/monitor && monitor -version"

# 启动服务 + 查状态
sshpass -p "r140Bpxm****" ssh ... root@102.134.**.** "systemctl start system-monitor && systemctl status system-monitor"

# 验证 + 查日志
sshpass -p "r140Bpxm****" ssh ... root@102.134.**.** "monitor -network / journalctl -u system-monitor -n 30"
```

一次部署任务里，**同样的明文密码出现了 8 次**——scp 上传、systemctl 停/启、chmod、查日志，每一步都在复现。这说明：

1. 密码被 Agent 存进了它的上下文/记忆/配置文件里，并**长期持有**；
2. 每次需要登录服务器时，Agent 会把它原样拼进 `sshpass -p` 命令；
3. 该命令会进入 shell 历史、进程列表（`ps aux` 可见）、以及任何采集了命令行的地方。

**风险**：任何能看到进程列表、shell 历史、或屏幕的人，都能直接拿到你的服务器 root 密码。更糟的是，如果 Agent 的对话记录被同步到第三方，密码也随之泄露——而本文"发现 1"已经证明，你的对话上下文正是经过 AWS 托管的后端处理的。

**教训**：不要让 Agent 掌握明文凭据。应使用 SSH key + agent 转发、密钥管理服务，或至少让 Agent 通过环境变量/secret 引用，而不是把密码写进命令。

### 发现 3：system prompt 与遥测数据外溢

监视还意外抓到了 Kiro 发给大模型的完整 system prompt（"You are Kiro, an agentic AI software engineer..."），以及它上报的 OpenTelemetry 遥测数据（`resourceMetrics`）。这些数据侧面印证了：Agent 的"人设"、你的编辑行为、使用模式，都在被持续采集和上报。

## 七、防御与反思

站在安全从业者的角度，这次实战带来几点反思：

1. **Agent 需要"黑匣子"**。飞机的黑匣子用于事故复盘，Agent 同样需要。可审计的执行轨迹是建立信任的前提。

2. **最小权限 + 凭据隔离**。别给 Agent 明文密码，别给它 root，别让它能直接改生产环境。它的每一次"自主"操作，都应该是可撤销、可审计、有边界的。

3. **解密监视是双刃剑**。MITM 能看清一切，但也意味着监视者同样能拿到所有明文。这套工具**只能用于你自己的机器和授权目标**，绝不能用于未授权监视。

4. **AI 供应链安全是真实存在的攻防面**。Agent 的模型、MCP 插件、依赖、遥测链路，都是新的攻击面。这次看到 Agent 明文复现密码，只是冰山一角。

## 八、开源与展望

完整的采集栈已开源，包含本地观察器、HTTPS 解密插件、实时面板、服务器端采集器与反向隧道脚本：

> **GitHub：https://github.com/tajleonbennis-maker/agent-security-toolkit**（`Agent-Execution-Monitor/` 目录）

后续计划：

- 增加**明文密码/密钥实时告警**规则（工具调用命令内容嗅探，命中即弹红）；
- ~~接入 eBPF / auditd~~ **（已实现）**：服务器端新增 `ebpf_tracer`，基于 BCC 在内核态挂 `sched_process_exec` + `sys_enter_connect` 两个 tracepoint，零漏采短命进程与连接（`/proc` 轮询会漏掉的 `<0.5s` 进程/连接），已实测回传面板；
- 支持更多 Agent（Cursor / CodeBuddy / Trae）的私有协议解析；
- 关联引擎产出完整时间轴与证据包，一键生成事件报告。

---

*本文所有测试均在作者自有设备与授权目标上完成，敏感信息（IP、密码）已脱敏。工具仅用于授权安全评估。*

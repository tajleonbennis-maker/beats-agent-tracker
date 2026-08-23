# 产品化部署指南（长期运行 + 应用层透视）

依据 2026-08-23 Kiro 部署监视实战的教训升级：

| 实战问题 | v3 方案 | 文件 |
|---|---|---|
| 数据分散在黑盒里，没有统一视图 | 实时 SSE 仪表板 + collector 事件总线 | `dashboard/collector.py`、`dashboard/index.html` |
| Kiro 调用了什么工具、参数、结果完全看不到 | MITM 代理 + addon 解析 HTTPS 流量，输出 tool.invoke/result、llm.request/response、conversation.* | `dashboard/mitm_addon.py`、`kiro/install_mitm_ca.sh`、`kiro/proxy_setup.sh` |
| R3 异常外联只有 IP，没有对端/域名/SNI | MITM  enriching：SNI、HTTP Host、JA3、路径、状态码 | `dashboard/mitm_addon.py` |
| Kiro 读本地文件（如 ~/.gitconfig）获取 git 账号无记录 | lsof 文件描述符扫描 + FSEvents，捕获敏感文件读取 | `kiro/observer.py --capture-reads`、`dashboard/fs_watcher.py` |
| 用户与 Kiro 的对话、Kiro 与上层模型的对话无记录 | MITM 解析 chat/completions 类 API，提取 user/assistant 消息 | `dashboard/mitm_addon.py` |
| 观察器随会话/进程组被杀，出现监视空窗 | watchdog 守护 + launchd KeepAlive + `--resume` 断链续写 | `kiro/watchdog.sh`、`kiro/install_launchd.sh` |
| Kiro 终端里的 go/git/ssh 是孙进程，网络漏拍 | 全进程树追踪（pid→ppid 可达即目标）+ 网络按当轮实时树归属 | `kiro/observer.py` |
| 告警只能事后 correlator 出，密码已推上 GitHub | 实时规则引擎 + 文件内容密钥嗅探，写入瞬间落盘 | `kiro/observer.py` RealtimeAlerts、`dashboard/collector.py` |
| Kiro SSH 部署到服务器后完全黑箱 | 服务器端采集器（sshd 会话树 + 文件 + 外联）+ 中央汇集 | `server/agent.py`、`server/collect_server.py` |

---

## 架构总览

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            用户 Mac（被监视侧）                            │
│  ┌─────────────┐  HTTPS   ┌──────────────┐   HTTP POST   ┌───────────┐  │
│  │  Kiro IDE   │─────────▶│  mitmproxy   │──────────────▶│ collector │  │
│  │ (Electron)  │          │  :8080 addon │               │  :8787    │  │
│  └─────────────┘          └──────────────┘               └─────┬─────┘  │
│       │                                                         │        │
│       │ 系统调用/文件                                            │ SSE    │
│       ▼                                                         ▼        │
│  ┌──────────────┐  HTTP POST  ┌───────────────┐      ┌────────────────┐ │
│  │ observer.py  │────────────▶│  实时面板网页  │◀─────│  dashboard/    │ │
│  │ (进程/网络/  │             │  http://...   │      │  collector.py  │ │
│  │  文件轮询)   │             │               │      └────────────────┘ │
│  └──────────────┘             └───────────────┘                          │
│       │                                                      browser    │
│       │ HTTP POST                                            (open)     │
│       ▼                                                                   │
│  ┌──────────────┐                                                         │
│  │ fs_watcher.py│  macOS FSEvents（workspace + Kiro User 数据目录）        │
│  └──────────────┘                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 可选：上报到 Mac
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         被部署服务器（Linux）                              │
│  ┌─────────────┐    network     ┌──────────────┐   HTTP POST  ┌────────┐ │
│  │ server/agent│───────────────▶│ Mac collector│◀─────────────│ 本地或 │ │
│  │  (systemd)  │                │  or collect  │              │ 远端   │ │
│  └─────────────┘                └──────────────┘              └────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 一、本地完整采集栈（推荐一键启动）

### 1.1 快速启动（watchdog + dashboard + FSEvents + observer）

```bash
cd beats-agent-tracker
bash kiro/monitor_kiro.sh /path/to/workspace --capture-reads
```

会自动：

1. 启动 collector 实时面板：`http://127.0.0.1:8787`
2. 启动 FSEvents 文件监视（workspace + Kiro User 数据目录）
3. 启动 observer（watchdog 守护、断链续写、实时告警）
4. 用默认浏览器打开面板

停止：

```bash
bash kiro/monitor_kiro.sh --stop
```

### 1.2 启用 MITM（捕获工具调用、对话内容、rich 网络数据）

Kiro 是 Electron 应用，走系统代理 + HTTPS。要解密，需要安装 mitmproxy CA 并设置代理：

```bash
# 1. 安装 mitmproxy（如果还没有）
brew install mitmproxy

# 2. 安装 CA 到系统钥匙串（需要 sudo 密码）
bash kiro/install_mitm_ca.sh

# 3. 开启系统代理（会让 Kiro 走 127.0.0.1:8080）
bash kiro/proxy_setup.sh on

# 4. 启动采集栈（--mitm 会同时启动 mitmproxy addon）
bash kiro/monitor_kiro.sh /path/to/workspace --capture-reads --mitm
```

结束后关闭代理：

```bash
bash kiro/proxy_setup.sh off
```

> ⚠️ 设置系统代理会影响本机所有应用。如只想监视 Kiro，可在 Kiro 内配置代理，或改用透明代理/pf 规则（高级）。

### 1.3 产品模式：launchd（系统级守护）

```bash
bash kiro/install_launchd.sh /path/to/workspace      # 安装并启动
bash kiro/install_launchd.sh --uninstall             # 卸载
```

- KeepAlive：哪怕整个进程组被 SIGKILL，launchd 立即重新拉起
- 日志：`~/Library/Logs/agent-monitor/observer.log`

---

## 二、各采集器说明

### observer.py（系统事实链）

```bash
python3 kiro/observer.py --workspace WS [选项]
  --seed-pid PID         监视任意 Agent（不限于 Kiro）：给它的主进程 pid
  --seed-pattern PREFIX  种子进程 argv 前缀（默认 /Applications/Kiro.app）
  --resume TRACE_ID      断点续写（watchdog 自动使用）
  --poll-proc 0.5        进程轮询秒（默认 0.5，短命孙进程不漏）
  --poll-net  0.3        网络轮询秒（默认 0.3）
  --capture-reads        启用 lsof 文件描述符扫描，捕获敏感文件读取（fs.read）
  --collector URL        实时上报到 dashboard collector
```

`--capture-reads` 会扫描 Kiro 进程树内每个进程已打开的文件，命中以下敏感模式才上报：
`.ssh/`、`.gnupg/`、`.aws/`、`.gitconfig`、`.git-credentials`、`.netrc`、
`Keychains`、`.npmrc`、`.pypirc`、`.docker/config.json`、`.kube/config`、
`.env`、shell history、profile/rc 文件等。

### fs_watcher.py（macOS FSEvents）

```bash
python3 dashboard/fs_watcher.py /path/to/workspace "/Users/.../Library/Application Support/Kiro/User"
```

捕获创建、修改、删除、重命名事件，带完整路径。

### mitm_addon.py（应用层语义）

加载到 mitmproxy 后，自动输出：

- `net.connect`： richer（host、path、SNI、JA3、对端 IP）
- `tool.invoke` / `tool.result`：识别 webFetch、remote_web_search、read_file、write_file、bash 等工具名
- `llm.request` / `llm.response`：向大模型 API 的请求/响应
- `conversation.user` / `conversation.assistant`：用户 prompt 与 Kiro/模型回复的预览
- `tool.http`：每个 HTTP 请求/响应摘要

### collector.py（实时面板 + 事件总线）

```bash
python3 dashboard/collector.py --port 8787 --events-dir events
```

- `POST /ingest`：各采集器上报事件
- `GET /events`：SSE 实时流
- `GET /api/state`、`/api/events`、`/api/alerts`：REST API
- 内置实时规则：R1（密钥嗅探）、R2（越界文件）、R3（异常外联），命中即 SSE 广播

---

## 三、服务器侧采集（被部署主机）

部署（在被监视的 Linux 服务器上执行，需要 SSH 凭据）：

```bash
bash server/install.sh root@102.134.48.49 [ssh端口]
```

在服务器上做的事：`agent.py` → `/opt/agent-monitor/`，systemd 单元
`agent-monitor.service`（root、Restart=always、开机自启）。

采集范围：

- **SSH 会话**：`sshd: user@pts/N` 会话进程的完整进程树——远端 Agent 在
  SSH 里跑的每条命令（git/systemctl/curl/scp…）都是子孙，逐个 process.spawn
- **网络**：`/proc/net/tcp(+6)` ESTABLISHED + `/proc/*/fd` socket inode 映射，
  会话树内进程的外联（数据外传可见）
- **文件**：`--watch /opt,/srv,/root,/var/www,/home` walk-diff
- **内容嗅探**：同本地（remote-deploy.sh 带密码落盘的瞬间报警）

服务器侧操作：

```bash
journalctl -u agent-monitor -f              # 实时日志
cat /var/lib/agent-monitor/events/srv_*.ndjson   # 事件流（哈希链防篡改）
touch /var/lib/agent-monitor/STOP           # 优雅停止
```

---

## 四、中央汇集（可选，事件回传监视机）

```bash
python3 server/collect_server.py --port 8787        # Mac 上跑
# 服务器端配置上报（改 systemd 单元 ExecStart 追加）：
#   agent.py --report-url http://<Mac的IP>:8787/ingest
```

- 每批上报做哈希链连续性校验（防传输篡改/乱序），断裂即告警
- `GET /status` 查看各源状态

> 注：dashboard/collector.py 已内置 collect_server.py 的核心能力，本地监视场景可直接用 collector。

---

## 五、多源合并报告（本地 + 服务器联合时间轴）

```bash
python3 correlator/correlate.py \
  --input events/kiro_xxx.ndjson,events/srv_yyy.ndjson \
  --out output/report
```

- 双链各自校验完整性，报告标注全部监视主机
- 实时告警文件（`*_alerts.ndjson`）自动合并进 alerts.json

---

## 六、已知边界与升级路线

| 能力 | 当前状态 | 下一步升级 |
|---|---|---|
| 工具调用参数/结果 | ✅ MITM 解析 HTTPS | 如 Kiro 走本地 IPC 而非 HTTP，需注入 preload/CDP |
| 用户-Kiro 对话 | ✅ MITM 解析 LLM API | 本地 LevelDB 备份解析（无需代理） |
| Kiro-LLM 请求 | ✅ MITM | 同上 |
| 文件读取 | ✅ lsof FD 扫描敏感路径 + FSEvents 变更 | fs_usage/EndpointSecurity 可覆盖全部 open() |
| 网络 rich data | ✅ SNI/Host/JA3 via MITM；observer 给 IP | 透明代理 + TLS fingerprinting |
| 服务器侧进程 | ✅ /proc 轮询 | eBPF/auditd 可零漏拍 |
| 实时告警 | ✅ collector + observer 双实时 | WebSocket 推送手机通知 |

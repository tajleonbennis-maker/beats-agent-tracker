#!/bin/bash
# 端到端演示：Agent Runtime → NDJSON 事件 → Filebeat 采集/映射 → 关联引擎
# 用法：bash demo/run_demo.sh [filebeat 二进制路径]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
FILEBEAT="${1:-${FILEBEAT:-/tmp/filebeat-8.15.4-darwin-x86_64/filebeat}}"
EVENTS_DIR="$ROOT/events"
OUT="$ROOT/output"
FB_DATA=/tmp/fbeat-agent-trace-data

if [ ! -x "$FILEBEAT" ]; then
  echo "!! 未找到 filebeat 二进制：$FILEBEAT"
  echo "   下载：curl -sSL -o /tmp/filebeat.tar.gz https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.15.4-darwin-x86_64.tar.gz && tar xzf /tmp/filebeat.tar.gz -C /tmp"
  echo "   或：  FILEBEAT=/path/to/filebeat bash demo/run_demo.sh"
  exit 1
fi

echo "== 0. 清理上次运行 =="
rm -rf "$EVENTS_DIR" "$OUT" "$FB_DATA" /tmp/agent-ws /tmp/agent-escape-test.txt
mkdir -p "$EVENTS_DIR" "$OUT"

echo "== 1. 运行演示 Agent（含植入的间接提示注入测试指令）=="
$PYTHON runtime/agent.py --task tasks/demo_task.json \
  --workspace /tmp/agent-ws --events-dir "$EVENTS_DIR" | tee "$OUT/agent_run.json"

EVENTS_FILE=$(ls "$EVENTS_DIR"/*.ndjson | head -1)
echo "事件文件：$EVENTS_FILE ($(wc -l < "$EVENTS_FILE" | tr -d ' ') 条)"

echo ""
echo "== 2. Filebeat 采集 + ECS 映射（Beats 专注采集层）=="
AGENT_TRACE_EVENTS_DIR="$EVENTS_DIR" "$FILEBEAT" -c "$ROOT/beats/filebeat.yml" \
  --path.data "$FB_DATA" -e > "$OUT/processed.ndjson" 2>"$OUT/filebeat.log" &
FB_PID=$!
# 轮询等待 Beats 采集完成（事件数达标或超时）
EXPECT=$(wc -l < "$EVENTS_FILE" | tr -d ' ')
for i in $(seq 1 60); do
  GOT=$(wc -l < "$OUT/processed.ndjson" 2>/dev/null | tr -d ' ' || echo 0)
  [ "${GOT:-0}" -ge "$EXPECT" ] && break
  sleep 1
done
kill "$FB_PID" 2>/dev/null || true
wait "$FB_PID" 2>/dev/null || true
echo "采集后事件：$(wc -l < "$OUT/processed.ndjson" | tr -d ' ') 条 → output/processed.ndjson"

echo ""
echo "== 3. 关联引擎：Span 树 + 时间轴 + 规则 + 证据包 =="
$PYTHON correlator/correlate.py --input "$OUT/processed.ndjson" --out "$OUT"

echo ""
echo "== 4. 证据包完整性验证 =="
$PYTHON correlator/evidence.py verify "$OUT/evidence_pkg"

echo ""
echo "== 5. 流量关联（Packetbeat 输出 → trace，可选）=="
PACKETBEAT="${PACKETBEAT:-/tmp/packetbeat-8.15.4-darwin-x86_64/packetbeat}"
if [ -s "$OUT/packetbeat.ndjson" ]; then
  $PYTHON correlator/enrich.py "$OUT/processed.ndjson" "$OUT/packetbeat.ndjson" \
    "$OUT/traffic.enriched.ndjson"
elif [ -x "$PACKETBEAT" ] && [ "${RUN_PACKETBEAT:-0}" = "1" ]; then
  # 实时抓包需要 root：sudo RUN_PACKETBEAT=1 bash demo/run_demo.sh
  # macOS 注意 beats/packetbeat.yml 的 device（lo0=回环 / en0=物理网卡）
  sudo "$PACKETBEAT" -c "$ROOT/beats/packetbeat.yml" \
    --path.data /tmp/pbeat-agent-trace-data -e > "$OUT/packetbeat.ndjson" 2>"$OUT/packetbeat.log" &
  PB_PID=$!
  sleep 2
  $PYTHON correlator/enrich.py "$OUT/processed.ndjson" "$OUT/packetbeat.ndjson" \
    "$OUT/traffic.enriched.ndjson"
  kill "$PB_PID" 2>/dev/null || true
else
  echo "跳过（无 output/packetbeat.ndjson；实时抓包需 root，见 beats/packetbeat.yml 注释）"
fi

echo ""
echo "产物："
echo "  $OUT/timeline.md           执行链时间轴（语义链+系统链）"
echo "  $OUT/alerts.json           风险告警（R1/R2/R3）"
echo "  $OUT/trace_summary.json    统计与指标"
echo "  $OUT/evidence_pkg/         可归档证据包（哈希链）"
echo "  $OUT/traffic.enriched.ndjson  流量事件（关联 trace 后，如启用 Packetbeat）"

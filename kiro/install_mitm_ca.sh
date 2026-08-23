#!/bin/bash
# 安装 mitmproxy CA 证书到 macOS 系统钥匙串，使 Kiro 信任 MITM 代理
#
# 前置：已安装 mitmproxy（brew install mitmproxy）
# 运行： bash kiro/install_mitm_ca.sh
# 会要求输入 sudo 密码
set -e

CA="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
if [ ! -f "$CA" ]; then
  echo "[ca] 首次生成 CA..."
  mitmdump --version >/dev/null 2>&1 || (echo "请先安装 mitmproxy (brew install mitmproxy)"; exit 1)
  # 运行一次 mitmdump 让 CA 自动生成（macOS 无 timeout，用后台+kill 代替）
  mitmdump --mode regular@8080 --set termlog_verbosity=error >/dev/null 2>&1 &
  MPID=$!
  sleep 2
  kill "$MPID" 2>/dev/null || true
  wait "$MPID" 2>/dev/null || true
fi

if [ ! -f "$CA" ]; then
  echo "[ca] 无法生成证书: $CA"
  exit 1
fi

echo "[ca] 安装 $CA 到系统信任库（需要 sudo）..."
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CA"
echo "[ca] ✅ 已安装。现在可以运行 bash kiro/proxy_setup.sh 开启 MITM"

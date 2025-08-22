#!/bin/bash
set -e

# ---------------- 配置参数 ----------------
PORT=22001
PASSWORD="yiyann***999"
METHOD="aes-256-gcm"
SHADOWSOCKS_CONFIG="/etc/shadowsocks-libev/config.json"
CLOUDFLARED_PORT=5353
DOH_UPSTREAM="https://doh.opendns.com/dns-query"

# ---------------- 安装依赖 ----------------
echo "📦 更新系统并安装必要组件..."
apt update
apt install -y shadowsocks-libev curl screen wget unzip sudo

# ---------------- 安装 cloudflared ----------------
if ! command -v cloudflared >/dev/null 2>&1; then
    echo "📥 安装 cloudflared..."
    wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
    sudo dpkg -i cloudflared-linux-amd64.deb
fi

# ---------------- 启动 cloudflared DoH 代理 ----------------
echo "🚀 启动 cloudflared 本地 DoH 代理..."
# 先杀掉可能存在的旧进程
pkill -f "cloudflared proxy-dns" || true
screen -dmS cloudflared_doh bash -c "cloudflared proxy-dns --port $CLOUDFLARED_PORT --upstream $DOH_UPSTREAM"

# ---------------- 配置 Shadowsocks ----------------
echo "📝 写入 Shadowsocks 配置..."
mkdir -p /etc/shadowsocks-libev
cat > "$SHADOWSOCKS_CONFIG" <<EOF
{
  "server": "0.0.0.0",
  "server_port": $PORT,
  "password": "$PASSWORD",
  "timeout": 300,
  "method": "$METHOD",
  "fast_open": false,
  "nameserver": "127.0.0.1:$CLOUDFLARED_PORT",
  "mode": "tcp_and_udp"
}
EOF

# ---------------- 启动 Shadowsocks 服务 ----------------
echo "🔧 启动并设置 Shadowsocks 开机自启..."
systemctl restart shadowsocks-libev
systemctl enable shadowsocks-libev

# ---------------- 输出客户端链接 ----------------
IP=$(curl -s ifconfig.me)
PLAIN="$METHOD:$PASSWORD@$IP:$PORT"
ENCODED=$(echo -n "$PLAIN" | base64 | tr -d '\n')
LINK="ss://$ENCODED"

echo ""
echo "✅ Shadowsocks + OpenDNS DoH 安装完成！"
echo "----------------------------------------"
echo "服务器地址 : $IP"
echo "端口       : $PORT"
echo "密码       : $PASSWORD"
echo "加密方式   : $METHOD"
echo "DNS        : https://doh.opendns.com -> 127.0.0.1:$CLOUDFLARED_PORT"
echo "----------------------------------------"
echo "📎 客户端链接："
echo "$LINK"
echo "----------------------------------------"
echo "💡 cloudflared 日志查看：screen -r cloudflared_doh"

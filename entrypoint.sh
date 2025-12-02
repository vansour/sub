#!/usr/bin/env sh
set -e

DATA_DIR="/app/data"
CONFIG_DIR="/app/config"
LOG_DIR="/app/logs"
CONFIG_FILE="$CONFIG_DIR/config.toml"

# 确保必要目录存在
mkdir -p "$DATA_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

# 如果配置文件不存在，则生成默认配置
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Generating default config.toml at $CONFIG_FILE..."
    cat <<EOF > "$CONFIG_FILE"
[server]
host = "${SERVER_HOST:-0.0.0.0}"
port = ${SERVER_PORT:-8080}

[log]
logFilePath = "${LOG_FILE_PATH:-/app/logs/sub.log}"
level = "${LOG_LEVEL:-debug}"
EOF
fi

# 运行应用
exec /app/sub
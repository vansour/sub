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

# 只有当文件不存在时才生成默认配置
# 注意：如果你之前已经运行过，可能需要手动删除旧的错误 config.toml，或者重建容器
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Generating default config.toml at $CONFIG_FILE..."
    cat <<EOF > "$CONFIG_FILE"
[server]
host = "${SERVER_HOST:-0.0.0.0}"
port = ${SERVER_PORT:-8080}

[log]
# 修改为 snake_case 以匹配 Rust 结构体
log_file_path = "${LOG_FILE_PATH:-/app/logs/sub.log}"
level = "${LOG_LEVEL:-debug}"
EOF
fi

# 运行应用
exec /app/sub
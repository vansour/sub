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
    
    # 生成随机加密密钥 (如果环境变量未提供)
    if [ -z "$SECRET_KEY" ]; then
        SECRET_KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1)
    fi

    cat <<EOF > "$CONFIG_FILE"
[server]
host = "${SERVER_HOST:-0.0.0.0}"
port = ${SERVER_PORT:-8080}
secret_key = "${SECRET_KEY}"
cookie_secure = ${COOKIE_SECURE:-false}

[log]
# 修改为 snake_case 以匹配 Rust 结构体
log_file_path = "${LOG_FILE_PATH:-/app/logs/sub.log}"
level = "${LOG_LEVEL:-debug}"
EOF
fi

# 复制默认 clash.yaml 配置（如果不存在）
CLASH_FILE="$CONFIG_DIR/clash.yaml"
DEFAULT_CLASH="/app/config.default/clash.yaml"
if [ ! -f "$CLASH_FILE" ] && [ -f "$DEFAULT_CLASH" ]; then
    echo "Copying default clash.yaml to $CLASH_FILE..."
    cp "$DEFAULT_CLASH" "$CLASH_FILE"
fi

# 运行应用
exec /app/sub
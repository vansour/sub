#!/usr/bin/env sh
set -e

CONFIG_DIR="/app/config"
DATA_DIR="/app/data"
DEFAULTS_CONFIG_DIR="/app/.defaults/config"
DEFAULTS_DATA_DIR="/app/.defaults/data"
CONFIG_FILE="$CONFIG_DIR/config.toml"
DATA_FILE="$DATA_DIR/data.toml"
DEFAULT_CONFIG_FILE="$DEFAULTS_CONFIG_DIR/config.toml"
DEFAULT_DATA_FILE="$DEFAULTS_DATA_DIR/data.toml"

# 确保目录存在
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"

# 如果没有配置文件，用默认的填充一次（不覆盖已有修改）
if [ ! -f "$CONFIG_FILE" ] && [ -f "$DEFAULT_CONFIG_FILE" ]; then
  cp "$DEFAULT_CONFIG_FILE" "$CONFIG_FILE"
  echo "[entrypoint] Populated $CONFIG_FILE from defaults."
fi

# 如果没有数据文件，用默认的填充一次（不覆盖已有修改）
if [ ! -f "$DATA_FILE" ] && [ -f "$DEFAULT_DATA_FILE" ]; then
  cp "$DEFAULT_DATA_FILE" "$DATA_FILE"
  echo "[entrypoint] Populated $DATA_FILE from defaults."
fi

# 运行应用
exec /app/sub
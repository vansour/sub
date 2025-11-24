#!/usr/bin/env sh
set -e

DATA_DIR="/app/data"
DEFAULTS_DIR="/app/.defaults/data"
DATA_FILE="$DATA_DIR/data.toml"
DEFAULT_FILE="$DEFAULTS_DIR/data.toml"

# 确保目录存在
mkdir -p "$DATA_DIR"

# 如果没有配置文件，用默认的填充一次（不覆盖已有修改）
if [ ! -f "$DATA_FILE" ] && [ -f "$DEFAULT_FILE" ]; then
  cp "$DEFAULT_FILE" "$DATA_FILE"
  echo "[entrypoint] Populated $DATA_FILE from defaults."
fi

# 运行应用
exec /app/sub
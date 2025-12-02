#!/usr/bin/env sh
set -e

DATA_DIR="/app/data"

# 确保数据目录存在
mkdir -p "$DATA_DIR"

# 运行应用
exec /app/sub
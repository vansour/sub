#!/usr/bin/env sh
set -e

# ============================================
# 配置路径
# ============================================
CONFIG_DIR="/app/config"
DATA_DIR="/app/data"
DEFAULTS_CONFIG_DIR="/app/.defaults/config"
CONFIG_FILE="$CONFIG_DIR/config.toml"
DEFAULT_CONFIG_FILE="$DEFAULTS_CONFIG_DIR/config.toml"

# 数据库路径（可通过环境变量覆盖）
DATABASE_PATH="${DATABASE_PATH:-/app/data/sub.db}"

# ============================================
# 颜色输出
# ============================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo "${GREEN}[entrypoint]${NC} $1"
}

log_warn() {
    echo "${YELLOW}[entrypoint]${NC} $1"
}

log_error() {
    echo "${RED}[entrypoint]${NC} $1"
}

# ============================================
# 1. 确保必要目录存在
# ============================================
log_info "Initializing directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"

# 设置权限（确保可写）
chmod 755 "$CONFIG_DIR" "$DATA_DIR" 2>/dev/null || true

log_info "Directories initialized:"
log_info "  - Config: $CONFIG_DIR"
log_info "  - Data:   $DATA_DIR"

# ============================================
# 2. 初始化配置文件
# ============================================
if [ ! -f "$CONFIG_FILE" ]; then
    if [ -f "$DEFAULT_CONFIG_FILE" ]; then
        cp "$DEFAULT_CONFIG_FILE" "$CONFIG_FILE"
        log_info "Created config file from defaults: $CONFIG_FILE"
    else
        log_warn "Default config file not found, application will use built-in defaults"
    fi
else
    log_info "Using existing config file: $CONFIG_FILE"
fi

# ============================================
# 3. 数据库状态检查
# ============================================
if [ -f "$DATABASE_PATH" ]; then
    DB_SIZE=$(du -h "$DATABASE_PATH" | cut -f1)
    log_info "Database found: $DATABASE_PATH (Size: $DB_SIZE)"
else
    log_info "Database not found, will be created on first run: $DATABASE_PATH"
fi

# ============================================
# 4. 环境变量检查和日志
# ============================================
log_info "Environment configuration:"
log_info "  - DATABASE_PATH: $DATABASE_PATH"
log_info "  - RUST_LOG: ${RUST_LOG:-info}"

# ============================================
# 5. 健康检查（确保数据库文件可访问）
# ============================================
if [ -f "$DATABASE_PATH" ]; then
    if [ ! -r "$DATABASE_PATH" ] || [ ! -w "$DATABASE_PATH" ]; then
        log_error "Database file exists but is not accessible (check permissions)"
        log_error "  Path: $DATABASE_PATH"
        exit 1
    fi
fi

# ============================================
# 6. 运行应用
# ============================================
log_info "Starting sub application..."
log_info "=========================================="

exec /app/sub
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

CLASH_CONFIG_FILE="$CONFIG_DIR/clash.yaml"
if [ ! -f "$CLASH_CONFIG_FILE" ]; then
    echo "Generating default clash.yaml at $CLASH_CONFIG_FILE..."
    cat <<EOF > "$CLASH_CONFIG_FILE"
mixed-port: 7890
allow-lan: false
bind-address: "*"
log-level: info
dns:
  enable: true
  ipv6: false
  default-nameserver:
    - 119.29.29.29
  nameserver:
    - 119.29.29.29
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter: []
  use-hosts: false
  use-system-hosts: true
  proxy-server-nameserver:
    - 8.8.8.8
  direct-nameserver:
    - 119.29.29.29
  direct-nameserver-follow-policy: true
  respect-rules: true
  nameserver-policy: {}
proxy-providers:
  sub:
    type: http
    url: {url}/{username}
    path: ./proxy_providers/{username}.yaml
    interval: 1800
    health-check:
      enable: true
      url: 	http://www.google.com/generate_204
      interval: 300
proxy-groups:
  - name: youtube
    type: select
    use:
      - sub
  - name: steam
    type: select
    use:
      - sub
  - name: github
    type: select
    use:
      - sub
  - name: openai
    type: select
    use:
      - sub
  - name: google
    type: select
    use:
      - sub
  - name: fallback
    type: select
    use:
      - sub
rule-providers:
  ipcidr_cn:
    type: http
    behavior: ipcidr
    url: https://gh-proxy.com/https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/ip/cn.yaml
    path: ./rule_providers/ipcidr_cn.yaml
    interval: 86400
  domain_cn:
    type: http
    behavior: domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/cn.yaml
    path: ./rule_providers/domain_cn.yaml
    interval: 86400
  domain_steam:
    type: http
    behavior: domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/steam.yaml
    path: ./rule_providers/domain_steam.yaml
    interval: 86400
  domain_github:
    type: http
    behavior: domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/github.yaml
    path: ./rule_providers/domain_github.yaml
    interval: 86400
  domain_youtube:
    type: http
    behavior: domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/youtube.yaml
    path: ./rule_providers/domain_youtube.yaml
    interval: 86400
  domain_openai:
    type: http
    behavior: domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/openai.yaml
    path: ./rule_providers/domain_openai.yaml
    interval: 86400
  domain_gemini:
    type: http
    behavior: domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/google-gemini.yaml
    path: ./rule_providers/domain_gemini.yaml
    interval: 86400
  domain_google:
    type: http
    behavior: domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/google.yaml
    path: ./rule_providers/domain_google.yaml
    interval: 86400
rules:
  - RULE-SET,ipcidr_cn,DIRECT
  - RULE-SET,domain_cn,DIRECT
  - RULE-SET,domain_youtube,youtube
  - RULE-SET,domain_steam,steam
  - RULE-SET,domain_github,github
  - RULE-SET,domain_openai,openai
  - RULE-SET,domain_gemini,google
  - RULE-SET,domain_google,google
  - MATCH,fallback
EOF
fi

# 运行应用
exec /app/sub
```
services:
  web:
    image: ghcr.io/vansour/sub:latest
    container_name: sub
    hostname: localhost
    ports:
      - "8080:8080"
    restart: unless-stopped
    volumes:
      - ./config:/app/config
      - ./data:/app/data
```

## Clash 模板占位符

应用在生成 per-user Clash 配置时会替换模板中的占位符：

- `{username}` -> 替换为目标用户名
- `{website}` -> 替换为协议与主机（来自请求头，例如 `https://example.com` 或 `http://localhost:8080`）

因此在 `data/clash/default.yaml` 的 `proxy-providers` 中使用 `{website}/{username}` 可以生成指向本服务的正确 URL。
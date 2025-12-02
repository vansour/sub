# Sub — 多用户链接聚合器

Sub 是一个使用 Rust (Actix-web) 开发的轻量级、高性能的多用户链接聚合服务。
它可将多个网页的正文抓取并合并为纯文本，以便在客户端或其他服务中消费。

---

## 主要特性 ✅
- 多用户管理：创建、删除、排序用户
- 链接聚合：为每个用户定义若干链接，访问 `/{username}` 返回按顺序合并的纯文本
- 智能 HTML 解析：使用 `scraper` + DOM 遍历保留段落与换行、过滤 `<script>`/`<style>` 等标签
- 管理后台：基于 Cookie 的 Session 认证，前端包含管理面板（`web/`）
- 日志：控制台紧凑输出 + 文件 JSON 格式写入（每天轮转）
- 持久化：SQLite 用作轻量数据库（路径：`data/sub.db`）
- 容器友好：Dockerfile + `docker compose` 支持快速部署

---

## 快速开始（推荐：Docker / docker-compose） 🚀
1. 构建并启动容器：

```bash
# 使用本地构建镜像并启动
docker compose up -d --build
```

2. 页面访问：
- 管理后台： http://127.0.0.1:8080
- 订阅合并流（文本）： http://127.0.0.1:8080/{username}

3. 默认管理员：
- 用户名: `admin`
- 密码: `password`

⚠️ 第一次启动请尽快登录并修改管理员用户名/密码（右上角 账号设置）。

---

## 配置项（`config/config.toml`）⚙️
服务会在容器启动时（或首次运行时）自动生成默认配置文件至 `config/config.toml`，下面是示例：

```toml
[server]
host = "0.0.0.0"
port = 8080

[log]
log_file_path = "/app/logs/sub.log"
level = "debug"
```

可用环境变量（覆盖默认配置或用于初始化）:
- `ADMIN_USER` — 初始化管理员用户名（仅数据库为空时生效）
- `ADMIN_PASSWORD` — 初始化管理员密码（仅数据库为空时生效）
- `DATABASE_URL` — SQLite 连接字符串，示例：`sqlite:/app/data/sub.db`（容器默认）
- `SERVER_HOST` / `SERVER_PORT` — 覆盖 `config.toml` 中的设置
- `LOG_FILE_PATH` / `LOG_LEVEL` — 覆盖日志设置

---

## 构建与本地运行（开发者）🛠️
前提：安装 Rust (stable)、SQLite

本地运行步骤：

```bash
# 准备工作目录
mkdir -p data config logs
# 生成一个最小配置（可参考上面的示例）
cat > config/config.toml <<'EOF'
[server]
host = "127.0.0.1"
port = 8080

[log]
log_file_path = "logs/sub.log"
level = "debug"
EOF

# 运行服务（数据库和 schema 会自动创建）
cargo run --release
```

注意：本项目在启动时会在 `data/` 下创建 `sub.db`（若不存在），并自动创建用户与管理员表结构，因此不依赖 `sqlx migrate` 来初始化表结构。

---

## Docker 使用建议 🔧
- 容器内的数据目录挂载：把宿主机的 `./data`、`./config` 挂载到容器，以便持久化数据库与配置。
- 建议使用反向代理（Nginx / Caddy）在生产环境提供 HTTPS；并将 `SessionMiddleware` 的 `cookie_secure` 设置为 `true`。

示例 `docker compose`：见 `compose.yml`（默认将 `CONFIG` 与 `DATA` 映射到宿主机）。

---

## HTTP API（管理/业务接口）📡
所有管理接口需要先通过 Cookie 登录（前端登录会使用 `/api/auth/login`）。

- POST /api/auth/login
  - 请求体: `{ "username": "admin", "password": "password" }`
  - 登录成功后会设置 Cookie，用于后续管理接口。

- POST /api/auth/logout — 退出登录。
- GET /api/auth/me — 获取当前登录用户。
- PUT /api/auth/account — 更新管理员用户名/密码。

- GET /api/users — 返回按排序的用户名数组（需登录）。
- POST /api/users — 创建用户，body: `{ "username": "foo" }`。
- DELETE /api/users/{username} — 删除用户。
- PUT /api/users/order — 更新用户顺序，body: `{ "order": ["u1","u2"] }`。
- GET /api/users/{username}/links — 获取用户的订阅链接数组。
- PUT /api/users/{username}/links — 更新用户的链接，body: `{ "links": ["https://a.com","https://b.com"] }`。

- GET /{username} — **核心业务接口**，按用户配置的顺序并发抓取每个链接（client 超时 10s，默认并发 5）并返回合并后的纯文本（Content-Type: text/plain）。
- GET /healthz — 健康检查 (HTTP 200 返回 `ok`)。

示例：使用 curl 登录并访问管理接口

```bash
# 登录并保存 cookie 到 cookies.txt
curl -c cookies.txt -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"password"}' http://127.0.0.1:8080/api/auth/login

# 使用 cookie 请求用户列表
curl -b cookies.txt http://127.0.0.1:8080/api/users

# 获取某用户合并后的文本
curl http://127.0.0.1:8080/example_user
```

---

## 前端（web UI）📱
前端资源静态保存在 `web/` 目录。登录到管理后台后可以创建用户、配置每个用户的订阅链接、拖拽排序并删除用户。

---

## 日志与监控 📊
- 控制台输出（适合 Docker logs）：紧凑、彩色
- 文件输出（JSON 格式，按天轮转）：路径由 `config/config.toml` 中 `log.log_file_path` 指定（默认 `/app/logs/sub.log`）。
- 容器镜像拥有健康检查（`HEALTHCHECK` 依赖 `/healthz` 接口）。

---

## 部署和安全建议 🔐
- 在生产环境中：使用 HTTPS（例如 Nginx / Caddy 反向代理）并将 cookie 改为 secure。
- SSRF 风险：应用会对所有配置的链接发起抓取请求，建议在防火墙层限制出站请求或使用网络策略来阻止访问内网地址。
- 超时和并发限制：`main.rs` 中使用 `reqwest::Client` 的超时时间为 10s，默认并发数为 5（在代码中常量 `CONCURRENT_REQUESTS_LIMIT`），如有必要可改造代码使其可配置。

---

## 贡献与开发建议 🤝
- 请在提交 PR 前确保代码通过 `cargo fmt` 和基本的 `cargo clippy` 检查。
- 若需要在代码层面改变 schema，请提供兼容的数据库迁移或兼容逻辑（当前项目在启动时自动创建表结构）。

---

## 许可证
本仓库当前没有添加许可证文件。若要发布或允许贡献者复用，请考虑添加合适的开源许可证（例如 MIT / Apache-2.0）。

---

作者: vansour
如果需要 README 中包含更多示例、API 细节或演示截图，请告诉我，我可以进一步补充。

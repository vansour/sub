# Sub — 多用户多链接合并器 (Rust + Actix)

这是一个用 Rust (actix-web) 编写的简单 Web 应用，用于管理多个用户及每个用户的若干链接，并能在访问 /{username} 时合并并返回该用户所有链接的页面内容。

主要功能
- 浏览用户列表
- 添加 / 删除 用户
- 编辑某用户的多链接（每行一个 URL）
- 打开 /{username} 查看合并后的页面内容（服务端抓取每个链接并合并）

运行说明
1. 安装 Rust 工具链（https://rustup.rs）
2. 必须设置服务端 API 密钥（UI 访问需携带正确的 api 参数）。你可以通过环境变量来设置：

```bash
export SUB_API_KEY=some-secret-value
```

3. 在仓库根目录运行本地二进制：

```bash
cargo run --release
```

Docker / Docker Compose（推荐用于生产或容器化运行）

设置 API Key（compose 会把环境变量 SUB_API_KEY 注入容器）：

```bash
export SUB_API_KEY=my-secret-key
```

使用 Docker Compose 来构建并运行：

```bash
docker compose up --build -d
```

服务会在 http://127.0.0.1:8080 可用，访问时请使用 ?api= 参数，例如：

http://127.0.0.1:8080/?api=my-secret-key


3. 打开浏览器访问 http://127.0.0.1:8080

存储
数据保存在项目的 data/data.toml（TOML 格式），Docker 镜像默认在 /app/data/data.toml。示例格式：

```toml
[[users]]
username = "alice"
links = ["https://example.com", "https://rust-lang.org"]
```

安全说明
服务器会在后端请求并返回第三方 HTML 内容，生产环境中请注意 XSS、CSP 和请求超时等安全限制。

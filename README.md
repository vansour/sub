# Sub — 多用户多链接合并器 (Rust + Actix)

这是一个用 Rust (actix-web) 编写的简单 Web 应用，用于管理多个用户及每个用户的若干链接，并能在访问 /{username} 时合并并返回该用户所有链接的页面内容。

主要功能
- 浏览用户列表
- 添加 / 删除 用户
- 编辑某用户的多链接（每行一个 URL）
- 打开 /{username} 查看合并后的页面内容（服务端抓取每个链接并合并）
链接合并顺序
-----------------
服务端现在会按照用户在 UI 中配置的链接顺序（从上到下）并发抓取各链接内容，但是最终合并输出会以正序（即与配置顺序相同）拼接，保证最终结果顺序一致。

保留换行
-----------------
服务端在把抓取到的 HTML 转换为纯文本时会保留常见的换行语义：
- 会把 <br> 转换为换行
- 会将块级标签（例如 <p>, <div>, <li> 等）视为段落分隔（插入空行）
- 保留 <pre> 区块内的原始换行和空格（不被折叠）

这能避免把原本包含多行的内容合并成一行，体验更接近网页的原始文本。

保留空格和制表符
-------------------
服务器现在会尽量保留链接内容中的空格（spaces）和制表符（tabs），不再在转换过程中把它们折叠或删除。这对于需要保留缩进、对齐或源码片段的场景很有用。

用户列表拖拽排序
-------------------
前端支持通过拖拽用户列表行来调整用户显示顺序，拖拽完成后会自动保存新的顺序到后端并写入 `data/data.toml`。如果需要手动更新排序，可以使用如下 API：

PUT /api/users/order

请求示例（JSON body）:

```json
{"order": ["alice", "bob", "charlie"]}
```

返回：

200 OK，返回保存后的顺序数组。


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

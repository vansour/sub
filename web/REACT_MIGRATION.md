# React 前端迁移指南

## 概述

前端已从原生 JavaScript 重写为 React 应用，具有以下优势：

- **组件化架构**：使用 React 组件进行代码复用和管理
- **状态管理**：使用 React Context 管理全局状态
- **更好的错误处理**：统一的 API 错误处理和用户通知
- **现代化构建**：使用 Vite 进行快速开发和优化构建
- **更少的全局变量**：所有状态都在 React 组件中管理

## 目录结构

```
web/
├── app.jsx                    # 主应用组件
├── main.jsx                   # React 入口文件
├── index-react.html           # React HTML 模板
├── style-react.css            # React 样式表
├── package.json               # 项目依赖配置
├── vite.config.js             # Vite 构建配置
├── components/                # React 组件
│   ├── Header.jsx            # 顶部导航栏
│   ├── UserList.jsx          # 用户列表容器
│   ├── UserTable.jsx         # 用户表格
│   ├── UserModal.jsx         # 添加/编辑用户弹窗
│   ├── QRModal.jsx           # 二维码弹窗
│   ├── ConfirmModal.jsx      # 确认对话框
│   └── SettingsModal.jsx     # 账号设置弹窗
├── pages/                     # 页面组件
│   └── LoginPage.jsx         # 登录页面
├── layouts/                   # 布局组件
│   └── MainLayout.jsx        # 主布局
├── context/                   # React Context
│   ├── AuthContext.js        # 认证状态上下文
│   └── NotificationContext.js# 通知状态上下文
├── services/                  # API 服务
│   └── api.js                # API 请求封装
└── 旧文件（保留）
    ├── index.html            # 原生 JS 版本
    ├── script.js             # 原生 JS 脚本
    └── style.css             # 原生样式表
```

## 安装和构建

### 开发环境

```bash
cd web

# 安装依赖
npm install

# 启动开发服务器（运行在 http://localhost:3000）
npm run dev
```

开发服务器会自动代理 `/api` 请求到后端（默认 http://localhost:8080）

### 生产构建

```bash
cd web

# 安装依赖
npm install

# 构建生产版本
npm run build

# 输出文件在 dist/ 目录中
```

### Docker 部署

修改后端 Dockerfile，使用构建后的 React 应用：

```dockerfile
# 构建前端（需要 Node.js）
FROM node:18 AS web-builder
WORKDIR /web
COPY web/package*.json ./
RUN npm install
COPY web/ .
RUN npm run build

# 使用 Rust 镜像构建后端
FROM rust:latest AS backend-builder
# ... 后端构建步骤 ...

# 最终镜像
FROM debian:bookworm-slim
# ... 复制后端和前端文件 ...
COPY --from=web-builder /web/dist /app/web
```

## 迁移对比

### 原生 JS 版本的问题

- 全局变量污染（`base`, `isEditMode`, `originalUsername` 等）
- 代码重复（多个弹窗打开/关闭逻辑）
- 错误处理不统一
- 没有使用现代前端框架
- API 请求没有集中管理

### React 版本的优势

| 特性 | 原生 JS | React |
|------|--------|-------|
| 全局变量 | 多个 | 零个 |
| 组件复用 | 困难 | 容易 |
| 状态管理 | 手动 | React Context |
| 错误处理 | 分散 | 统一 |
| 代码行数 | 600+ | 400+ |
| 打包大小 | ~20KB | ~40KB (gzip) |

## 核心组件说明

### AuthContext

管理认证状态和操作：

```javascript
{
  isAuthenticated,  // 是否已认证
  onLogin(token),   // 登录函数
  onLogout()        // 登出函数
}
```

### NotificationContext

显示用户通知/提示消息：

```javascript
const { showNotification } = useNotification();
showNotification('消息内容', 'success', 3000); // type: info | success | warning | error
```

### API Service

统一的 API 请求层（`services/api.js`）：

- 自动添加认证 token
- 统一错误处理（如 401 自动跳转登录）
- 使用 `ApiError` 异常类

### UserList 组件

用户列表的主容器，包含：

- 加载、错误、空状态处理
- 用户 CRUD 操作
- 拖拽排序
- 模态框管理

## 环境变量

可以通过 Vite 环境变量配置后端地址：

创建 `.env` 或 `.env.production` 文件：

```
VITE_API_BASE=http://api.example.com
```

在代码中使用：

```javascript
const API_BASE = import.meta.env.VITE_API_BASE || window.location.origin;
```

## 浏览器兼容性

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- 不支持 IE11

## 生产优化

1. **代码分割**：Vite 自动分割代码块
2. **Tree Shaking**：移除未使用的代码
3. **Minification**：使用 Terser 压缩
4. **Image Optimization**：可配置图片优化
5. **Lazy Loading**：支持组件懒加载

## 故障排除

### API 请求 401 错误

- 检查认证 token 是否过期
- 检查后端 JWT_SECRET 配置
- 查看浏览器开发者工具的 Network 标签

### 样式不生效

- 确保使用 `style-react.css` 而不是 `style.css`
- 检查 Vite 是否正确加载 CSS 文件
- 清空浏览器缓存

### 构建失败

- 检查 Node.js 版本 (需要 16+)
- 删除 `node_modules` 和 `package-lock.json`，重新安装
- 检查是否有 TypeScript 错误（如果使用 TS）

## 下一步

1. 将原生 JS 版本的 `index.html` 替换为 `index-react.html`
2. 更新 Dockerfile 构建前端
3. 配置 Web 服务器提供静态文件
4. 运行生产构建并测试

## 参考资源

- [React 文档](https://react.dev)
- [Vite 文档](https://vitejs.dev)
- [React Hooks 文档](https://react.dev/reference/react)

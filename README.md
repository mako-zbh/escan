# eScan — 漏洞扫描工具链

基于 **FOFA/Hunter** + **Nuclei** + **MIIT ICP** + **DeepSeek AI** 的漏洞扫描工具链，提供 **React SPA Web Dashboard** 实时监控。

---

## 🚀 快速开始

### 方式一：Docker（推荐）

```bash
# 1. 配置环境变量
cp .env .env.local
# 编辑 .env.local 填入 FOFA_KEY / HUNTER_API_KEY / DB_PASSWORD 等

# 2. 一键构建 + 启动（含 PostgreSQL）
./scripts/docker-build.sh

# 浏览器打开 http://localhost:5050
```

其他命令：
```bash
./scripts/docker-build.sh --build-only   # 仅构建镜像
./scripts/docker-build.sh --stop         # 停止服务
./scripts/docker-build.sh --logs         # 查看实时日志
./scripts/docker-build.sh --restart      # 重建并重启
```

### 方式二：本地开发

```bash
git clone <repo> && cd tools

# 后端
pip install -r requirements.txt
cp .env .env.local   # 编辑 .env.local 填入真实值

# 前端
cd frontend && npm install && cd ..

# 初始化数据库（首次使用）
python scripts/init_db.py --create

# 启动
uvicorn escan.web.app:app --host 0.0.0.0 --port 5050
```

浏览器打开 `http://localhost:5050`。

---

## ✨ 核心特性

| 特性 | 说明 |
|------|------|
| 🔍 **多引擎资产收集** | FOFA / Hunter 双引擎，地域筛选 |
| ⚡ **Nuclei 漏洞扫描** | 每个模板独立扫描专属资产，避免交叉扫描 |
| 📋 **ICP 备案查询** | 爱站反查 + MIIT 官方 API（滑块验证码自动识别 + IPv6 代理轮换） |
| 🤖 **AI 模板生成** | DeepSeek AI 从漏洞描述生成 Nuclei YAML 模板，含 OCR + 4 级查重 |
| 🖥️ **Web Dashboard** | React + TypeScript + Vite，实时日志 SSE 推送 |
| 🔄 **断点续扫** | `--resume` 从上次中断位置继续 |
| 🧠 **增量扫描** | 24h 缓存命中跳过，仅查询新模板 |
| 🌐 **全局代理池** | 轮询/随机策略，各组件独立开关，批量验证添加 |
| ⚙️ **配置热重载** | 修改 `.env` / `.env.local` 后无需重启，`POST /api/config/reload` 即时生效 |
| 🐳 **Docker 一键部署** | docker-compose：PostgreSQL + eScan 单端口运行 |

---

## 🏗️ 架构

```
┌─ CLI ──────────────────────────────────────────────────┐
│  escan agent convert|batch|check     AI 模板生成     │
│  escan pipeline categorized|search    扫描流水线     │
│  escan server                         Web 服务启动    │
└────────────────────────────────────────────────────────┘

┌─ Web Dashboard (:5050) ───────────────────────────────┐
│  React + TypeScript + Vite                             │
│  模板库 · 漏洞总览 · ICP 查询 · 扫描控制 · 配置管理    │
│  代理池管理 · 实时日志 SSE · 进度推送                    │
└────────────────────────────────────────────────────────┘
                           ↕ HTTP
┌─ FastAPI (:5050) ─────────────────────────────────────┐
│  REST API + PostgreSQL 13 表 + MIIT 官方 ICP            │
│  SSE 事件流：进度 + 日志 + 实时推送                      │
└────────────────────────────────────────────────────────┘

┌─ Pipeline ─────────────────────────────────────────────┐
│  Step 1: FOFA/Hunter 资产收集（可配资产数 1-10000）     │
│  Step 2: Nuclei 模板扫描（每模板只扫专属资产）           │
│  Step 3: Host/IP 提取                                   │
│  Step 4: ICP 备案查询（爱站 + MIIT 官方）                │
└────────────────────────────────────────────────────────┘
```

---

## 🔧 配置

加载优先级：**环境变量 > .env.local > .env > 默认值**。

> 💡 修改配置文件后无需重启服务：`curl -X POST http://localhost:5050/api/config/reload`
> 前端配置管理页面支持 `.env` / `.env.local` 双标签编辑。

### 搜索引擎

| 环境变量 | 说明 |
|---|---|
| `FOFA_KEY` | FOFA 官方 API Key（推荐，优先级高于代理）|
| `FOFA_API` | FOFA 代理接口地址 |
| `FOFA_PROXY_COOKIE` | FOFA 代理 Cookie |
| `FOFA_SIZE` | 每模板查询资产数（默认 `100`） |
| `HUNTER_API_KEY` | Hunter 官方 API Key（推荐） |
| `HUNTER_API` | Hunter 官方 API（默认 `https://hunter.qianxin.com/openApi/search`） |
| `HUNTER_SIZE` | 每模板查询资产数（默认 `100`） |
| `SEARCH_ENGINE` | 默认引擎 `fofa` |

### 数据库

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `DB_HOST` | `localhost` | PostgreSQL 主机 |
| `DB_PORT` | `5432` | 端口 |
| `DB_NAME` | `escan` | 数据库名 |
| `DB_USER` | `escan` | 用户名 |
| `DB_PASSWORD` | （空） | 密码，未配置时 DB 功能跳过 |

### 代理池

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `PROXY_FILE` | `proxies.txt` | 代理列表文件 |
| `PROXY_STRATEGY` | `round_robin` | 策略：`round_robin` / `random` |
| `PROXY_COOLDOWN` | `60` | 失败冷却秒数 |
| `PROXY_MAX_FAILURES` | `3` | 连续失败阈值 |
| `PROXY_ENABLED_FOFA` | `0` | FOFA 启用代理 |
| `PROXY_ENABLED_HUNTER` | `0` | Hunter 启用代理 |
| `PROXY_ENABLED_NUCLEI` | `0` | Nuclei 启用代理 |
| `PROXY_ENABLED_ICP` | `0` | ICP 查询启用代理 |
| `PROXY_ENABLED_DEEPSEEK` | `0` | DeepSeek 启用代理 |

### 其他

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `DEEPSEEK_API_KEY` | — | DeepSeek API 密钥（agent 命令必填） |
| `DEEPSEEK_MODEL` | `deepseek-v4-flash` | AI 模型 |
| `LOG_LEVEL` | `INFO` | 日志级别 |
| `AGENT_CONCURRENCY` | `3` | 批量转换并发数 |
| `ICP_THREADS` | `2` | ICP 查询并发数 |
| `AIZHAN_COOKIE` | — | 爱站 Cookie |

---

## 📖 命令参考

### Agent — AI 模板生成

```bash
escan agent convert <md>              # 单文件转换
escan agent convert <md> --force      # 强制重新生成（忽略查重）
escan agent check <md|dir>            # 查重检测（不生成 POC）
escan agent batch <dir>               # 批量转换（仅新增，自动查重）
escan agent batch <dir> --force       # 强制全量生成
```

**查重引擎（四级匹配）：**

| 级别 | 条件 | 动作 |
|---|---|---|
| L1-CVE | CVE 编号一致 | 跳过 |
| L2-FOFA+Path | FOFA + 请求路径一致 | 跳过 |
| L3-FOFA | FOFA 语法一致 | 跳过 |
| L4-Title | 标题相似度 > 80% | 仅警告 |

L1-L3 命中自动跳过 API 调用，`--force` 忽略查重。

**转换流程：** 解析 MD → OCR 截图 → 查重检测 → DeepSeek API 生成 YAML → nuclei 校验 → 原子写入。

### Pipeline — 扫描流水线

```bash
# 基础用法
escan pipeline categorized [poc_dir]              # 全量分类扫描
escan pipeline categorized-incremental [poc_dir]   # 增量扫描（24h 缓存）
escan pipeline categorized --resume                 # 从断点恢复
escan pipeline search <query>                       # 单条资产查询
escan pipeline status                               # 扫描状态概览

# 地域筛选（可选，留空查全部）
escan pipeline categorized --region CN              # 仅查中国资产
escan pipeline categorized --region 北京            # 仅查北京

# Web UI 中还可指定每模板资产数（默认 100，最大 10000）
```

**4 步流水线：** 资产收集 → Nuclei 扫描 → Host 提取 → ICP 备案查询

### Server — Web 服务

```bash
# 本地开发
uvicorn escan.web.app:app --host 0.0.0.0 --port 5050

# 启动器
uv run escan server
```

---

## 🖥️ Web Dashboard

前端基于 **React + TypeScript + Vite**，后端 FastAPI 单端口托管。

| 模块 | 说明 |
|---|---|
| **Dashboard** | 统计概览：任务数、漏洞数、资产数 |
| **模板库** | 浏览/筛选/搜索 Nuclei 模板，查看资产、命中、ICP 统计 |
| **扫描任务** | 启动扫描（类型/引擎/地域/资产数）、实时日志 SSE 推送、进度显示 |
| **漏洞总览** | 跨模板漏洞表，ICP 备案关联，CSV 导出 |
| **ICP 查询** | 输入域名或单位名，调用 MIIT 官方 API |
| **代理池管理** | 添加/删除/测试代理，批量验证添加，各组件独立开关 |
| **配置管理** | `.env` + `.env.local` 双标签在线编辑，保存后热重载 |
| **实时日志** | 扫描过程中各步骤实时推送至浏览器 |

---

## 🐳 Docker 部署

### 文件结构

```
├── Dockerfile                  # 三阶段构建（Node → Nuclei → Python）
├── docker-compose.yml          # PostgreSQL + eScan 服务编排
├── .dockerignore
└── scripts/
    ├── docker-build.sh         # 一键构建启动脚本
    └── docker-entrypoint.sh    # 容器入口（DB 等待 → 迁移 → 启动）
```

### 挂载卷

| 路径 | 类型 | 用途 |
|------|------|------|
| `output/` | 命名卷 | 扫描输出结果 |
| `logs/` | 命名卷 | 运行时日志 |
| `nuclei-poc/` | 绑定挂载 | Nuclei POC 模板 |
| `proxies.txt` | 绑定挂载 | 代理列表 |
| `.env` / `.env.local` | 绑定挂载 | 配置文件 |

### 架构

```
docker-compose.yml
├── db (postgres:16-alpine, 5432)
│   └── pgdata 卷
└── escan (escan:latest, 5050)
    ├── output 卷
    ├── logs 卷
    ├── ./nuclei-poc → /app/nuclei-poc
    ├── ./proxies.txt → /app/proxies.txt
    ├── ./.env → /app/.env
    └── ./.env.local → /app/.env.local
```

---

## 🗄️ 数据库

### Schema 迁移（v0 → v7）

| v | 内容 |
|---|------|
| 1 | 8 张核心表：模板、任务、资产、结果、ICP、缓存、去重、版本 |
| 2 | scan_results/host_results/icp_results 去重约束 |
| 3 | checkpoint_snapshots 断点续扫 |
| 4 | template_scan_coverage、icp_stats、URL 注册表、物化视图 |
| 5 | scan_logs 实时日志 |
| 6 | icp_results 增加 template_id + asset_id 直接关联 |
| 7 | dedup query 索引优化 |

### 初始化

```bash
# 查看当前状态
python scripts/init_db.py --status

# 首次初始化
python scripts/init_db.py --create

# 删除重建
python scripts/init_db.py --drop
```

### 表结构

13 张表 + 3 个物化视图：

```
poc_templates ──── 模板库
scan_tasks ─────── 扫描任务
discovered_assets  发现资产
scan_results ───── Nuclei 命中
host_results ───── 提取的主机/域名
icp_results ────── ICP 备案
query_cache ────── 查询缓存
dedup_index ────── AI 去重索引
scan_logs ──────── 扫描实时日志
checkpoint_snapshots  断点续扫
template_scan_coverage 模板覆盖
template_icp_stats ── ICP 统计
global_url_registry ─  URL 注册表
```

---

## 📁 项目结构

```
tools/
├── escan/
│   ├── config.py              # 集中配置（热重载支持）
│   ├── cli.py                 # CLI 入口
│   ├── agent/                 # AI 模板生成
│   │   ├── converter.py       # MD→YAML 核心转换器
│   │   ├── prompts.py         # 7 种漏洞类型 Prompt
│   │   ├── ocr.py             # GLM-OCR 图片识别
│   │   ├── validator.py       # YAML 校验 + 自动重试
│   │   └── dedup.py           # 4 级查重引擎
│   ├── pipeline/              # 扫描流水线
│   │   ├── orchestrator.py    # 流水线编排器
│   │   ├── fofa.py            # FOFA 查询
│   │   ├── hunter.py          # Hunter 查询
│   │   ├── nuclei.py          # Nuclei 扫描调用
│   │   ├── icp.py             # ICP 查询（爱站）
│   │   ├── miit_icp.py        # MIIT 官方 ICP
│   │   ├── cache.py           # 增量缓存
│   │   └── checkpoint.py      # 断点续扫
│   ├── database/              # 数据访问层
│   │   ├── models.py          # DDL + 7 版迁移
│   │   ├── dao.py             # CRUD 操作
│   │   └── connection.py      # 连接池
│   ├── utils/
│   │   ├── network.py         # IP/YAML/FOFA 解析
│   │   ├── proxy.py           # 代理池
│   │   └── retry.py           # 指数退避重试
│   └── web/                   # FastAPI
│       ├── app.py             # 应用入口 + 前端静态托管
│       ├── routes.py          # REST + SSE 路由
│       ├── models.py          # Pydantic 模型
│       ├── sse.py             # SSE 事件流管理器
│       └── launcher.py        # 启动器
├── frontend/                  # React + TypeScript + Vite
│   ├── src/
│   │   ├── pages/             # Dashboard / Scan / Config / Proxy 等
│   │   ├── components/        # 复用组件
│   │   ├── hooks/             # useSSE / useSSELogs
│   │   ├── services/api.ts    # API 调用
│   │   └── types/index.ts     # TypeScript 类型定义
│   └── package.json
├── Dockerfile                 # 多阶段构建
├── docker-compose.yml         # 服务编排
├── scripts/
│   ├── docker-build.sh        # 构建启动脚本
│   ├── docker-entrypoint.sh   # 容器入口
│   └── init_db.py             # 数据库初始化
├── .env                       # 配置模板
├── .env.local                 # 本地配置（不提交 Git）
└── pyproject.toml
```

---

## 🔌 API 概览

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/stats` | 仪表盘统计 |
| `GET` | `/api/templates` | 模板列表 |
| `POST` | `/api/scans` | 触发扫描 |
| `GET` | `/api/scans/{id}/stream` | SSE 进度流 |
| `GET` | `/api/scans/{id}/logs/stream` | SSE 日志流 |
| `GET` | `/api/scans/{id}/logs` | 历史日志 |
| `GET` | `/api/config?source=env|local` | 读取配置 |
| `PUT` | `/api/config?source=env|local` | 保存配置 |
| `POST` | `/api/config/reload` | 热重载配置 |
| `GET` | `/api/proxy/status` | 代理池状态 |
| `POST` | `/api/proxy/add` | 添加代理 |
| `POST` | `/api/proxy/batch-test` | 批量测试代理 |
| `POST` | `/api/proxy/batch-add` | 批量添加代理 |
| `PUT` | `/api/proxy/toggle` | 组件代理开关 |
| `GET` | `/api/docs` | Swagger 文档 |

---

## 📄 License

MIT

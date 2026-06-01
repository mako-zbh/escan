# eScan — 漏洞扫描工具链 v1

基于 FOFA/Hunter + Nuclei + MIIT ICP + DeepSeek AI 的漏洞扫描工具链，提供 Web Dashboard 实时监控。

## 快速开始

```bash
git clone <repo> && cd tools
uv sync
cd frontend && npm install && cd ..

# 配置环境变量
cp .env .env.local   # 编辑 .env.local 填入真实值

# 启动 Web 服务（API :5050 + Dashboard :3000）
uv run escan server
```

浏览器打开 `http://localhost:3000`。

## 架构

```
┌─ CLI ─────────────────────────────────────────────────┐
│  escan agent convert|batch|check     AI 模板生成    │
│  escan pipeline categorized|search    扫描流水线    │
│  escan server                         Web 服务启动   │
└───────────────────────────────────────────────────────┘

┌─ Web Dashboard (:3000) ───────────────────────────────┐
│  模板库浏览 · 漏洞总览 · ICP 查询 · 扫描控制 · 配置管理  │
└───────────────────────────────────────────────────────┘
                           ↕ HTTP
┌─ Flask API (:5050) ───────────────────────────────────┐
│  REST API + PostgreSQL 14 表 + MIIT 官方 ICP           │
└───────────────────────────────────────────────────────┘

┌─ Pipeline ────────────────────────────────────────────┐
│  Step 1: FOFA/Hunter 资产收集                          │
│  Step 2: Nuclei 模板扫描                               │
│  Step 3: Host/IP 提取                                  │
│  Step 4: ICP 备案查询 (爱站 + MIIT 官方)                │
└───────────────────────────────────────────────────────┘
```

## 配置

加载优先级：**环境变量 > .env.local > .env > 默认值**。

### 必填

| 环境变量 | 说明 |
|---|---|
| `DEEPSEEK_API_KEY` | DeepSeek API 密钥（agent 命令必填） |

### 搜索引擎

| 模式 | FOFA | Hunter |
|---|---|---|
| 官方 API（推荐） | `FOFA_KEY` | `HUNTER_API_KEY` |
| 代理 Cookie | `FOFA_PROXY_COOKIE` | `HUNTER_PROXY_COOKIE` |

不配置时 FOFA 走内置默认代理，开箱即用。

### 数据库

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `DB_HOST` | `localhost` | PostgreSQL 主机 |
| `DB_PORT` | `5432` | PostgreSQL 端口 |
| `DB_NAME` | `escan` | 数据库名 |
| `DB_USER` | `escan` | 用户名 |
| `DB_PASSWORD` | （空） | 密码，未配置时 DB 功能跳过 |

### 其他

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `DEEPSEEK_MODEL` | `deepseek-v4-flash` | AI 模型 |
| `FOFA_SIZE` | `100` | 单次查询条数 |
| `NUCLEI_PATH` | 自动查找 `$PATH` | nuclei 路径 |
| `LOG_LEVEL` | `INFO` | 日志级别 |
| `AGENT_CONCURRENCY` | `3` | 批量转换并发数 |

---

## 命令参考

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
escan pipeline categorized-incremental --region Shanghai
escan pipeline search 'app="nginx"' --region 广东
```

**地域筛选规则：** 2-3 位全大写字母（CN/US/HK）→ `country` 过滤，其余（中文或长英文）→ `region` 过滤。留空不追加过滤条件。

**4 步流水线：** 资产收集 → Nuclei 扫描 → Host 提取 → ICP 备案查询

### Server — Web 服务

```bash
escan server     # 同时启动 API (:5050) + Dashboard (:3000)
```

---

## Web Dashboard

Dashboard 提供以下功能模块：

| 模块 | 入口 | 说明 |
|---|---|---|
| 模板库 | 左侧面板 | 浏览/筛选/搜索 Nuclei 模板，查看资产、命中、ICP 统计 |
| 模板详情 | 点击模板 | 资产 URL、域名、ICP 备案、扫描命中 四个子视图 |
| 漏洞总览 | Header「漏洞总览」 | 跨模板漏洞表：名称、资产、ICP 域名/备案号/主体、扫描时间 |
| 漏洞筛选 | 总览页 Tab | 「全量」/「有ICP备案」切换，host 级别精确匹配 |
| ICP 查询 | Header「ICP 查询」 | 输入域名或单位名，调用 MIIT 官方 API 查备案 |
| 扫描控制 | Header「执行扫描」 | 选择扫描类型、引擎、地域筛选，提交后台任务，实时日志 |
| 配置编辑 | Header「配置」 | 在线编辑 `.env` 文件，自动备份 |
| CSV 导出 | 漏洞总览页 | 导出当前筛选结果为 CSV |

---

## 数据库

### 初始化

```bash
# 查看当前状态（表名、行数、Schema 版本）
uv run python scripts/init_db.py --status

# 首次初始化（建库 + 执行所有迁移）
uv run python scripts/init_db.py --create

# 删除旧库后重建
uv run python scripts/init_db.py --drop

# 仅执行迁移（库已存在时）
uv run python scripts/init_db.py
```

配置从 `.env` 读取（`DB_HOST`、`DB_PORT`、`DB_NAME`、`DB_USER`、`DB_PASSWORD`）。

### 迁移系统

6 版增量迁移，版本号记录在 `schema_version` 表：

| v | 内容 |
|---|------|
| 1 | 8 张核心表：模板、任务、资产、结果、ICP、缓存、去重、版本 |
| 2 | scan_results/host_results/icp_results 去重约束 |
| 3 | checkpoint_snapshots 断点续扫 |
| 4 | template_scan_coverage 覆盖统计、icp_stats、URL 注册表、物化视图 |
| 5 | scan_logs 实时日志 |
| 6 | icp_results 增加 template_id + asset_id 直接关联 |

启动 Web 服务时自动执行迁移（`escan server`），无需手动操作。

### 表结构

14 张表 + 3 个物化视图：

```
poc_templates ──── 模板库
scan_tasks ─────── 扫描任务
discovered_assets  发现资产 (FK→模板+任务)
scan_results ───── Nuclei 命中 (FK→模板+任务+资产)
host_results ───── 提取的主机/域名 (FK→任务)
icp_results ────── ICP 备案 (FK→模板+任务+资产)
query_cache ────── FOFA/Hunter 查询缓存
dedup_index ────── AI 去重索引 (FK→模板)
scan_logs ──────── 扫描实时日志 (FK→任务)
checkpoint_snapshots  断点续扫快照 (FK→任务)
template_scan_coverage 模板扫描覆盖状态
template_icp_stats ─── 模板 ICP 统计
global_url_registry ── 跨模板 URL 注册表
schema_version ──── 迁移版本管理
```

---

## 项目结构

```
tools/
├── escan/
│   ├── cli.py                 # CLI 入口
│   ├── config.py              # 集中配置（.env 加载）
│   ├── agent/                 # AI 模板生成
│   │   ├── converter.py       # MD→YAML 核心转换器
│   │   ├── prompts.py         # 7 种漏洞类型 Prompt
│   │   ├── ocr.py             # GLM-OCR 图片识别
│   │   ├── validator.py       # YAML 校验 + 自动重试
│   │   └── dedup.py           # 4 级查重引擎
│   ├── pipeline/              # 扫描流水线
│   │   ├── orchestrator.py    # 流水线编排器
│   │   ├── fofa.py            # FOFA 查询（官方/代理双模式）
│   │   ├── hunter.py          # Hunter 查询
│   │   ├── nuclei.py          # Nuclei 扫描调用
│   │   ├── icp.py             # ICP 查询（爱站 + ip138）
│   │   ├── miit_icp.py        # MIIT 官方 ICP（集成 ICP_Query）
│   │   ├── cache.py           # 增量扫描缓存
│   │   └── checkpoint.py      # 断点续扫
│   ├── database/              # 数据访问层
│   │   ├── models.py          # DDL + 6 版迁移
│   │   ├── dao.py             # CRUD 操作
│   │   └── connection.py      # 连接池
│   ├── web/                   # Flask API
│   │   ├── app.py             # 应用入口
│   │   ├── routes.py          # REST 路由
│   │   ├── log_handler.py     # DB 日志处理器
│   │   └── launcher.py        # 统一启动器
│   └── utils/
│       ├── network.py         # IP/YAML/FOFA 解析
│       ├── files.py           # 文件 I/O
│       └── retry.py           # 指数退避重试
├── frontend/                  # Web Dashboard
│   ├── server.js              # Express 静态服务
│   └── public/
│       ├── index.html
│       ├── css/style.css
│       └── js/                # api, app, dashboard, templates,
│                              #   detail, scan, config, vuln, icp_query
├── nuclei-poc/                # Nuclei YAML 模板目录
├── output/                    # 流水线输出目录
├── .env                       # 配置模板
├── pyproject.toml
└── README.md
```

## 引用

本项目集成了 [ICP_Query](https://github.com/HG-ha/ICP_Query) — 工信部官方 ICP 备案查询引擎，支持滑块验证码自动识别和 IPv6 代理池轮换。

## License

MIT

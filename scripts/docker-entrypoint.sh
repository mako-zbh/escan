#!/usr/bin/env bash
# ============================================================
# docker-entrypoint.sh — eScan Docker 容器入口
# 1. 等待 PostgreSQL 就绪
# 2. 初始化数据库（创建 + 迁移）
# 3. 启动 uvicorn
# ============================================================
set -e

# 颜色
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log()   { echo -e "${GREEN}[eScan]${NC} $1"; }
warn()  { echo -e "${YELLOW}[eScan]${NC} $1"; }
error() { echo -e "${RED}[eScan]${NC} $1"; }

# ---- 1. 初始化 Nuclei 模板（后台超时运行，不阻塞启动） ----
if command -v nuclei &>/dev/null; then
    if [ ! -d "$HOME/.nuclei-templates" ] || [ -z "$(ls -A "$HOME/.nuclei-templates" 2>/dev/null)" ]; then
        log "后台下载 Nuclei 模板（不影响启动）..."
        # 后台下载，30 秒超时，不阻塞主进程
        timeout 30 nuclei -update-templates 2>/dev/null && \
            log "Nuclei 模板下载完成" || \
            warn "Nuclei 模板下载超时/失败（扫描时会自动下载）" &
    fi
fi

# ---- 2. 等待 PostgreSQL ----
if [ -n "$DB_HOST" ] && [ -n "$DB_PASSWORD" ]; then
    log "等待 PostgreSQL ($DB_HOST:$DB_PORT) 就绪..."
    for i in $(seq 1 30); do
        if python3 -c "
import psycopg2
try:
    psycopg2.connect(host='$DB_HOST', port=$DB_PORT, user='$DB_USER',
                     password='$DB_PASSWORD', dbname='postgres')
    print('ready')
except Exception:
    pass
" 2>/dev/null | grep -q ready; then
            log "PostgreSQL 就绪"
            break
        fi
        if [ "$i" -eq 30 ]; then
            error "PostgreSQL 未就绪，请检查 DB_HOST/DB_PORT/DB_USER/DB_PASSWORD"
            exit 1
        fi
        sleep 1
    done

# ---- 3. 初始化数据库 ----
    log "初始化数据库..."
    python3 scripts/init_db.py --create || {
        warn "数据库初始化失败（可忽略，可能已初始化）"
    }
else
    warn "DB_HOST 或 DB_PASSWORD 未设置，跳过数据库初始化（无数据库模式运行）"
fi

# ---- 4. 启动 Uvicorn ----
log "启动 eScan 服务 (http://0.0.0.0:5050)"
log "API 文档: http://localhost:5050/api/docs"

LOG_LEVEL="${LOG_LEVEL:-INFO}"
exec uvicorn escan.web.app:app \
    --host 0.0.0.0 \
    --port 5050 \
    --log-level "${LOG_LEVEL,,}" \
    --workers 1

#!/usr/bin/env bash
# ============================================================
# docker-build.sh — eScan Docker 构建与启动脚本
#
# 用法:
#   ./scripts/docker-build.sh              # 构建 + 启动
#   ./scripts/docker-build.sh --build-only # 仅构建镜像
#   ./scripts/docker-build.sh --up         # 仅启动（不构建）
#   ./scripts/docker-build.sh --stop       # 停止服务
#   ./scripts/docker-build.sh --logs       # 查看日志
#   ./scripts/docker-build.sh --help       # 帮助
# ============================================================
set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

log()    { echo -e "${GREEN}[eScan]${NC} $1"; }
warn()   { echo -e "${YELLOW}[eScan]${NC} $1"; }
error()  { echo -e "${RED}[eScan]${NC} $1"; }
info()   { echo -e "${CYAN}[eScan]${NC} $1"; }

show_help() {
    cat <<EOF
用法: ./scripts/docker-build.sh [选项]

选项:
  --build-only   仅构建 Docker 镜像，不启动
  --up           仅启动已有容器（跳过构建）
  --stop         停止并移除容器
  --logs         实时查看容器日志
  --restart      重建并重启
  --help         显示此帮助

默认（无参数）：构建镜像 + 启动服务
EOF
    exit 0
}

# --- 解析参数 ---
MODE="full"
for arg in "$@"; do
    case "$arg" in
        --build-only) MODE="build" ;;
        --up)         MODE="up" ;;
        --stop)       MODE="stop" ;;
        --logs)       MODE="logs" ;;
        --restart)    MODE="restart" ;;
        --help)       show_help ;;
        *)            error "未知参数: $arg"; show_help ;;
    esac
done

# ============================================================
# 前置检查
# ============================================================
if [ "$MODE" = "stop" ]; then
    log "停止容器..."
    docker compose -p escan down
    log "已停止"
    exit 0
fi

if [ "$MODE" = "logs" ]; then
    exec docker compose -p escan logs -f
fi

# 检查 Docker 是否可用
command -v docker >/dev/null 2>&1 || { error "Docker 未安装"; exit 1; }
command -v docker compose >/dev/null 2>&1 || { error "docker compose 插件未安装"; exit 1; }

# ============================================================
# 准备宿主机目录和文件
# ============================================================
log "检查运行时目录..."

# nuclei-poc — POC 模板目录
if [ ! -d "nuclei-poc" ]; then
    mkdir -p nuclei-poc
    warn "已创建 nuclei-poc/ 目录（为空），请放入 Nuclei POC 模板文件"
fi

# proxies.txt — 代理文件
if [ ! -f "proxies.txt" ]; then
    touch proxies.txt
    warn "已创建空的 proxies.txt，如需代理请编辑该文件"
fi

# ============================================================
# 配置提醒
# ============================================================
if [ ! -f ".env.local" ]; then
    warn ""
    warn "===== 首次使用提醒 ====="
    warn "请创建 .env.local 文件并填入 API Key 等敏感配置："
    warn "  cp .env .env.local"
    warn "  然后编辑 .env.local 填入 FOFA_KEY / HUNTER_API_KEY / DB_PASSWORD 等"
    warn ""
    warn "或者通过环境变量传递（例如 export FOFA_KEY=xxx）"
    warn "Docker Compose 会自动读取宿主机 .env 文件"
    warn "========================="
    warn ""
fi

# ============================================================
# 构建
# ============================================================
if [ "$MODE" = "build" ] || [ "$MODE" = "full" ]; then
    log "构建 Docker 镜像（这可能需要 5-10 分钟）..."
    docker compose -p escan build
    log "构建完成"
fi

if [ "$MODE" = "build" ]; then
    log "镜像已构建，使用 docker compose up -d 启动"
    exit 0
fi

# ============================================================
# 启动
# ============================================================
if [ "$MODE" = "up" ] || [ "$MODE" = "full" ]; then
    log "启动服务..."

    if [ "$MODE" = "full" ]; then
        # 构建后的首次启动，自动创建目录卷
        docker compose -p escan up -d --remove-orphans
    else
        docker compose -p escan up -d --remove-orphans
    fi

    log "服务已启动"
    echo ""
    log "访问地址: http://localhost:5050"
    log "API 文档: http://localhost:5050/api/docs"
    echo ""

    # 显示初始日志
    sleep 2
    docker compose -p escan logs --tail 20
    echo ""
    info "提示: 使用 --logs 查看实时日志，--stop 停止服务"
fi

# ============================================================
# 重启
# ============================================================
if [ "$MODE" = "restart" ]; then
    log "重启服务..."
    docker compose -p escan down
    docker compose -p escan build
    docker compose -p escan up -d --remove-orphans
    log "服务已重启"
fi

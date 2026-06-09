# ============================================================
# Dockerfile — eScan 漏洞扫描工具链
# 多阶段构建: frontend-builder → runtime
# ============================================================

# ---- Stage 1: 前端构建 ----
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build


# ---- Stage 2: Nuclei 扫描器（下载预编译二进制） ----
FROM alpine:3.20 AS nuclei-builder
RUN apk add --no-cache curl unzip
ARG NUCLEI_VERSION=3.4.1
RUN curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    -o /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /tmp/nuclei-extract && \
    find /tmp/nuclei-extract -name "nuclei" -type f -exec cp {} /usr/local/bin/nuclei \; && \
    chmod +x /usr/local/bin/nuclei && \
    rm -rf /tmp/nuclei.zip /tmp/nuclei-extract


# ---- Stage 3: Python 运行环境 ----
FROM python:3.11-slim AS runtime

LABEL maintainer="eScan"
LABEL description="漏洞扫描工具链 — FOFA + Nuclei + ICP + AI 模板生成"

# 避免 Python 生成 __pycache__ 和字节码缓存
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/app

# 系统依赖（psycopg2 / numpy / pillow / onnxruntime 所需）
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 先安装 Python 依赖（利用 Docker 层缓存）
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目代码
COPY escan/ escan/
COPY scripts/ scripts/
COPY pyproject.toml README.md ./

# 复制前端构建产物
COPY --from=frontend-builder /app/frontend/dist/ frontend/dist/

# 复制 nuclei 扫描器
COPY --from=nuclei-builder /usr/local/bin/nuclei /usr/local/bin/nuclei

# 创建卷挂载点目录（确保权限）
RUN mkdir -p /app/output /app/logs /app/nuclei-poc && \
    touch /app/proxies.txt

# 入口脚本
COPY scripts/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 5050

ENTRYPOINT ["/docker-entrypoint.sh"]

"""FastAPI 应用入口（迁移自 Flask）。

单端口模式：后端 5050 端口同时提供 API (/api/*) 和前端静态页面 (/*)。
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .routes import router

# 前端构建产物目录（相对于项目根）
_FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"


def _mount_frontend(app: FastAPI) -> None:
    """如果存在构建产物，挂载前端静态文件并添加 SPA 兜底路由。"""
    if not _FRONTEND_DIST.is_dir():
        return

    # 子目录静态文件挂载（避免 mount("/") 干扰 API 路由）
    for subdir in ["assets", "css", "js"]:
        p = _FRONTEND_DIST / subdir
        if p.is_dir():
            app.mount(f"/{subdir}", StaticFiles(directory=str(p)), name=f"fe_{subdir}")

    # 根路径 → index.html
    @app.get("/", include_in_schema=False)
    async def root():
        return FileResponse(str(_FRONTEND_DIST / "index.html"))

    # SPA 兜底：非 /api/* 路径均返回 index.html
    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404)
        fp = _FRONTEND_DIST / full_path
        if fp.is_file():
            return FileResponse(str(fp))
        return FileResponse(str(_FRONTEND_DIST / "index.html"))


def create_app() -> FastAPI:
    app = FastAPI(
        title="eScan API",
        description="漏洞扫描工具链 — FOFA + Nuclei + ICP + AI 模板生成",
        version="2.0",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # API 路由优先注册
    app.include_router(router, prefix="/api")

    # 前端静态文件（兜底）
    _mount_frontend(app)

    return app


app = create_app()


def main():
    """直接启动 FastAPI（兼容旧 launcher 的 subprocess 调用）。"""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5050)

"""FastAPI 应用入口（迁移自 Flask）。"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import router


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

    app.include_router(router, prefix="/api")

    return app


app = create_app()


def main():
    """直接启动 FastAPI（兼容旧 launcher 的 subprocess 调用）。"""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5050)

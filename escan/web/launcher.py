"""Web 服务启动器 — 一键启动 FastAPI 后端 + Vite 前端。

用法: uv run escan server
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from ..config import ROOT_DIR

_FRONTEND_DIR = ROOT_DIR / "frontend"


def launch():
    """启动后端 (port 5050) 和前端 Vite dev server (port 5173)。

    Ctrl+C 同时停止两个服务。
    """
    procs: dict[str, subprocess.Popen] = {}
    shutdown = False
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    def _shutdown(_sig=None, _frame=None):
        nonlocal shutdown
        if shutdown:
            return
        shutdown = True
        print("\n正在关闭...")
        for name, p in procs.items():
            p.terminate()
        for name, p in procs.items():
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # 后端 — uvicorn
    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "escan.web.app:app",
         "--host", "0.0.0.0", "--port", "5050", "--log-level", "info"],
        stdout=sys.stdout, stderr=sys.stderr,
        env=env,
    )
    procs["api"] = api

    # 前端 — Vite dev server
    if (_FRONTEND_DIR / "node_modules").is_dir():
        fe = subprocess.Popen(
            ["npm", "run", "dev"],
            cwd=str(_FRONTEND_DIR),
            stdout=sys.stdout, stderr=sys.stderr,
            env=env,
        )
        procs["frontend"] = fe

    print()
    print("  eScan v2.0")

    # 如果已有前端构建产物，单端口模式；否则需要 Vite 开发服务器
    if (_FRONTEND_DIR / "dist").is_dir():
        print(f"  访问地址: http://localhost:5050")
    else:
        print(f"  API 文档:  http://localhost:5050/api/docs")
    if procs.get("frontend"):
        print(f"  Dashboard: http://localhost:5173")
    print()

    # 监控子进程
    while procs and not shutdown:
        for name in list(procs):
            p = procs[name]
            rc = p.poll()
            if rc is not None:
                if not shutdown:
                    if rc != 0:
                        print(f"\n[{name}] 异常退出 (code={rc})，正在关闭...")
                    _shutdown()
                break
        time.sleep(0.5)

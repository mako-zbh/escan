"""统一启动 Flask API + 前端开发服务器。"""

import os
import subprocess
import signal
import sys
import time
from pathlib import Path

from ..config import ROOT_DIR

_frontend_dir = ROOT_DIR / "frontend"


def launch() -> None:
    """启动后端 API (5050) 和前端 (3000)，Ctrl+C 同时停止。"""
    procs: dict[str, subprocess.Popen] = {}
    shutdown = False
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    def _shutdown(sig=None, frame=None):
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

    # 后端 — 用 __main__ 方式避免 flask reload 的 RuntimeWarning
    api = subprocess.Popen(
        [sys.executable, "-c",
         "from escan.web.app import main; main()"],
        stdout=sys.stdout, stderr=sys.stderr,
        env=env,
    )
    procs["api"] = api
    print("VulnScan API:      http://localhost:5050")

    # 前端
    if _frontend_dir.is_dir() and (_frontend_dir / "node_modules").is_dir():
        fe = subprocess.Popen(
            ["npm", "start"],
            cwd=str(_frontend_dir),
            stdout=sys.stdout, stderr=sys.stderr,
            env=env,
        )
        procs["frontend"] = fe
        print("VulnScan Dashboard: http://localhost:3000")

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

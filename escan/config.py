"""
集中配置 — 从环境变量 /.env / .env.local 读取，支持运行时热重载。

加载优先级：环境变量 > .env.local > .env > 默认值
修改 .env / .env.local 后无需重启进程，下次 _env() 调用自动感知。
"""

from __future__ import annotations

import os
import time
from pathlib import Path

# 项目根目录（pyproject.toml 所在）
ROOT_DIR = Path(__file__).resolve().parent.parent

# 跟踪文件修改时间以实现自动重载
_env_file_mtimes: dict[str, float] = {}


def _load_dotenv(overwrite: bool = False) -> None:
    """按优先级加载 .env 和 .env.local 到 os.environ。

    Args:
        overwrite: True 时覆盖已有环境变量（热重载用），
                   False 时仅补充缺失值（首次加载）。
    """
    global _env_file_mtimes
    for name in (".env", ".env.local"):
        env_file = ROOT_DIR / name
        if not env_file.is_file():
            continue
        mtime = env_file.stat().st_mtime
        _env_file_mtimes[name] = mtime
        with open(env_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip().strip("\"'")
                if overwrite:
                    os.environ[key] = value
                elif not os.environ.get(key):  # 空字符串视为未设置，允许 .env.local 覆盖
                    os.environ[key] = value


def _check_reload() -> bool:
    """检查 .env / .env.local 文件是否有修改，有则自动重载。

    Returns:
        True 表示发生了重载。
    """
    global _env_file_mtimes
    for name in (".env", ".env.local"):
        env_file = ROOT_DIR / name
        if not env_file.is_file():
            continue
        mtime = env_file.stat().st_mtime
        if _env_file_mtimes.get(name) != mtime:
            _load_dotenv(overwrite=True)
            return True
    return False


# 首次加载（仅补充缺失值，不覆盖环境变量）
_load_dotenv(overwrite=False)


def reload_env() -> None:
    """强制重新加载 .env / .env.local，覆盖所有已有环境变量。

    修改文件后调用此函数立即生效，无需重启进程。
    """
    _load_dotenv(overwrite=True)


def _env(key: str, default: str = "") -> str:
    """读取环境变量，并在文件变更时自动重载。"""
    _check_reload()
    return os.environ.get(key, default)


def get(key: str, default: str = "") -> str:
    """读取配置项（运行时安全，自动感知文件变更）。"""
    return _env(key, default)


def getbool(key: str, default: str = "0") -> bool:
    """读取布尔配置项。"""
    return _env(key, default).lower() in ("1", "true")


def getint(key: str, default: str = "0") -> int:
    """读取整数配置项。"""
    return int(_env(key, default))


def getfloat(key: str, default: str = "0") -> float:
    """读取浮点数配置项。"""
    return float(_env(key, default))


# ============================================================
# 以下为模块级常量（首次加载时的快照，主要用于 import 兼容）
# 如需运行时热更新，请使用 config.get() / config.getbool() 等函数，
# 或直接调用 config.reload_env() 触发重载。
# ============================================================

# --- FOFA ---
FOFA_EMAIL = _env("FOFA_EMAIL")
FOFA_KEY = _env("FOFA_KEY")
FOFA_API = _env("FOFA_API")
FOFA_OFFICIAL_API = _env("FOFA_OFFICIAL_API", "https://fofa.info/api/v1/search/all")
FOFA_PROXY_COOKIE = _env("FOFA_PROXY_COOKIE")
FOFA_SIZE = getint("FOFA_SIZE", "100")

# --- Hunter（奇安信鹰图）---
HUNTER_API_KEY = _env("HUNTER_API_KEY")
HUNTER_API = _env("HUNTER_API", "https://hunter.qianxin.com/openApi/search")
HUNTER_PROXY_API = _env("HUNTER_PROXY_API")
HUNTER_PROXY_COOKIE = _env("HUNTER_PROXY_COOKIE")
HUNTER_SIZE = getint("HUNTER_SIZE", "100")

# --- Nuclei ---
NUCLEI_PATH = _env("NUCLEI_PATH") or None
POC_DIR = str(ROOT_DIR / "nuclei-poc")
OUTPUT_DIR = str(ROOT_DIR / "output")

# --- ICP / 爱站 ---
AIZHAN_COOKIE = _env("AIZHAN_COOKIE")
ICP_THREADS = getint("ICP_THREADS", "2")
ICP_DELAY = getfloat("ICP_DELAY", "5.0")

# --- DeepSeek Agent ---
DEEPSEEK_API_KEY = _env("DEEPSEEK_API_KEY")
DEEPSEEK_MODEL = _env("DEEPSEEK_MODEL", "deepseek-v4-flash")
DEEPSEEK_API = _env("DEEPSEEK_API", "https://api.deepseek.com/v1/chat/completions")

# --- GLM-OCR ---
GLM_OCR_API = _env("GLM_OCR_API", "http://127.0.0.1:8080/v1/chat/completions")

# --- PostgreSQL ---
DB_HOST = _env("DB_HOST", "localhost")
DB_PORT = getint("DB_PORT", "5432")
DB_NAME = _env("DB_NAME", "escan")
DB_USER = _env("DB_USER", "escan")
DB_PASSWORD = _env("DB_PASSWORD", "")

# --- 运行参数 ---
LOG_LEVEL = _env("LOG_LEVEL", "INFO")
AGENT_CONCURRENCY = getint("AGENT_CONCURRENCY", "3")
SEARCH_ENGINE = _env("SEARCH_ENGINE", "fofa")

# --- 代理池 ---
PROXY_FILE = _env("PROXY_FILE", "proxies.txt")
PROXY_LIST = _env("PROXY_LIST")
PROXY_ENABLED_FOFA = getbool("PROXY_ENABLED_FOFA", "0")
PROXY_ENABLED_HUNTER = getbool("PROXY_ENABLED_HUNTER", "0")
PROXY_ENABLED_NUCLEI = getbool("PROXY_ENABLED_NUCLEI", "0")
PROXY_ENABLED_ICP = getbool("PROXY_ENABLED_ICP", "0")
PROXY_ENABLED_DEEPSEEK = getbool("PROXY_ENABLED_DEEPSEEK", "0")
PROXY_STRATEGY = _env("PROXY_STRATEGY", "round_robin")
PROXY_COOLDOWN = getfloat("PROXY_COOLDOWN", "60")
PROXY_MAX_FAILURES = getint("PROXY_MAX_FAILURES", "3")

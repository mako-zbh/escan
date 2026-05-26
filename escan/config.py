"""
集中配置 — 从环境变量 /.env 读取，代码中不硬编码任何 secret。
加载优先级：环境变量 > .env.local > .env > 默认值
"""

import os
from pathlib import Path

# 项目根目录（pyproject.toml 所在）
ROOT_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv() -> None:
    """按优先级加载 .env 和 .env.local（不依赖 python-dotenv）。"""
    for name in (".env", ".env.local"):
        env_file = ROOT_DIR / name
        if not env_file.is_file():
            continue
        with open(env_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip().strip("\"'")
                # 环境变量优先，不覆盖
                if key not in os.environ:
                    os.environ[key] = value


_load_dotenv()


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


# --- FOFA ---
FOFA_EMAIL = _env("FOFA_EMAIL")
FOFA_KEY = _env("FOFA_KEY")  # 官方 API key，设置后优先使用官方接口
FOFA_API = _env("FOFA_API")  # 代理接口地址
FOFA_OFFICIAL_API = _env("FOFA_OFFICIAL_API", "https://fofa.info/api/v1/search/all")
FOFA_PROXY_COOKIE = _env("FOFA_PROXY_COOKIE")
FOFA_SIZE = int(_env("FOFA_SIZE", "100"))

# --- Hunter（奇安信鹰图）---
HUNTER_API_KEY = _env("HUNTER_API_KEY")  # 官方 API key，设置后优先使用官方接口
HUNTER_API = _env("HUNTER_API", "https://hunter.qianxin.com/openApi/search")
HUNTER_PROXY_API = _env("HUNTER_PROXY_API")  # 代理接口地址
HUNTER_PROXY_COOKIE = _env("HUNTER_PROXY_COOKIE")  # 代理接口 Cookie
HUNTER_SIZE = int(_env("HUNTER_SIZE", "100"))

# --- Nuclei ---
NUCLEI_PATH = _env("NUCLEI_PATH") or None
POC_DIR = str(ROOT_DIR / "nuclei-poc")
OUTPUT_DIR = str(ROOT_DIR / "output")

# --- ICP / 爱站 ---
AIZHAN_COOKIE = _env("AIZHAN_COOKIE")
ICP_THREADS = int(_env("ICP_THREADS", "2"))
ICP_DELAY = float(_env("ICP_DELAY", "5.0"))

# --- DeepSeek Agent ---
DEEPSEEK_API_KEY = _env("DEEPSEEK_API_KEY")
DEEPSEEK_MODEL = _env("DEEPSEEK_MODEL", "deepseek-v4-flash")
DEEPSEEK_API = _env("DEEPSEEK_API", "https://api.deepseek.com/v1/chat/completions")

# --- GLM-OCR ---
GLM_OCR_API = _env("GLM_OCR_API", "http://127.0.0.1:8080/v1/chat/completions")

# --- PostgreSQL ---
DB_HOST = _env("DB_HOST", "localhost")
DB_PORT = int(_env("DB_PORT", "5432"))
DB_NAME = _env("DB_NAME", "escan")
DB_USER = _env("DB_USER", "escan")
DB_PASSWORD = _env("DB_PASSWORD", "")

# --- 运行参数 ---
LOG_LEVEL = _env("LOG_LEVEL", "INFO")
AGENT_CONCURRENCY = int(_env("AGENT_CONCURRENCY", "3"))
SEARCH_ENGINE = _env("SEARCH_ENGINE", "fofa")  # fofa | hunter

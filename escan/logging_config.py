"""统一日志配置"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler

from .config import LOG_LEVEL, ROOT_DIR

LOG_FORMAT = "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(name: str | None = None) -> logging.Logger:
    """配置并返回 logger，同时输出到控制台和文件。

    - 控制台: 彩色级别标签，便于开发时阅读
    - 文件:   logs/<date>.log，按 5MB 轮转，保留最近 5 个
    """
    logger = logging.getLogger(name or "escan")
    logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

    if logger.handlers:
        return logger

    # 控制台 handler
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG)
    console.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    logger.addHandler(console)

    # 文件 handler（按大小轮转）
    logs_dir = ROOT_DIR / "logs"
    logs_dir.mkdir(exist_ok=True)
    file_handler = RotatingFileHandler(
        logs_dir / "vulnscan.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """获取子模块 logger（继承根 logger 配置）。"""
    return logging.getLogger(f"escan.{name}")

"""文件 I/O 工具"""

import os
import json
from pathlib import Path
from datetime import datetime


def ensure_dir(path: str | Path) -> Path:
    """确保目录存在，返回 Path 对象。"""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_output(category: str, filename: str, content: str) -> Path:
    """写入输出文件到 output/<category>/<filename>。

    category: fofa, nuclei, icp, _failed 等
    """
    from ..config import OUTPUT_DIR

    out_dir = ensure_dir(Path(OUTPUT_DIR) / category)
    filepath = out_dir / filename
    filepath.write_text(content, encoding="utf-8")
    return filepath


def load_json_cache(name: str) -> dict:
    """加载 JSON 缓存文件（output/<name>.json）。"""
    from ..config import OUTPUT_DIR

    cache_file = Path(OUTPUT_DIR) / f"{name}.json"
    if cache_file.is_file():
        with open(cache_file, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_json_cache(name: str, data: dict) -> None:
    """保存 JSON 缓存文件。"""
    from ..config import OUTPUT_DIR

    cache_file = ensure_dir(Path(OUTPUT_DIR)) / f"{name}.json"
    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def timestamp_dir(base: str) -> Path:
    """创建带时间戳的子目录并返回。

    output/fofa/2026-05-10_14-30-00/
    """
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return ensure_dir(Path(base) / ts)

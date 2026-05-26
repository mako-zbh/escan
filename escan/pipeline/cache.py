"""增量扫描缓存 — 优先使用数据库，数据库不可用时回退到 JSON 文件。

数据库表: query_cache (24h TTL)
文件缓存: output/scanned.json
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..config import OUTPUT_DIR
from ..logging_config import get_logger

logger = get_logger("pipeline.cache")

CACHE_FILE = Path(OUTPUT_DIR) / "scanned.json"
ASSET_TTL_HOURS = 24
NUCLEI_RESULTS_KEY = "nuclei"
ASSET_RESULTS_KEYS = {"fofa": "fofa", "hunter": "hunter"}


def _hash(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()[:12]


# --- 文件缓存（fallback）---

def _load_file_cache() -> dict:
    if CACHE_FILE.is_file():
        try:
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            logger.warning("scanned.json 损坏，重建缓存")
    return {}


def _save_file_cache(data: dict) -> None:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _asset_cache_key(engine: str) -> str:
    return ASSET_RESULTS_KEYS.get(engine, "fofa")


# --- 资产查询缓存 ---

def get_cached_assets(tag: str, engine: str = "fofa") -> list[str] | None:
    """查询缓存资产，优先数据库，回退文件。"""
    query_hash = _hash(tag)

    # 1. 尝试数据库
    from ..database.connection import get_cursor
    from ..database.dao import get_cached_assets as db_get

    with get_cursor() as cur:
        if cur is not None:
            assets = db_get(cur, query_hash, engine)
            if assets is not None:
                logger.info("%s 缓存命中 (DB): %s... → %d 条", engine.upper(), tag[:60], len(assets))
                return assets

    # 2. 回退到文件缓存
    cache = _load_file_cache()
    engine_key = _asset_cache_key(engine)
    entry = cache.get(engine_key, {}).get(query_hash)
    if not entry:
        return None

    ts = datetime.fromisoformat(entry["ts"])
    if datetime.now(timezone.utc) - ts.replace(tzinfo=timezone.utc) > timedelta(hours=ASSET_TTL_HOURS):
        logger.debug("%s 文件缓存过期: %s", engine.upper(), tag[:60])
        return None

    assets = entry.get("assets", [])
    logger.info("%s 缓存命中 (文件): %s... → %d 条", engine.upper(), tag[:60], len(assets))
    return assets


def set_cached_assets(tag: str, assets: list[str], engine: str = "fofa") -> None:
    """缓存资产查询结果，同时写入数据库和文件。"""
    query_hash = _hash(tag)

    # 1. 写入数据库
    from ..database.connection import get_cursor
    from ..database.dao import set_cached_assets as db_set

    with get_cursor() as cur:
        if cur is not None:
            db_set(cur, query_hash, tag, assets, engine)

    # 2. 同时写入文件（兼容性）
    cache = _load_file_cache()
    engine_key = _asset_cache_key(engine)
    cache.setdefault(engine_key, {})
    cache[engine_key][query_hash] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "assets": assets,
    }
    _save_file_cache(cache)


def get_scan_stats() -> dict:
    """获取扫描统计信息。"""
    from ..database.connection import get_cursor
    from ..database.dao import get_db_stats

    with get_cursor() as cur:
        if cur is not None:
            stats = get_db_stats(cur)
            if stats:
                return {
                    "fofa_cached_queries": stats.get("active_cache_count", 0),
                    "hunter_cached_queries": 0,
                    "templates_scanned": stats.get("template_count", 0),
                    "unique_assets": stats.get("asset_count", 0),
                    "total_hits": stats.get("vuln_count", 0),
                    "cache_file": str(CACHE_FILE),
                }

    # 文件回退
    cache = _load_file_cache()
    fofa_entries = len(cache.get("fofa", {}))
    hunter_entries = len(cache.get("hunter", {}))
    nuclei_entries = cache.get(NUCLEI_RESULTS_KEY, {})

    total_templates = len(nuclei_entries)
    total_assets = set()
    total_hits = 0
    for tid, assets in nuclei_entries.items():
        for asset, entry in assets.items():
            total_assets.add(asset)
            if entry.get("found"):
                total_hits += 1

    return {
        "fofa_cached_queries": fofa_entries,
        "hunter_cached_queries": hunter_entries,
        "templates_scanned": total_templates,
        "unique_assets": len(total_assets),
        "total_hits": total_hits,
        "cache_file": str(CACHE_FILE),
    }

"""代理池 — 从文件和/或环境变量加载代理，轮询选择，失败自动冷却。

用法:
    from ..utils.proxy import get_proxy
    from ..config import PROXY_ENABLED_FOFA

    proxies = get_proxy(PROXY_ENABLED_FOFA)   # {"http": url, "https": url} 或直连
    requests.get(url, proxies=proxies)
"""

from __future__ import annotations

import random
import threading
import time
from pathlib import Path

from ..config import (
    ROOT_DIR, PROXY_FILE, PROXY_LIST,
    PROXY_STRATEGY, PROXY_COOLDOWN, PROXY_MAX_FAILURES,
)
from ..logging_config import get_logger

logger = get_logger("utils.proxy")


class ProxyPool:
    """线程安全的代理池，支持轮询/随机选择 + 失败冷却。"""

    def __init__(
        self,
        proxies: list[str],
        strategy: str = "round_robin",
        cooldown: float = 60.0,
        max_failures: int = 3,
    ):
        self._proxies = proxies
        self._strategy = strategy
        self._cooldown = cooldown
        self._max_failures = max_failures

        self._lock = threading.Lock()
        self._index = 0
        self._failures: dict[str, int] = {}       # proxy_url → consecutive failures
        self._cooldowns: dict[str, float] = {}     # proxy_url → cooldown until timestamp

    def __len__(self) -> int:
        return len(self._proxies)

    def status(self) -> dict:
        """返回池状态快照（线程安全）。"""
        with self._lock:
            now = time.monotonic()
            proxies_status = []
            for url in self._proxies:
                in_cooldown = url in self._cooldowns and now < self._cooldowns[url]
                proxies_status.append({
                    "url": url,
                    "failures": self._failures.get(url, 0),
                    "in_cooldown": in_cooldown,
                    "cooldown_remaining": max(0, self._cooldowns.get(url, 0) - now) if in_cooldown else 0,
                })
            return {
                "total": len(self._proxies),
                "available": sum(1 for p in proxies_status if not p["in_cooldown"]),
                "in_cooldown": sum(1 for p in proxies_status if p["in_cooldown"]),
                "strategy": self._strategy,
                "cooldown_seconds": self._cooldown,
                "max_failures": self._max_failures,
                "proxies": proxies_status,
            }

    # --- public ---

    def get_proxy(self) -> dict[str, str] | None:
        """返回一个代理 dict ({'http': url, 'https': url})，或 None 当池为空。"""
        if not self._proxies:
            return None

        with self._lock:
            now = time.monotonic()

            # 清理过期冷却
            expired = [u for u, t in self._cooldowns.items() if now >= t]
            for u in expired:
                del self._cooldowns[u]

            available = [
                u for u in self._proxies if u not in self._cooldowns
            ]

            if not available:
                # 全部冷却中 → 重置所有冷却，重试
                self._cooldowns.clear()
                self._failures.clear()
                available = list(self._proxies)
                logger.warning("所有代理均在冷却中，重置冷却状态")

            if self._strategy == "random":
                url = random.choice(available)
            else:
                # round_robin: 从当前位置向后搜索第一个可用
                for _ in range(len(self._proxies)):
                    url = self._proxies[self._index % len(self._proxies)]
                    self._index += 1
                    if url in available:
                        break
                else:
                    url = available[0]

        return {"http": url, "https": url}

    def mark_success(self, proxy_dict: dict[str, str]) -> None:
        """标记代理成功，重置失败计数。"""
        url = proxy_dict.get("http") or proxy_dict.get("https")
        if not url:
            return
        with self._lock:
            self._failures.pop(url, None)

    def mark_failure(self, proxy_dict: dict[str, str]) -> None:
        """标记代理失败，连续失败达阈值后进入冷却。"""
        url = proxy_dict.get("http") or proxy_dict.get("https")
        if not url:
            return
        with self._lock:
            count = self._failures.get(url, 0) + 1
            self._failures[url] = count
            if count >= self._max_failures:
                self._cooldowns[url] = time.monotonic() + self._cooldown
                logger.warning(
                    "代理 %s 连续失败 %d 次，冷却 %.0fs",
                    url, count, self._cooldown,
                )

    # --- loading helpers ---

    @staticmethod
    def _load_from_file(path: Path) -> list[str]:
        """从文件读取代理列表，一行一个，去注释和空行。"""
        if not path.is_file():
            return []
        proxies = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                proxies.append(line)
        return proxies

    @staticmethod
    def _load_from_env(env_val: str) -> list[str]:
        """从 PROXY_LIST 环境变量解析代理。"""
        if not env_val:
            return []
        return [p.strip() for p in env_val.split(",") if p.strip()]

    @classmethod
    def from_config(cls) -> ProxyPool | None:
        """从配置创建 ProxyPool，合并文件 + 环境变量。

        文件路径 PROXY_FILE 如为相对路径，相对于 ROOT_DIR 解析。
        """
        proxy_file_path = Path(PROXY_FILE)
        if not proxy_file_path.is_absolute():
            proxy_file_path = ROOT_DIR / proxy_file_path

        file_proxies = cls._load_from_file(proxy_file_path)
        env_proxies = cls._load_from_env(PROXY_LIST)

        # 合并去重（保持顺序：文件在前，env 在后）
        seen: set[str] = set()
        merged: list[str] = []
        for p in file_proxies + env_proxies:
            if p not in seen:
                seen.add(p)
                merged.append(p)

        if not merged:
            return None

        pool = cls(
            merged,
            strategy=PROXY_STRATEGY,
            cooldown=PROXY_COOLDOWN,
            max_failures=PROXY_MAX_FAILURES,
        )
        logger.info(
            "代理池就绪: %d 个代理 (文件 %d, env %d), 策略 %s",
            len(pool), len(file_proxies), len(env_proxies), PROXY_STRATEGY,
        )
        return pool


# --- 单例 ---

_pool: ProxyPool | None = None
_pool_lock = threading.Lock()
_pool_initialized = False


def get_proxy_pool() -> ProxyPool | None:
    """获取全局 ProxyPool 单例，首次调用时从配置初始化。"""
    global _pool, _pool_initialized
    if _pool_initialized:
        return _pool

    with _pool_lock:
        if _pool_initialized:
            return _pool
        _pool_initialized = True
        _pool = ProxyPool.from_config()
        return _pool


def get_proxy(enabled: bool) -> dict[str, str | None]:
    """解析组件代理 dict。

    - enabled=False → 直连 {"http": None, "https": None}
    - enabled=True + 池非空 → 从池中选取代理
    - enabled=True + 池为空 → 直连

    """
    if not enabled:
        return {"http": None, "https": None}
    pool = get_proxy_pool()
    if pool is None:
        return {"http": None, "https": None}
    p = pool.get_proxy()
    if p is None:
        return {"http": None, "https": None}
    return p


def mark_proxy_success(proxy_dict: dict) -> None:
    """标记代理成功（用于手动跟踪的场景）。"""
    pool = get_proxy_pool()
    if pool and proxy_dict.get("http"):
        pool.mark_success(proxy_dict)


def mark_proxy_failure(proxy_dict: dict) -> None:
    """标记代理失败（用于手动跟踪的场景）。"""
    pool = get_proxy_pool()
    if pool and proxy_dict.get("http"):
        pool.mark_failure(proxy_dict)

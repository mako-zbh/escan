"""FOFA 资产查询 — 支持官方 API key 和代理 cookie 两种模式。

优先级：FOFA_KEY（官方 API）> FOFA_PROXY_COOKIE（代理接口）
"""

import base64
import time

import requests

from ..config import (
    FOFA_KEY, FOFA_SIZE, FOFA_API, FOFA_OFFICIAL_API, FOFA_PROXY_COOKIE,
)
from ..logging_config import get_logger
from ..utils.retry import retry

logger = get_logger("pipeline.fofa")

# 绕过系统代理环境变量（HTTP_PROXY / HTTPS_PROXY）
_NO_PROXY = {"http": None, "https": None}


def _use_official_api() -> bool:
    return bool(FOFA_KEY)


def _build_proxy_headers() -> dict:
    from urllib.parse import urlparse
    parsed = urlparse(FOFA_API)
    origin = f"{parsed.scheme}://{parsed.hostname}"
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.7060.96 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": origin,
        "Referer": f"{origin}/app/fofa-vip",
        "Cookie": FOFA_PROXY_COOKIE,
    }


def _parse_results(data: dict) -> list[str]:
    """解析 API 返回的 results 为 URL 列表。

    results 格式::

        [["host", "ip", "title", "port", ...], ...]
    """
    urls = []
    for row in data.get("results", []):
        if not row:
            continue
        host = row[0]
        if not host.startswith(("http://", "https://")):
            host = f"http://{host}"
        urls.append(host)
    return list(set(urls))


def _query_official(query: str, size: int = FOFA_SIZE) -> list[str]:
    """通过 FOFA 官方 API 查询，使用 API key 认证。

    GET https://fofa.info/api/v1/search/all
    """
    qbase64 = base64.b64encode(query.encode()).decode()
    params = {
        "key": FOFA_KEY,
        "qbase64": qbase64,
        "size": size,
        "fields": "host,ip,port,title",
    }

    resp = requests.get(
        FOFA_OFFICIAL_API, params=params, timeout=180, proxies=_NO_PROXY,
    )
    resp.raise_for_status()
    result = resp.json()

    if result.get("error"):
        errmsg = result.get("errmsg", "未知错误")
        raise RuntimeError(f"FOFA 官方 API 错误: {errmsg}")

    urls = _parse_results(result)
    logger.debug("FOFA 官方查询: %s... → %d 条", query[:60], len(urls))
    return urls


def _query_proxy(query: str, size: int = FOFA_SIZE) -> list[str]:
    """通过代理接口查询，使用 Cookie 认证。
    """
    from urllib.parse import urlencode

    body = urlencode({
        "action": "fofa_cx",
        "fofa_yf": query,
        "fofa_ts": str(size),
    })

    resp = requests.post(
        FOFA_API,
        data=body,
        headers=_build_proxy_headers(),
        timeout=180,
        proxies=_NO_PROXY,
    )
    resp.raise_for_status()
    result = resp.json()

    if result.get("error"):
        errmsg = result.get("errmsg", "未知错误")
        raise RuntimeError(f"FOFA 代理接口错误: {errmsg}")

    urls = _parse_results(result)
    logger.debug("FOFA 代理查询: %s... → %d 条", query[:60], len(urls))
    return urls


@retry(max_retries=2, base_delay=2.0)
def query_fofa(query: str, size: int = FOFA_SIZE) -> list[str]:
    """查询 FOFA 资产，返回去重后的 URL 列表。

    自动选择模式：FOFA_KEY 存在 → 官方 API，否则 → 代理接口。
    """
    if _use_official_api():
        return _query_official(query, size)
    return _query_proxy(query, size)


def query_fofa_multiple(queries: list[str], size: int = FOFA_SIZE) -> list[str]:
    """批量查询多条 FOFA 语句，去重合并。"""
    all_assets = []
    for i, query in enumerate(queries):
        if i > 0:
            time.sleep(1.5)
        try:
            assets = query_fofa(query, size)
            logger.info("FOFA 查询: %s... → %d 条", query[:60], len(assets))
            all_assets.extend(assets)
        except Exception as e:
            logger.error("FOFA 查询失败: %s... → %s", query[:60], e)

    merged = list(set(all_assets))
    logger.info("FOFA 批量查询完成: %d 条查询 → %d 条去重资产", len(queries), len(merged))
    return merged

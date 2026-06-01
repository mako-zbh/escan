"""FOFA 资产查询 — 支持官方 API key 和代理 cookie 两种模式。

优先级：FOFA_KEY（官方 API）> FOFA_PROXY_COOKIE（代理接口）
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field

import requests

from ..config import (
    FOFA_KEY, FOFA_SIZE, FOFA_API, FOFA_OFFICIAL_API, FOFA_PROXY_COOKIE,
)
from ..logging_config import get_logger
from ..utils.retry import retry

logger = get_logger("pipeline.fofa")

# 绕过系统代理环境变量（HTTP_PROXY / HTTPS_PROXY）
_NO_PROXY = {"http": None, "https": None}


@dataclass
class FofaAsset:
    """FOFA 查询返回的单条资产。"""
    url: str               # 完整 URL（由 host 字段构造）
    host: str              # FOFA 返回的 host 字段（IP 或域名，可能含端口）
    ip: str | None = None  # FOFA 返回的直接 IP
    port: int = 80            # 端口号（构造时已归一化，始终为 int）
    title: str | None = None  # 页面标题
    fid: str | None = None   # FOFA 指纹 ID
    scheme: str = "http"
    query_used: str = ""

    @property
    def dedup_key(self) -> tuple[str, str, int]:
        """归一化去重键: (scheme, host, port)。"""
        return _normalize_dedup_key(self.scheme, self.host, self.port)


def _normalize_dedup_key(scheme: str, host: str, port: int | None) -> tuple[str, str, int]:
    """将 (scheme, host, port) 归一化为去重键。

    - scheme 小写，缺失默认 http
    - host 小写
    - port 归一化：http 默认 80，https 默认 443
    """
    scheme = (scheme or "http").lower()
    host = (host or "").lower().strip()
    if port is None:
        port = 443 if scheme == "https" else 80
    return (scheme, host, port)


def _parse_url_parts(raw_host: str) -> tuple[str, str, int | None]:
    """从 FOFA host 字段解析 (scheme, hostname, port)。"""
    if raw_host.startswith("https://"):
        scheme = "https"
        host_part = raw_host[len("https://"):]
    elif raw_host.startswith("http://"):
        scheme = "http"
        host_part = raw_host[len("http://"):]
    else:
        scheme = "http"
        host_part = raw_host

    host_part = host_part.split("/")[0]
    if ":" in host_part:
        hostname, port_str = host_part.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = None
        return scheme, hostname, port
    return scheme, host_part, None


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


def _parse_results(data: dict) -> list[FofaAsset]:
    """解析 API 返回的 results 为 FofaAsset 列表，按去重键去重。

    results 格式::

        [["host", "ip", "title", "port", ...], ...]

    fields 请求为 "host,ip,port,title,fid"，对应 row[0..4]。
    """
    seen: dict[tuple, FofaAsset] = {}
    for row in data.get("results", []):
        if not row:
            continue
        raw_host = row[0] or ""
        ip = row[1] if len(row) > 1 else None
        raw_port = row[2] if len(row) > 2 else None
        try:
            fofa_port = int(raw_port) if raw_port not in (None, "") else None
        except (ValueError, TypeError):
            fofa_port = None
        title = row[3] if len(row) > 3 else None
        fid = row[4] if len(row) > 4 else None

        if not raw_host.startswith(("http://", "https://")):
            raw_host = f"http://{raw_host}"

        scheme, hostname, url_port = _parse_url_parts(raw_host)
        # 优先使用 FOFA 返回的 port，其次从 URL 解析，最后用默认值
        port = fofa_port if fofa_port is not None else url_port
        if port is None:
            port = 443 if scheme == "https" else 80

        url = f"{scheme}://{hostname}:{port}"

        asset = FofaAsset(
            url=url, host=hostname, ip=ip, port=port,
            title=title, fid=fid, scheme=scheme,
        )
        key = asset.dedup_key
        if key not in seen:
            seen[key] = asset

    return list(seen.values())


def _query_official(query: str, size: int = FOFA_SIZE) -> list[FofaAsset]:
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

    assets = _parse_results(result)
    logger.debug("FOFA 官方查询: %s... → %d 条", query[:60], len(assets))
    return assets


def _query_proxy(query: str, size: int = FOFA_SIZE) -> list[FofaAsset]:
    """通过代理接口查询，使用 Cookie 认证。"""
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

    assets = _parse_results(result)
    logger.debug("FOFA 代理查询: %s... → %d 条", query[:60], len(assets))
    return assets


@retry(max_retries=2, base_delay=2.0)
def query_fofa(query: str, size: int = FOFA_SIZE, label: str = "") -> list[FofaAsset]:
    """查询 FOFA 资产，返回去重后的 FofaAsset 列表。
    自动选择模式：FOFA_KEY 存在 → 官方 API，否则 → 代理接口。
    label: 可选模板名，错误日志附带。
    """
    try:
        if _use_official_api():
            return _query_official(query, size)
        return _query_proxy(query, size)
    except Exception as e:
        if label:
            logger.error("FOFA 查询错误 [%s]: %s... → %s", label, query[:60], e)
        raise


def query_fofa_multiple(queries: list[str], size: int = FOFA_SIZE,
                         label: str = "") -> list[FofaAsset]:
    """批量查询多条 FOFA 语句，按去重键合并。label: 可选模板名。"""
    seen: dict[tuple, FofaAsset] = {}
    for i, query in enumerate(queries):
        if i > 0:
            time.sleep(1.5)
        try:
            assets = query_fofa(query, size, label=label)
            logger.info("FOFA 查询: %s... → %d 条", query[:60], len(assets))
            for a in assets:
                key = a.dedup_key
                if key not in seen:
                    seen[key] = a
        except Exception as e:
            logger.error("FOFA 查询失败 [%s]: %s... → %s", label or "-", query[:60], e)

    merged = list(seen.values())
    logger.info("FOFA 批量查询完成: %d 条查询 → %d 条去重资产", len(queries), len(merged))
    return merged

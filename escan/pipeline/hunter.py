"""Hunter 资产查询 — 奇安信鹰图平台，支持官方 API key 和代理 Cookie 两种模式。

优先级：HUNTER_API_KEY（官方 API）> HUNTER_PROXY_COOKIE（代理接口）

查询语法自动从 FOFA 翻译为 Hunter 兼容格式。
"""

import base64
import re
import time

import requests

from ..config import (
    HUNTER_API_KEY, HUNTER_API, HUNTER_SIZE,
    HUNTER_PROXY_API, HUNTER_PROXY_COOKIE,
    PROXY_ENABLED_HUNTER,
)
from ..logging_config import get_logger
from ..utils.proxy import get_proxy
from .fofa import FofaAsset, _normalize_dedup_key, _parse_url_parts

logger = get_logger("pipeline.hunter")

# FOFA → Hunter 字段名映射
_FIELD_MAP = {
    "body": "web.body",
    "title": "web.title",
    "header": "header",
    "domain": "domain",
    "port": "port",
    "protocol": "protocol",
    "server": "header",
    "cert": "cert",
    "country": "country",
    "ip": "ip",
    "banner": "web.body",
    "icp": "icp",
}

# Hunter 值内部不能包含这些模式（会被误解析为操作符/注释符）
_HUNTER_UNSAFE_VALUE_RE = re.compile(r'"[^"]*(?:=\s*[($]|\$\(|#\w)[^"]*"')


def _use_official_api() -> bool:
    return bool(HUNTER_API_KEY)


def _is_hunter_safe_term(term: str) -> bool:
    """检查单个查询 term 的值是否兼容 Hunter 解析器。"""
    return not _HUNTER_UNSAFE_VALUE_RE.search(term)


def translate_fofa_to_hunter(query: str) -> str:
    """将 FOFA 查询语法翻译为 Hunter 兼容语法。

    1. 字段名映射：body → web.body, title → web.title ...
    2. 过滤含 Hunter 不兼容字符的查询片段
    3. 如果所有片段都被过滤，返回简化后的基础查询
    """
    if re.search(r"\bweb\.(body|title)\b", query, re.IGNORECASE):
        return query

    def _replace_field(match):
        fofa_field = match.group(1)
        hunter_field = _FIELD_MAP.get(fofa_field)
        if hunter_field is not None:
            return f"{hunter_field}="
        return match.group(0)

    translated = re.sub(
        r"\b(" + "|".join(map(re.escape, _FIELD_MAP)) + r")=",
        _replace_field,
        query,
    )

    terms = re.split(r"\s*\|\|\s*", translated)
    safe_terms = []
    dropped = False

    for term in terms:
        sub_terms = re.split(r"\s*&&\s*", term)
        safe_sub = [st for st in sub_terms if _is_hunter_safe_term(st)]

        if len(safe_sub) == len(sub_terms):
            safe_terms.append(term)
        elif safe_sub:
            safe_terms.append(" && ".join(safe_sub))
            dropped = True
        else:
            dropped = True

    if not safe_terms:
        logger.warning("Hunter 查询完全无法兼容，降级为 domain 搜索: %s", query[:80])
        return ""

    if dropped:
        result = " || ".join(safe_terms)
        logger.debug("Hunter 清理查询: %d → %d 片段", len(terms), len(safe_terms))
        return result

    return translated


def _query_official(query: str, size: int = HUNTER_SIZE) -> list[FofaAsset]:
    """通过 Hunter 官方 API 查询，使用 API key 认证。"""
    hunter_query = translate_fofa_to_hunter(query)

    if not hunter_query:
        logger.warning("Hunter 查询为空（所有片段不兼容），返回空结果")
        return []

    query_b64 = base64.urlsafe_b64encode(hunter_query.encode("utf-8")).decode("utf-8")

    page_size = min(size, 20)
    page = 1
    seen: dict[tuple, FofaAsset] = {}

    while len(seen) < size:
        params = {
            "api-key": HUNTER_API_KEY,
            "search": query_b64,
            "page": page,
            "page_size": page_size,
            "is_web": 1,
        }

        resp = requests.get(HUNTER_API, params=params, timeout=30, proxies=get_proxy(PROXY_ENABLED_HUNTER))
        resp.raise_for_status()
        data = resp.json()

        if data.get("code") != 200:
            raise RuntimeError(
                f"Hunter API 错误 ({data.get('code')}): {data.get('message', '未知错误')}"
            )

        arr = data.get("data", {}).get("arr", [])
        if not arr:
            break

        for item in arr:
            url = item.get("url", "")
            if not url:
                continue
            scheme = "https" if url.startswith("https://") else "http"
            host_part = url.split("://")[1].split("/")[0] if "://" in url else url.split("/")[0]
            if ":" in host_part:
                host, port_str = host_part.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = 443 if scheme == "https" else 80
            else:
                host = host_part
                port = 443 if scheme == "https" else 80
            asset = FofaAsset(
                url=url, host=host, ip=item.get("ip"), port=port,
                title=item.get("title"), scheme=scheme,
            )
            key = asset.dedup_key
            if key not in seen:
                seen[key] = asset

        total = data.get("data", {}).get("total", 0)
        if page * page_size >= total or page * page_size >= size:
            break
        page += 1

    result = list(seen.values())
    logger.info("Hunter 官方查询: %s... → %d 条", query[:60], len(result))
    return result


def _query_proxy(query: str, size: int = HUNTER_SIZE) -> list[FofaAsset]:
    """通过代理接口查询 Hunter，使用 Cookie 认证。"""
    from urllib.parse import urlencode

    hunter_query = translate_fofa_to_hunter(query)
    if not hunter_query:
        return []

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.7060.96 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Cookie": HUNTER_PROXY_COOKIE,
    }

    body = urlencode({
        "search": hunter_query,
        "size": str(size),
    })

    resp = requests.post(
        HUNTER_PROXY_API,
        data=body,
        headers=headers,
        timeout=180,
        proxies=get_proxy(PROXY_ENABLED_HUNTER),
    )
    resp.raise_for_status()
    result = resp.json()

    if result.get("error"):
        errmsg = result.get("errmsg", "未知错误")
        raise RuntimeError(f"Hunter 代理接口错误: {errmsg}")

    # 代理接口返回 results 格式: [["host", "ip", "port", ...], ...]
    seen: dict[tuple, FofaAsset] = {}
    for row in result.get("results", []):
        if not row:
            continue
        raw_host = row[0] or ""
        ip = row[1] if len(row) > 1 else None
        raw_port = row[2] if len(row) > 2 else None
        try:
            fofa_port = int(raw_port) if raw_port not in (None, "") else None
        except (ValueError, TypeError):
            fofa_port = None

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
            scheme=scheme,
        )
        key = asset.dedup_key
        if key not in seen:
            seen[key] = asset

    result = list(seen.values())
    logger.info("Hunter 代理查询: %s... → %d 条", query[:60], len(result))
    return result


def query_hunter(query: str, size: int = HUNTER_SIZE,
                label: str = "") -> list[FofaAsset]:
    """查询 Hunter 资产，返回去重后的 FofaAsset 列表。

    自动选择模式：HUNTER_API_KEY 存在 → 官方 API，否则 → 代理接口。
    自动将 FOFA 语法翻译为 Hunter 语法，过滤不兼容片段。
    label: 可选模板名，错误日志附带。
    """
    try:
        if _use_official_api():
            return _query_official(query, size)
        return _query_proxy(query, size)
    except Exception as e:
        if label:
            logger.error("Hunter 查询失败 [%s]: %s... → %s", label, query[:60], e)
        raise


def query_hunter_multiple(queries: list[str], size: int = HUNTER_SIZE,
                         label: str = "") -> list[FofaAsset]:
    """批量查询多条 Hunter 语句，按去重键合并。label: 可选模板名。"""
    seen: dict[tuple, FofaAsset] = {}
    for i, query in enumerate(queries):
        if i > 0:
            time.sleep(1.5)
        try:
            assets = query_hunter(query, size, label=label)
            logger.info("Hunter 查询: %s... → %d 条", query[:60], len(assets))
            for a in assets:
                key = a.dedup_key
                if key not in seen:
                    seen[key] = a
        except Exception as e:
            logger.error("Hunter 查询失败 [%s]: %s... → %s", label or "-", query[:60], e)

    merged = list(seen.values())
    logger.info("Hunter 批量查询完成: %d 条查询 → %d 条去重资产", len(queries), len(merged))
    return merged

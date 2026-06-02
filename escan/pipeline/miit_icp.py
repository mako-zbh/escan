"""MIIT ICP 备案查询 — DIRECT CONNECTION ONLY.

政府网站 (beian.miit.gov.cn) 强制直连，不走代理池。
内部使用 ymicp IPv6 本地绑定实现轮换。

用法:
    from .miit_icp import query_icp_batch, format_output

    # IP 查询
    results = query_icp_batch(["1.2.3.4", "example.com"])
    # results: [{"ip": "1.2.3.4", "results": [{"domain": "...", "icp": "...", ...}], "error": None}]

    # 格式化
    print(format_output(results, label="模板名"))
"""

import os
import sys
import asyncio
import time
from pathlib import Path

from ..logging_config import get_logger

logger = get_logger("pipeline.miit_icp")

# 内嵌的 ICP_Query 目录
_ICP_QUERY_DIR = Path(__file__).resolve().parent / "icp_query"

if str(_ICP_QUERY_DIR) not in sys.path:
    sys.path.insert(0, str(_ICP_QUERY_DIR))

os.environ.setdefault("ICP_QUERY_CONFIG", str(_ICP_QUERY_DIR / "config.yml"))

_beian_instance = None


def _get_beian():
    """延迟初始化 beian 实例（内置 IPv6 轮换）。"""
    global _beian_instance
    if _beian_instance is not None:
        return _beian_instance

    old_cwd = os.getcwd()
    try:
        os.chdir(str(_ICP_QUERY_DIR))
        from ymicp import beian
        _beian_instance = beian()
    finally:
        os.chdir(old_cwd)

    return _beian_instance


async def _query_single_async(name: str, page_size: int = 20) -> dict:
    """异步查询单个域名/IP/单位的 ICP 备案信息。"""
    myicp = _get_beian()
    return await myicp.ymWeb(name, pageNum=1, pageSize=str(page_size), proxy="")


def _parse_miit_results(data: dict, query_name: str) -> list[dict]:
    """将 MIIT API 返回解析为统一格式。"""
    results = []
    if data.get("code") == 200 and data.get("params"):
        for item in data["params"].get("list", []):
            results.append({
                "domain": item.get("domain", ""),
                "icp": item.get("mainLicence", ""),
                "source": "miit",
                "unitName": item.get("unitName", ""),
                "natureName": item.get("natureName", ""),
                "leaderName": item.get("leaderName", ""),
                "serviceLicence": item.get("serviceLicence", ""),
                "limitAccess": item.get("limitAccess", ""),
                "contentTypeName": item.get("contentTypeName", ""),
                "updateRecordTime": item.get("updateRecordTime", ""),
                "domainId": item.get("domainId"),
                "mainId": item.get("mainId"),
                "serviceId": item.get("serviceId"),
                "total": data["params"].get("total", 0),
            })
    return results


def query_icp_single(name: str) -> dict:
    """同步查询单个域名/IP 的 ICP 备案信息。"""
    try:
        raw = asyncio.run(_query_single_async(name))
        results = _parse_miit_results(raw, name)
        return {
            "code": raw.get("code", 500),
            "params": raw.get("params", {}),
            "results": results,
        }
    except Exception as e:
        logger.error("MIIT ICP 查询失败: %s → %s", name, e)
        return {"code": 500, "message": str(e), "results": []}


def query_icp_batch(hosts: list[str], concurrency: int = 3) -> list[dict]:
    """批量查询 IP/域名，返回格式兼容旧的 aizhan batch_query_icp。

    Returns:
        [{"ip": host, "results": [{"domain": ..., "icp": ..., ...}], "error": None}, ...]
    """
    if not hosts:
        return []

    semaphore = asyncio.Semaphore(concurrency)

    async def _query_one(host: str) -> dict:
        async with semaphore:
            try:
                raw = await _query_single_async(host)
                results = _parse_miit_results(raw, host)
                return {"ip": host, "results": results, "error": None}
            except Exception as e:
                logger.error("MIIT ICP 查询失败 [%s]: %s", host, e)
                return {"ip": host, "results": [], "error": str(e)}

    async def _batch():
        tasks = [_query_one(h) for h in hosts]
        return await asyncio.gather(*tasks)

    try:
        domain_results = asyncio.run(_batch())
        return list(domain_results)
    except Exception as e:
        logger.error("MIIT ICP 批量查询失败: %s", e)
        return [{"ip": h, "results": [], "error": str(e)} for h in hosts]


# ---------------------------------------------------------------------------
# 格式化输出（兼容旧的 format_output）
# ---------------------------------------------------------------------------

def format_output(all_results: list[dict], label: str = "") -> str:
    """格式化 ICP 查询结果。"""
    lines = [
        "=" * 70,
        f"模板: {label}" if label else "",
        f"ICP 备案查询结果（{time.strftime('%Y-%m-%d %H:%M:%S')}）",
        "数据源: MIIT 官方 API (ICP_Query)",
        "=" * 70,
    ]
    total_domains = 0
    total_icp = 0
    valid_count = 0

    for item in all_results:
        if item.get("error") or not item.get("results"):
            continue
        valid_count += 1
        lines.append(f"\n> {item['ip']}")
        for entry in item["results"]:
            domain = entry.get("domain") or "-"
            icp = entry.get("icp") or "-"
            unit = entry.get("unitName") or "-"
            nature = entry.get("natureName") or ""
            update_time = entry.get("updateRecordTime") or ""
            lines.append(f"  域名: {domain:<35s}  备案号: {icp}")
            lines.append(f"  {' ' * 5} 主办单位: {unit}")
            if nature:
                lines.append(f"  {' ' * 5} 单位性质: {nature}")
            if update_time:
                lines.append(f"  {' ' * 5} 审核时间: {update_time}")
            total_domains += 1
            if icp != "-":
                total_icp += 1

    lines += [
        "",
        "=" * 70,
        f"统计: 查询 {len(all_results)} 个 host | 有数据 {valid_count} | "
        f"域名 {total_domains} | 有备案号 {total_icp}",
        "=" * 70,
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 旧接口兼容别名
# ---------------------------------------------------------------------------

def batch_query_icp(hosts: list[str], concurrency: int = 3) -> list[dict]:
    """兼容旧 icp.batch_query_icp 调用。"""
    return query_icp_batch(hosts, concurrency)


def enrich_icp_with_api(all_results: list[dict]) -> list[dict]:
    """兼容旧接口 — MIIT API 已包含完整数据，无需额外补充。"""
    return all_results

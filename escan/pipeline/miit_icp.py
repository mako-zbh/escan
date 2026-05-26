"""
MIIT ICP 备案查询 — 基于 ICP_Query 项目的官方工信部 API。

集成路径：直接导入 ../ICP_Query 中的 beian 类，通过 asyncio 桥接
为同步调用，供 pipeline 流程直接使用。

beian 内置 IPv6 本地地址池轮换（Linux/macOS 自动检测），无需外部代理。

用法:
    from .miit_icp import query_icp_batch
    results = query_icp_batch(["qq.com", "baidu.com"])
    # results: [{"domain": "qq.com", "unitName": "...", "mainLicence": "...", ...}]
"""

import os
import sys
import asyncio
from pathlib import Path

from ..logging_config import get_logger

logger = get_logger("pipeline.miit_icp")

_ICP_QUERY_DIR = Path(__file__).resolve().parent.parent.parent.parent / "ICP_Query"

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
    """异步查询单个域名/单位的 ICP 备案信息。"""
    myicp = _get_beian()
    return await myicp.ymWeb(name, pageNum=1, pageSize=str(page_size), proxy="")


def query_icp_single(name: str) -> dict:
    """同步查询单个域名的 ICP 备案信息。

    Returns:
        {
            "code": 200/500,
            "params": {
                "list": [{"domain": "...", "unitName": "...", "mainLicence": "...", ...}],
                "total": int
            }
        }
    """
    try:
        return asyncio.run(_query_single_async(name))
    except Exception as e:
        logger.error("MIIT ICP 查询失败: %s → %s", name, e)
        return {"code": 500, "message": str(e)}


def query_icp_batch(domains: list[str], concurrency: int = 5) -> list[dict]:
    """同步批量查询多个域名的 ICP 备案信息。

    Returns:
        [{"ip": domain_or_ip, "results": [{"domain": ..., "icp": ..., "icp_api": {...}}], "error": None}, ...]
        格式与旧 aizhan batch_query_icp 兼容。
    """
    if not domains:
        return []

    semaphore = asyncio.Semaphore(concurrency)

    async def _query_one(name: str) -> dict:
        async with semaphore:
            try:
                data = await _query_single_async(name)
                results = []
                if data.get("code") == 200 and data.get("params"):
                    for item in data["params"].get("list", []):
                        results.append({
                            "domain": item.get("domain", ""),
                            "icp": item.get("mainLicence", ""),
                            "source": "miit",
                            "icp_api": {
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
                            },
                        })
                return {"ip": name, "results": results, "error": None}
            except Exception as e:
                logger.error("MIIT ICP 查询异常: %s → %s", name, e)
                return {"ip": name, "results": [], "error": str(e)}

    async def _batch():
        tasks = [_query_one(d) for d in domains]
        return await asyncio.gather(*tasks)

    try:
        return asyncio.run(_batch())
    except Exception as e:
        logger.error("MIIT ICP 批量查询失败: %s", e)
        return [{"ip": d, "results": [], "error": str(e)} for d in domains]

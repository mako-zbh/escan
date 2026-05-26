"""ICP 备案查询 — 多源聚合（爱站 + ip138 + 本地 ICP API）"""

import re
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from ..config import ICP_THREADS, ICP_DELAY
from ..logging_config import get_logger
from ..utils.network import is_ipv4, get_main_domain

logger = get_logger("pipeline.icp")

_NO_PROXY = {"http": None, "https": None}

MAX_RETRIES = 3
RETRY_BACKOFF = 10
AIZHAN_URL = "https://dns.aizhan.com/{ip}/"
IP138_URL = "https://site.ip138.com/{ip}/"
ICP_API_URL = "http://127.0.0.1:16181/query/web"


# ---------------------------------------------------------------------------
# 通用 HTTP 会话
# ---------------------------------------------------------------------------

def _build_session() -> requests.Session:
    s = requests.Session()
    s.trust_env = False  # 绕过系统代理环境变量
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.5",
    })
    return s


# ---------------------------------------------------------------------------
# 爱站 IP 反查
# ---------------------------------------------------------------------------

def parse_aizhan_html(html: str) -> list[dict]:
    """解析爱站 IP 反查页面，提取域名和 ICP 备案号。"""
    results = []
    tr_pattern = re.compile(r"<tr[^>]*>(.*?)</tr>", re.DOTALL | re.IGNORECASE)
    td_domain = re.compile(
        r'<td[^>]*class="domain"[^>]*>.*?<a[^>]*>([^<]+)</a>',
        re.DOTALL | re.IGNORECASE,
    )
    icp_loose = re.compile(r"([一-龥]{1,6}ICP[备证]+\d+号(?:-\d+)?)")
    domain_link = re.compile(
        r'<a href="[^"]*" rel="nofollow" target="_blank">([a-zA-Z0-9\-\.]+)</a>'
    )

    for tr_match in tr_pattern.finditer(html):
        row_html = tr_match.group(1)
        entry = {"domain": None, "icp": None}

        dm = td_domain.search(row_html)
        if not dm:
            dm = domain_link.search(row_html)
        if dm:
            domain = dm.group(1).strip()
            if not is_ipv4(domain) and re.match(r"^[a-zA-Z0-9\-\.]+$", domain):
                entry["domain"] = domain

        icp = icp_loose.search(row_html)
        if icp:
            entry["icp"] = icp.group(1).strip()

        if entry["domain"] or entry["icp"]:
            results.append(entry)

    return results


def _query_aizhan(ip: str, session: requests.Session) -> dict:
    """查询爱站单个 IP 的域名和备案信息。"""
    for attempt in range(MAX_RETRIES):
        try:
            resp = session.get(
                AIZHAN_URL.format(ip=ip),
                timeout=20,
                allow_redirects=True,
            )
            if resp.status_code == 404:
                return {"ip": ip, "results": [], "source": "aizhan", "error": "无数据(404)"}

            if resp.status_code == 429:
                wait = RETRY_BACKOFF * (attempt + 1) + random.uniform(0, 3)
                logger.warning("%s aizhan 429 限流，重试 %d/%d，等待 %ds", ip, attempt + 1, MAX_RETRIES, int(wait))
                time.sleep(wait)
                continue

            resp.raise_for_status()
            return {"ip": ip, "results": parse_aizhan_html(resp.text), "source": "aizhan", "error": None}

        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 429:
                wait = RETRY_BACKOFF * (attempt + 1) + random.uniform(0, 3)
                logger.warning("%s aizhan 429 限流，重试 %d/%d，等待 %ds", ip, attempt + 1, MAX_RETRIES, int(wait))
                time.sleep(wait)
                continue
            return {"ip": ip, "results": [], "source": "aizhan", "error": str(e)}
        except Exception as e:
            return {"ip": ip, "results": [], "source": "aizhan", "error": str(e)}

    return {"ip": ip, "results": [], "source": "aizhan", "error": f"429 重试 {MAX_RETRIES} 次后仍失败"}


# ---------------------------------------------------------------------------
# ip138 IP 反查域名
# ---------------------------------------------------------------------------

def parse_ip138_html(html: str) -> list[str]:
    """解析 ip138 IP 反查页面，提取绑定域名列表。

    HTML 结构::

        <li><span class="date">2025-11-02-----2026-01-07</span>
        <a href="/sunxuexi.top/" target="_blank">sunxuexi.top</a></li>
    """
    domains = []
    pattern = re.compile(
        r'<span\s+class="date"[^>]*>[^<]*</span>\s*<a\s+href="/([^/"]+)/"',
        re.IGNORECASE,
    )
    for m in pattern.finditer(html):
        domain = m.group(1).strip()
        if domain and not is_ipv4(domain):
            domains.append(domain)
    return list(set(domains))


def query_ip138(ip: str, session: requests.Session) -> dict:
    """查询 ip138 的 IP 反查结果。"""
    try:
        resp = session.get(
            IP138_URL.format(ip=ip),
            timeout=20,
            allow_redirects=True,
        )
        if resp.status_code == 404:
            return {"ip": ip, "domains": [], "source": "ip138", "error": "无数据(404)"}

        resp.raise_for_status()
        domains = parse_ip138_html(resp.text)
        return {"ip": ip, "domains": domains, "source": "ip138", "error": None}

    except Exception as e:
        return {"ip": ip, "domains": [], "source": "ip138", "error": str(e)}


# ---------------------------------------------------------------------------
# 本地 ICP 备案 API（http://127.0.0.1:16181）
# ---------------------------------------------------------------------------

def _build_icp_api_headers() -> dict:
    return {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Referer": "http://127.0.0.1:16181/",
        "Content-Type": "application/json",
    }


def query_icp_api(domain: str) -> dict | None:
    """通过本地 ICP API 查询域名备案信息。

    GET /query/web?search={domain}&pageNum=1&pageSize=10

    Returns:
        {"icp_number": ..., "company_name": ..., "company_type": ...} 或 None
    """
    try:
        resp = requests.get(
            ICP_API_URL,
            params={"search": domain, "pageNum": 1, "pageSize": 10},
            headers=_build_icp_api_headers(),
            timeout=15,
            proxies=_NO_PROXY,
        )

        if resp.status_code == 429:
            logger.warning("ICP API 429 限流，跳过 %s", domain)
            return None

        resp.raise_for_status()
        data = resp.json()

        if data.get("code") == 429:
            logger.warning("ICP API 429 限流，跳过 %s: %s", domain, data.get("msg", ""))
            return None

        if data.get("code") != 200 or not data.get("success"):
            return None

        items = data.get("params", {}).get("list", [])
        if not items:
            return None

        item = items[0]
        return {
            "icp_number": item.get("serviceLicence", "") or item.get("mainLicence", ""),
            "company_name": item.get("unitName", ""),
            "company_type": item.get("natureName", ""),
            "site_name": item.get("domain", ""),
            "audit_date": item.get("updateRecordTime", ""),
        }

    except Exception as e:
        logger.debug("ICP API 查询 %s 失败: %s", domain, e)
        return None


def batch_query_icp_api(
    domains: list[str],
    delay: float = 2.0,  # 请求间隔（秒），避免触发限流
) -> list[dict]:
    """对一批域名查询本地 ICP API 获取备案信息。

    自动将子域名转化为主域名再查询，避免子域名查不到备案。
    """
    if not domains:
        return []

    # 转化为主域名并去重，保留原始域名映射
    main_map: dict[str, str] = {}  # main_domain → first original
    for d in domains:
        if is_ipv4(d):
            main_map[d] = d
        else:
            main = get_main_domain(d)
            if main not in main_map:
                main_map[main] = d

    main_domains = list(main_map)
    logger.info(
        "ICP API 查询 %d 个域名（去重为主域名后 %d 个）",
        len(domains), len(main_domains),
    )

    results = []
    for i, domain in enumerate(main_domains):
        if i > 0:
            time.sleep(delay)
        try:
            icp_info = query_icp_api(domain)
            results.append({"domain": domain, "icp": icp_info})
            icp_num = icp_info.get("icp_number", "-") if icp_info else "-"
            logger.info("  %s → ICP: %s", domain, icp_num)
        except Exception as e:
            results.append({"domain": domain, "icp": None, "error": str(e)})
            logger.error("  %s → %s", domain, e)

    return results


# ---------------------------------------------------------------------------
# 聚合查询 — 合并爱站 + ip138
# ---------------------------------------------------------------------------

def query_ip(ip: str, delay: float = ICP_DELAY) -> dict:
    """查询单个 IP 的域名和备案信息（聚合爱站 + ip138）。

    Returns:
        {"ip": ..., "results": list[dict], "error": str | None}
    """
    jitter = random.uniform(-1.0, 1.0)
    if delay + jitter > 0:
        time.sleep(delay + jitter)

    session = _build_session()

    aizhan_result = _query_aizhan(ip, session)
    ip138_result = query_ip138(ip, session)

    # 合并结果 — 爱站为主，ip138 补充缺失域名
    merged_results = list(aizhan_result.get("results", []))
    aizhan_domains = {r.get("domain") for r in merged_results if r.get("domain")}

    for domain in ip138_result.get("domains", []):
        if domain and domain not in aizhan_domains:
            merged_results.append({"domain": domain, "icp": None, "source": "ip138"})
            aizhan_domains.add(domain)

    # 合并错误信息
    combined_error = None
    errors = []
    if aizhan_result.get("error"):
        errors.append(f"aizhan: {aizhan_result['error']}")
    if ip138_result.get("error"):
        errors.append(f"ip138: {ip138_result['error']}")
    if errors:
        combined_error = "; ".join(errors)

    return {"ip": ip, "results": merged_results, "error": combined_error}


# ---------------------------------------------------------------------------
# 批量查询
# ---------------------------------------------------------------------------

def batch_query_icp(
    ips: list[str],
    threads: int = ICP_THREADS,
    delay: float = ICP_DELAY,
) -> list[dict]:
    """批量查询多个 IP 的域名和备案信息（聚合爱站 + ip138）。"""
    logger.info("ICP 查询 %d 个 IP，%d 线程，间隔 %.1fs", len(ips), threads, delay)

    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {executor.submit(query_ip, ip, delay): ip for ip in ips}
        for future in as_completed(future_map):
            ip = future_map[future]
            try:
                res = future.result()
                results.append(res)
                status = f"{len(res['results'])} 条域名" if not res["error"] else res["error"]
                logger.info("  %s → %s", ip, status)
            except Exception as e:
                results.append({"ip": ip, "results": [], "error": str(e)})
                logger.error("  %s → %s", ip, e)

    results.sort(key=lambda x: x["ip"])
    return results


def enrich_icp_with_api(all_results: list[dict]) -> list[dict]:
    """对聚合结果中的所有域名补充本地 ICP API 备案详情。

    自动将子域名转化为主域名再查询，为每个域名的 dict 添加 icp_api 字段。
    """
    all_domains = set()
    for item in all_results:
        if item.get("error") or not item.get("results"):
            continue
        for entry in item["results"]:
            domain = entry.get("domain")
            if domain:
                all_domains.add(domain)

    if not all_domains:
        return all_results

    api_results = batch_query_icp_api(list(all_domains))
    api_map = {r["domain"]: r.get("icp") for r in api_results if r.get("icp")}

    for item in all_results:
        for entry in item.get("results", []):
            domain = entry.get("domain")
            if not domain:
                continue
            # 将子域名转化为主域名再匹配（与 batch_query_icp_api 一致）
            main = get_main_domain(domain)
            if main in api_map:
                entry["icp_api"] = api_map[main]

    return all_results


# ---------------------------------------------------------------------------
# 格式化输出
# ---------------------------------------------------------------------------

def format_output(all_results: list[dict], label: str = "") -> str:
    """格式化 ICP 查询结果。"""
    lines = [
        "=" * 70,
        f"模板: {label}" if label else "",
        f"ICP 备案查询结果（{time.strftime('%Y-%m-%d %H:%M:%S')}）",
        "数据源: 爱站 + ip138 | 备案: 本地 ICP API",
        "=" * 70,
    ]
    total_domains = 0
    total_icp = 0
    total_api = 0
    valid_count = 0

    for item in all_results:
        if item.get("error") or not item.get("results"):
            continue
        valid_count += 1
        lines.append(f"\n> {item['ip']}")
        for entry in item["results"]:
            domain = entry.get("domain") or "-"
            icp = entry.get("icp") or "-"
            lines.append(f"  域名: {domain:<35s}  备案号: {icp}")
            total_domains += 1
            if icp != "-":
                total_icp += 1
            # ICP API 补充信息
            icp_api = entry.get("icp_api")
            if icp_api:
                company = icp_api.get("company_name", "-")
                api_icp = icp_api.get("icp_number", "-")
                lines.append(f"  {' ' * 5} [API] 主办单位: {company:<25s} 备案号: {api_icp}")
                total_api += 1

    lines += [
        "",
        "=" * 70,
        f"统计: 查询 {len(all_results)} IP | 有数据 {valid_count} | "
        f"域名 {total_domains} | 有备案号 {total_icp} | ICP API 补充 {total_api}",
        "=" * 70,
    ]
    return "\n".join(lines)

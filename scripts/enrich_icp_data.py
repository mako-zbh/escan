"""回填 icp_results 的 icp_api 字段（调用本地 ICP API）."""

import json
import sys
import time
import argparse

import requests

sys.path.insert(0, ".")
from escan.database.connection import get_cursor

API_URL = "http://127.0.0.1:16181/query/web"
DELAY = 1.8  # seconds between API calls


def log(msg):
    print(msg, flush=True)


def query_icp_api(domain: str) -> dict | None:
    try:
        resp = requests.get(
            API_URL,
            params={"search": domain, "pageNum": 1, "pageSize": 5},
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "*/*",
                "Referer": "http://127.0.0.1:16181/",
            },
            timeout=18,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("code") == 429:
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
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--start", type=int, default=0, help="跳过前 N 个域名")
    args = parser.parse_args()

    # 获取待回填域名列表
    with get_cursor() as cur:
        cur.execute("""
            SELECT DISTINCT domain FROM icp_results
            WHERE domain IS NOT NULL AND icp_api IS NULL
            ORDER BY domain
        """)
        domains = [r[0] for r in cur.fetchall()]

    log(f"待回填域名: {len(domains)}")

    total = 0
    for i in range(args.start, len(domains)):
        domain = domains[i]
        start = time.monotonic()

        if i > args.start:
            elapsed = time.monotonic() - start
            time.sleep(max(0, DELAY - elapsed))

        icp_data = query_icp_api(domain)

        if icp_data:
            icp_number = icp_data.get("icp_number", "")
            company = icp_data.get("company_name", "")
            log(f"  [{i+1}/{len(domains)}] {domain} → {company} / {icp_number}")

            if not args.dry_run:
                # 每条单独 commit，立即可见
                with get_cursor() as cur:
                    cur.execute("""
                        UPDATE icp_results
                        SET icp_api = %s::jsonb, icp_number = %s
                        WHERE domain = %s AND icp_api IS NULL
                    """, (json.dumps(icp_data), icp_number, domain))
                total += 1
        else:
            if (i + 1) % 20 == 0:
                log(f"  [{i+1}/{len(domains)}] ...")

    log(f"\n完成: {total} 个域名回填了 ICP 备案信息")


if __name__ == "__main__":
    main()

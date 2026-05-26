"""数据访问层 — 所有 CRUD 操作。

每个函数第一参数为 cursor，cursor 为 None 时安全返回默认值。
"""

import json
import uuid

from ..logging_config import get_logger

logger = get_logger("database.dao")


def _ok(rowcount: int) -> bool:
    return rowcount > 0


# === poc_templates ===

def upsert_poc_template(cursor, data: dict) -> bool:
    """插入或更新 POC 模板。"""
    if cursor is None:
        return False
    cursor.execute("""
        INSERT INTO poc_templates (template_id, name, severity, tags, file_path, fofa_query, api_truncated, created_at, updated_at)
        VALUES (%(template_id)s, %(name)s, %(severity)s, %(tags)s, %(file_path)s, %(fofa_query)s, %(api_truncated)s, NOW(), NOW())
        ON CONFLICT (template_id) DO UPDATE SET
            name = EXCLUDED.name,
            severity = EXCLUDED.severity,
            tags = EXCLUDED.tags,
            file_path = COALESCE(EXCLUDED.file_path, poc_templates.file_path),
            fofa_query = COALESCE(EXCLUDED.fofa_query, poc_templates.fofa_query),
            api_truncated = EXCLUDED.api_truncated,
            updated_at = NOW()
    """, {
        "template_id": data["id"],
        "name": data["name"],
        "severity": data.get("severity"),
        "tags": data.get("tags"),
        "file_path": data.get("file"),
        "fofa_query": data.get("fofa_query"),
        "api_truncated": data.get("api_truncated", False),
    })
    return _ok(cursor.rowcount)


def get_poc_template(cursor, template_id: str) -> dict | None:
    if cursor is None:
        return None
    cursor.execute(
        "SELECT template_id, name, severity, tags, created_at, updated_at "
        "FROM poc_templates WHERE template_id = %s",
        (template_id,),
    )
    row = cursor.fetchone()
    if not row:
        return None
    return dict(zip(
        ("template_id", "name", "severity", "tags", "created_at", "updated_at"), row
    ))


# === scan_tasks ===

def create_scan_task(cursor, task_type: str, engine: str, output_dir: str) -> str | None:
    """创建扫描任务，返回 task_id UUID 字符串。"""
    if cursor is None:
        return None
    task_id = str(uuid.uuid4())
    cursor.execute("""
        INSERT INTO scan_tasks (task_id, task_type, engine, status, output_dir, started_at)
        VALUES (%s, %s, %s, 'running', %s, NOW())
    """, (task_id, task_type, engine, output_dir))
    logger.debug("创建扫描任务: %s (%s/%s)", task_id, task_type, engine)
    return task_id


def complete_scan_task(cursor, task_id: str, status: str, counts: dict, error: str = None):
    """标记扫描任务完成，写入各步计数。"""
    if cursor is None:
        return
    cursor.execute("""
        UPDATE scan_tasks
        SET status = %s,
            step1_assets = %s, step2_vulns = %s,
            step3_hosts = %s, step4_icp = %s,
            current_step = %s,
            error_message = %s,
            completed_at = NOW()
        WHERE task_id = %s
    """, (
        status,
        counts.get("step1", 0), counts.get("step2", 0),
        counts.get("step3", 0), counts.get("step4", 0),
        0,  # current_step cleared on completion
        error, task_id,
    ))


# === discovered_assets ===

def insert_discovered_assets(cursor, task_id: str, template_id: str,
                              asset_records: list[dict], engine: str) -> int:
    """批量插入资产，跳过重复，同步写入全局 URL 注册表。"""
    if cursor is None or not asset_records:
        return 0
    from hashlib import md5
    from psycopg2.extras import execute_values

    rows = []
    for r in asset_records:
        url = r["url"]
        url_hash = md5(url.encode()).hexdigest()[:12]
        rows.append((
            str(uuid.uuid4()), task_id, template_id,
            url, r.get("host"), r.get("port"), r.get("scheme", "http"),
            r.get("title"), engine, r.get("query_used"),
            url_hash,
        ))

    execute_values(cursor, """
        INSERT INTO discovered_assets
            (asset_id, task_id, template_id, url, host, port, scheme, title, engine, query_used, url_hash)
        VALUES %s
        ON CONFLICT (task_id, template_id, url) DO NOTHING
    """, rows, page_size=200)

    # 同步写入全局 URL 注册表
    for r in asset_records:
        url = r["url"]
        url_hash = md5(url.encode()).hexdigest()[:12]
        cursor.execute("""
            INSERT INTO global_url_registry (url_hash, canonical_url, first_seen_task, template_count, last_seen_at)
            VALUES (%s, %s, %s, 1, NOW())
            ON CONFLICT (url_hash) DO UPDATE SET
                template_count = global_url_registry.template_count + 1,
                last_seen_at = NOW()
        """, (url_hash, url, task_id))

    return cursor.rowcount


def get_assets_by_task(cursor, task_id: str) -> list[dict]:
    if cursor is None:
        return []
    cursor.execute("""
        SELECT asset_id, template_id, url, host, port, scheme, title, engine, discovered_at
        FROM discovered_assets WHERE task_id = %s ORDER BY discovered_at
    """, (task_id,))
    return [_asset_row(r) for r in cursor.fetchall()]


def _asset_row(row) -> dict:
    return dict(zip(
        ("asset_id", "template_id", "url", "host", "port", "scheme", "title", "engine", "discovered_at"), row
    ))


# === scan_results ===

def insert_scan_results(cursor, task_id: str, template_id: str,
                         lines: list[str]) -> int:
    """批量插入 nuclei 扫描结果。每行格式: [template] [proto] [severity] URL"""
    if cursor is None or not lines:
        return 0
    from psycopg2.extras import execute_values
    import re

    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # 解析: [template-name] [protocol] [severity] url
        parts = line.split(" ", 3)
        protocol = parts[1].strip("[]") if len(parts) > 1 else None
        severity = parts[2].strip("[]") if len(parts) > 2 else None
        matched_url = parts[3] if len(parts) > 3 else (parts[0] if len(parts) == 1 else line)
        rows.append((
            str(uuid.uuid4()), task_id, template_id,
            protocol, severity, matched_url, line,
        ))

    if not rows:
        return 0

    execute_values(cursor, """
        INSERT INTO scan_results
            (result_id, task_id, template_id, protocol, severity, matched_url, raw_line)
        VALUES %s
        ON CONFLICT (task_id, template_id, matched_url) DO NOTHING
    """, rows, page_size=200)
    return cursor.rowcount


def get_scan_results_by_task(cursor, task_id: str) -> list[dict]:
    if cursor is None:
        return []
    cursor.execute("""
        SELECT r.result_id, r.template_id, r.protocol, r.severity, r.matched_url, r.raw_line, r.scanned_at
        FROM scan_results r WHERE r.task_id = %s ORDER BY r.scanned_at
    """, (task_id,))
    return [dict(zip(
        ("result_id", "template_id", "protocol", "severity", "matched_url", "raw_line", "scanned_at"), row
    )) for row in cursor.fetchall()]


# === host_results ===

def insert_host_results(cursor, task_id: str, template_name: str,
                        hosts: list[str], template_id: str = None) -> int:
    """批量插入 host 提取结果，按 (task_id, template_name, host) 去重。"""
    if cursor is None or not hosts:
        return 0
    from psycopg2.extras import execute_values

    tid = template_id or template_name
    rows = [
        (str(uuid.uuid4()), task_id, template_name, h, tid, False)
        for h in hosts
    ]
    execute_values(cursor, """
        INSERT INTO host_results
            (host_result_id, task_id, template_name, host, template_id, is_ip)
        VALUES %s
        ON CONFLICT (task_id, template_name, host) DO NOTHING
    """, rows, page_size=200)
    return cursor.rowcount


# === icp_results ===

def insert_icp_results(cursor, task_id: str, icp_list: list[dict],
                        template_id: str = None,
                        ip_asset_map: dict[str, str] = None) -> int:
    """批量插入 ICP 备案结果。只写入有备案数据（icp_api 或 icp_number）的记录。

    template_id: 关联的 POC 模板 ID
    ip_asset_map: IP → asset_id 映射，用于关联到 discovered_assets
    """
    if cursor is None or not icp_list:
        return 0
    from psycopg2.extras import execute_values

    asset_map = ip_asset_map or {}
    rows = []
    for entry in icp_list:
        ip = entry.get("ip", "")
        asset_id = asset_map.get(ip)
        for r in entry.get("results", []):
            icp_number = r.get("icp")
            icp_api = r.get("icp_api")
            if not icp_number and not icp_api:
                continue
            rows.append((
                str(uuid.uuid4()), task_id, ip,
                r.get("domain"), icp_number, r.get("source", "aizhan"),
                json.dumps(icp_api) if icp_api else None,
                template_id,
                asset_id,
            ))

    if not rows:
        return 0

    execute_values(cursor, """
        INSERT INTO icp_results
            (icp_result_id, task_id, ip_address, domain, icp_number, source, icp_api,
             template_id, asset_id)
        VALUES %s
        ON CONFLICT (task_id, ip_address, domain) DO NOTHING
    """, rows, page_size=200)
    return cursor.rowcount


# === query_cache ===

def get_cached_assets(cursor, query_hash: str, engine: str) -> list[str] | None:
    """获取未过期的缓存资产。返回 None 表示未命中。"""
    if cursor is None:
        return None
    cursor.execute("""
        SELECT assets FROM query_cache
        WHERE query_hash = %s AND engine = %s AND expires_at > NOW()
    """, (query_hash, engine))
    row = cursor.fetchone()
    if row:
        return row[0]  # psycopg2 自动解析 JSONB 为 Python list
    return None


def set_cached_assets(cursor, query_hash: str, query_string: str,
                       assets: list[str], engine: str,
                       template_id: str = None,
                       result_count: int = None,
                       truncated: bool = False) -> bool:
    """写入缓存，24h 过期。"""
    if cursor is None:
        return False
    cursor.execute("""
        INSERT INTO query_cache (query_hash, query_string, engine, assets, template_id, result_count, truncated, created_at, expires_at)
        VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s, NOW(), NOW() + INTERVAL '24 hours')
        ON CONFLICT (query_hash) DO UPDATE SET
            query_string = EXCLUDED.query_string,
            assets = EXCLUDED.assets,
            template_id = COALESCE(EXCLUDED.template_id, query_cache.template_id),
            result_count = COALESCE(EXCLUDED.result_count, query_cache.result_count),
            truncated = EXCLUDED.truncated,
            created_at = NOW(),
            expires_at = NOW() + INTERVAL '24 hours'
    """, (query_hash, query_string, json.dumps(assets), engine, template_id, result_count, truncated))
    return _ok(cursor.rowcount)


def clean_expired_cache(cursor) -> int:
    """清理过期缓存。"""
    if cursor is None:
        return 0
    cursor.execute("DELETE FROM query_cache WHERE expires_at <= NOW()")
    return cursor.rowcount


# === dedup_index ===

def rebuild_dedup_index(cursor, entries: list[dict]) -> int:
    """全量重建去重索引（先清空再插入）。"""
    if cursor is None:
        return 0
    cursor.execute("DELETE FROM dedup_index")
    for e in entries:
        cursor.execute("""
            INSERT INTO dedup_index
                (template_id, name, tags, cve_list, method, path, fofa_hash, path_hash, file_path)
            VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s)
        """, (
            e["id"], e["name"], e.get("tags"),
            json.dumps(e.get("cve_list", [])),
            e.get("method", "GET"), e.get("path"),
            e.get("fofa_hash"), e.get("path_hash"), e.get("file"),
        ))
    return len(entries)


def insert_dedup_entry(cursor, entry: dict) -> bool:
    """插入单条去重索引。"""
    if cursor is None:
        return False
    cursor.execute("""
        INSERT INTO dedup_index
            (template_id, name, tags, cve_list, method, path, fofa_hash, path_hash, file_path)
        VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s)
        ON CONFLICT (template_id) DO UPDATE SET
            name = EXCLUDED.name,
            tags = EXCLUDED.tags,
            cve_list = EXCLUDED.cve_list,
            method = EXCLUDED.method,
            path = EXCLUDED.path,
            fofa_hash = EXCLUDED.fofa_hash,
            path_hash = EXCLUDED.path_hash,
            file_path = EXCLUDED.file_path,
            indexed_at = NOW()
    """, (
        entry["id"], entry["name"], entry.get("tags"),
        json.dumps(entry.get("cve_list", [])),
        entry.get("method", "GET"), entry.get("path"),
        entry.get("fofa_hash"), entry.get("path_hash"), entry.get("file"),
    ))
    return _ok(cursor.rowcount)


def load_dedup_index(cursor) -> list[dict]:
    """从 DB 加载去重索引（供 DedupIndex 初始化）。"""
    if cursor is None:
        return []
    cursor.execute("""
        SELECT template_id, name, tags, cve_list, method, path, fofa_hash, path_hash, file_path
        FROM dedup_index
    """)
    return [dict(zip(
        ("id", "name", "tags", "cve_list", "method", "path", "fofa_hash", "path_hash", "file"), row
    )) for row in cursor.fetchall()]


# === checkpoint ===

def upsert_checkpoint(cursor, task_id: str, output_dir: str,
                       scan_type: str, engine: str, state: dict) -> bool:
    """写入或更新扫描断点快照。"""
    if cursor is None:
        return False
    cursor.execute("""
        INSERT INTO checkpoint_snapshots
            (task_id, output_dir, scan_type, engine, state, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s::jsonb, NOW(), NOW())
        ON CONFLICT (task_id) DO UPDATE SET
            output_dir = EXCLUDED.output_dir,
            state = EXCLUDED.state,
            updated_at = NOW()
    """, (task_id, output_dir, scan_type, engine, json.dumps(state)))
    return _ok(cursor.rowcount)


def load_checkpoint_from_db(cursor, task_id: str) -> dict | None:
    """从 DB 加载断点快照。"""
    if cursor is None:
        return None
    cursor.execute("""
        SELECT state FROM checkpoint_snapshots WHERE task_id = %s
    """, (task_id,))
    row = cursor.fetchone()
    if row:
        return row[0]  # psycopg2 自动解析 JSONB
    return None


# === template_scan_coverage ===

def upsert_template_coverage(cursor, task_id: str, template_id: str,
                              data: dict) -> bool:
    """写入或更新模板扫描覆盖状态。"""
    if cursor is None:
        return False
    cursor.execute("""
        INSERT INTO template_scan_coverage
            (coverage_id, task_id, template_id, has_assets, asset_count,
             was_scanned, hits_found, hosts_extracted, icp_queried)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (task_id, template_id) DO UPDATE SET
            has_assets = COALESCE(EXCLUDED.has_assets, template_scan_coverage.has_assets),
            asset_count = COALESCE(EXCLUDED.asset_count, template_scan_coverage.asset_count),
            was_scanned = COALESCE(EXCLUDED.was_scanned, template_scan_coverage.was_scanned),
            hits_found = COALESCE(EXCLUDED.hits_found, template_scan_coverage.hits_found),
            hosts_extracted = COALESCE(EXCLUDED.hosts_extracted, template_scan_coverage.hosts_extracted),
            icp_queried = COALESCE(EXCLUDED.icp_queried, template_scan_coverage.icp_queried)
    """, (
        str(uuid.uuid4()), task_id, template_id,
        data.get("has_assets", False),
        data.get("asset_count", 0),
        data.get("was_scanned", False),
        data.get("hits_found", 0),
        data.get("hosts_extracted", 0),
        data.get("icp_queried", False),
    ))
    return _ok(cursor.rowcount)


# === template_icp_stats ===

def upsert_template_icp_stats(cursor, task_id: str, template_id: str,
                               data: dict) -> bool:
    """写入或更新模板 ICP 统计。"""
    if cursor is None:
        return False
    cursor.execute("""
        INSERT INTO template_icp_stats
            (icp_stats_id, task_id, template_id, ips_queried, ips_with_data,
             domains_found, domains_with_icp, icp_api_supplement)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (task_id, template_id) DO UPDATE SET
            ips_queried = EXCLUDED.ips_queried,
            ips_with_data = EXCLUDED.ips_with_data,
            domains_found = EXCLUDED.domains_found,
            domains_with_icp = EXCLUDED.domains_with_icp,
            icp_api_supplement = EXCLUDED.icp_api_supplement
    """, (
        str(uuid.uuid4()), task_id, template_id,
        data.get("ips_queried", 0),
        data.get("ips_with_data", 0),
        data.get("domains_found", 0),
        data.get("domains_with_icp", 0),
        data.get("icp_api_supplement", 0),
    ))
    return _ok(cursor.rowcount)


# === scan_logs ===

def insert_scan_log(cursor, task_id: str, step: int, level: str, message: str) -> bool:
    """写入一条扫描日志。"""
    if cursor is None:
        return False
    cursor.execute("""
        INSERT INTO scan_logs (task_id, step, level, message)
        VALUES (%s, %s, %s, %s)
    """, (task_id, step, level, message))
    return _ok(cursor.rowcount)


def get_scan_logs(cursor, task_id: str, limit: int = 100, offset: int = 0) -> list[dict]:
    """查询扫描日志（最新在前）。"""
    if cursor is None:
        return []
    cursor.execute("""
        SELECT id, task_id, step, level, message, created_at
        FROM scan_logs WHERE task_id = %s
        ORDER BY created_at DESC
        LIMIT %s OFFSET %s
    """, (task_id, limit, offset))
    return [dict(zip(
        ("id", "task_id", "step", "level", "message", "created_at"), row
    )) for row in cursor.fetchall()]


def get_scan_logs_since(cursor, task_id: str, since_id: int = 0) -> list[dict]:
    """查询指定 ID 之后的新日志（用于增量轮询）。"""
    if cursor is None:
        return []
    cursor.execute("""
        SELECT id, task_id, step, level, message, created_at
        FROM scan_logs WHERE task_id = %s AND id > %s
        ORDER BY created_at
        LIMIT 200
    """, (task_id, since_id))
    return [dict(zip(
        ("id", "task_id", "step", "level", "message", "created_at"), row
    )) for row in cursor.fetchall()]


def update_task_current_step(cursor, task_id: str, step: int) -> bool:
    """更新扫描任务的当前步骤。"""
    if cursor is None:
        return False
    cursor.execute("""
        UPDATE scan_tasks SET current_step = %s WHERE task_id = %s
    """, (step, task_id))
    return _ok(cursor.rowcount)


def delete_scan_logs(cursor, task_id: str) -> int:
    """删除指定任务的所有扫描日志，返回删除条数。"""
    if cursor is None:
        return 0
    cursor.execute("DELETE FROM scan_logs WHERE task_id = %s", (task_id,))
    return cursor.rowcount


def delete_scan_task(cursor, task_id: str) -> dict:
    """级联删除扫描任务及其所有关联数据。返回各表删除条数。"""
    if cursor is None:
        return {}
    stats = {}

    cursor.execute("DELETE FROM scan_logs WHERE task_id = %s", (task_id,))
    stats["scan_logs"] = cursor.rowcount

    cursor.execute("DELETE FROM discovered_assets WHERE task_id = %s", (task_id,))
    stats["discovered_assets"] = cursor.rowcount

    cursor.execute("DELETE FROM scan_results WHERE task_id = %s", (task_id,))
    stats["scan_results"] = cursor.rowcount

    cursor.execute("DELETE FROM host_results WHERE task_id = %s", (task_id,))
    stats["host_results"] = cursor.rowcount

    cursor.execute("DELETE FROM icp_results WHERE task_id = %s", (task_id,))
    stats["icp_results"] = cursor.rowcount

    cursor.execute("DELETE FROM template_scan_coverage WHERE task_id = %s", (task_id,))
    stats["template_scan_coverage"] = cursor.rowcount

    cursor.execute("DELETE FROM template_icp_stats WHERE task_id = %s", (task_id,))
    stats["template_icp_stats"] = cursor.rowcount

    cursor.execute("DELETE FROM checkpoint_snapshots WHERE task_id = %s", (task_id,))
    stats["checkpoint_snapshots"] = cursor.rowcount

    cursor.execute("DELETE FROM scan_tasks WHERE task_id = %s", (task_id,))
    stats["scan_tasks"] = cursor.rowcount

    return stats


# === materialized views ===

def refresh_materialized_views(cursor) -> None:
    """刷新所有物化视图。"""
    if cursor is None:
        return
    for mv in ("mv_task_summary", "mv_template_effectiveness", "mv_cross_template_urls"):
        cursor.execute(f"REFRESH MATERIALIZED VIEW {mv}")


# === host_results ===

def get_db_stats(cursor) -> dict:
    """获取数据库统计概览。"""
    if cursor is None:
        return {}
    stats = {"schema_version": 0}

    cursor.execute("SELECT COALESCE(MAX(version), 0) FROM schema_version")
    stats["schema_version"] = cursor.fetchone()[0]

    for label, table in [
        ("template_count", "poc_templates"),
        ("task_count", "scan_tasks"),
        ("asset_count", "discovered_assets"),
        ("vuln_count", "scan_results"),
        ("host_count", "host_results"),
        ("icp_count", "icp_results"),
    ]:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        stats[label] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM query_cache")
    stats["cache_count"] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM query_cache WHERE expires_at > NOW()")
    stats["active_cache_count"] = cursor.fetchone()[0]

    # 漏洞按严重级别分布
    cursor.execute("""
        SELECT severity, COUNT(*) FROM scan_results
        WHERE severity IS NOT NULL GROUP BY severity ORDER BY COUNT(*) DESC
    """)
    stats["severity_dist"] = dict(cursor.fetchall())

    # 最近任务
    cursor.execute("""
        SELECT task_id, task_type, engine, status, step2_vulns, started_at
        FROM scan_tasks ORDER BY started_at DESC LIMIT 5
    """)
    stats["recent_tasks"] = [dict(zip(
        ("task_id", "task_type", "engine", "status", "vulns", "started_at"), row
    )) for row in cursor.fetchall()]

    return stats

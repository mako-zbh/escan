import threading

from flask import Blueprint, jsonify, request

from ..config import POC_DIR
from ..database.connection import get_cursor
from ..database.dao import get_db_stats
from ..logging_config import get_logger

api = Blueprint("api", __name__, url_prefix="/api")

logger = get_logger("web.routes")

# 后台运行的扫描任务列表
_scan_threads: dict[str, threading.Thread] = {}
_scan_stop_events: dict[str, threading.Event] = {}


def _serialize(obj):
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(v) for v in obj]
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return obj


def _rows_to_dicts(cursor, columns):
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


@api.route("/health")
def health():
    return jsonify({"status": "ok"})


@api.route("/stats")
def stats():
    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503
        return jsonify(_serialize(get_db_stats(cur)))


@api.route("/severity")
def severity():
    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503
        cur.execute("""
            SELECT severity, COUNT(*) FROM scan_results
            WHERE severity IS NOT NULL GROUP BY severity ORDER BY COUNT(*) DESC
        """)
        return jsonify(dict(cur.fetchall()))


@api.route("/templates")
def templates():
    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)
    severity_filter = request.args.get("severity", "")
    search = request.args.get("search", "")
    has_icp = request.args.get("has_icp", "")

    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503

        inner_where = []
        outer_where = []
        params = []

        if severity_filter:
            inner_where.append("pt.severity = %s")
            params.append(severity_filter)

        if search:
            inner_where.append("pt.name ILIKE %s")
            params.append(f"%{search}%")

        if has_icp == "1":
            outer_where.append("icp_count > 0")
        elif has_icp == "0":
            outer_where.append("icp_count = 0")

        inner_clause = "WHERE " + " AND ".join(inner_where) if inner_where else ""
        outer_clause = "WHERE " + " AND ".join(outer_where) if outer_where else ""

        cur.execute(f"""
            WITH template_stats AS (
                SELECT pt.template_id, pt.name, pt.severity, pt.fofa_query, pt.file_path,
                       pt.created_at, pt.updated_at,
                       COALESCE(tc.total_assets, 0) AS asset_count,
                       COALESCE(tc.total_hits, 0) AS hit_count,
                       COALESCE(tc.domain_count, 0) AS domain_count,
                       COALESCE(tc.icp_count, 0) AS icp_count
                FROM poc_templates pt
                LEFT JOIN (
                    SELECT tsc.template_id,
                           SUM(tsc.asset_count) AS total_assets,
                           SUM(tsc.hits_found) AS total_hits,
                           SUM(tsc.hosts_extracted) AS domain_count,
                           COUNT(DISTINCT ir.icp_result_id) AS icp_count
                    FROM template_scan_coverage tsc
                    LEFT JOIN host_results hr
                        ON hr.template_id = tsc.template_id AND hr.task_id = tsc.task_id
                    LEFT JOIN icp_results ir
                        ON ir.task_id = tsc.task_id
                        AND (hr.host = ir.ip_address OR hr.host = ir.domain)
                    GROUP BY tsc.template_id
                ) tc ON tc.template_id = pt.template_id
                {inner_clause}
            )
            SELECT * FROM template_stats
            {outer_clause}
            ORDER BY asset_count DESC
            LIMIT %s OFFSET %s
        """, params + [limit, offset])

        columns = ("template_id", "name", "severity", "fofa_query", "file_path",
                   "created_at", "updated_at",
                   "asset_count", "hit_count", "domain_count", "icp_count")
        items = _serialize(_rows_to_dicts(cur, columns))

        cur.execute(f"""
            WITH template_stats AS (
                SELECT pt.template_id,
                       COALESCE(tc.icp_count, 0) AS icp_count
                FROM poc_templates pt
                LEFT JOIN (
                    SELECT tsc.template_id,
                           COUNT(DISTINCT ir.icp_result_id) AS icp_count
                    FROM template_scan_coverage tsc
                    LEFT JOIN host_results hr
                        ON hr.template_id = tsc.template_id AND hr.task_id = tsc.task_id
                    LEFT JOIN icp_results ir
                        ON ir.task_id = tsc.task_id
                        AND (hr.host = ir.ip_address OR hr.host = ir.domain)
                    GROUP BY tsc.template_id
                ) tc ON tc.template_id = pt.template_id
                {inner_clause}
            )
            SELECT COUNT(*) FROM template_stats {outer_clause}
        """, params)
        total = cur.fetchone()[0]

        return jsonify({"items": items, "total": total, "limit": limit, "offset": offset})


@api.route("/templates/<template_id>")
def template_detail(template_id):
    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503

        cur.execute("""
            SELECT template_id, name, severity, tags, fofa_query, file_path,
                   api_truncated, created_at, updated_at
            FROM poc_templates WHERE template_id = %s
        """, (template_id,))
        t_columns = ("template_id", "name", "severity", "tags", "fofa_query",
                     "file_path", "api_truncated", "created_at", "updated_at")
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "template not found"}), 404

        template = dict(zip(t_columns, row))

        # per-task coverage stats
        cur.execute("""
            SELECT tsc.task_id, tsc.has_assets, tsc.asset_count,
                   tsc.was_scanned, tsc.hits_found, tsc.hosts_extracted,
                   tsc.icp_queried,
                   st.status, st.started_at, st.completed_at
            FROM template_scan_coverage tsc
            JOIN scan_tasks st ON st.task_id = tsc.task_id
            WHERE tsc.template_id = %s
            ORDER BY st.started_at DESC
        """, (template_id,))
        c_columns = ("task_id", "has_assets", "asset_count", "was_scanned",
                     "hits_found", "hosts_extracted", "icp_queried",
                     "status", "started_at", "completed_at")
        template["tasks"] = _serialize(_rows_to_dicts(cur, c_columns))

        # aggregate ICP stats — 优先使用 icp_results.template_id 直接关联
        cur.execute("""
            SELECT COUNT(DISTINCT ir.ip_address) FILTER (WHERE ir.ip_address ~ '^\\d+\\.\\d+\\.\\d+\\.\\d+$'),
                   COUNT(DISTINCT ir.icp_result_id),
                   COUNT(DISTINCT ir.domain) FILTER (WHERE ir.domain IS NOT NULL),
                   COUNT(DISTINCT ir.icp_result_id) FILTER (WHERE ir.icp_number IS NOT NULL OR ir.icp_api IS NOT NULL),
                   COUNT(DISTINCT ir.icp_result_id) FILTER (WHERE ir.icp_api IS NOT NULL)
            FROM icp_results ir
            WHERE ir.template_id = %s
        """, (template_id,))
        row = cur.fetchone()
        template["icp_summary"] = {
            "ips_queried": row[0] or 0,
            "ips_with_data": row[1] or 0,
            "domains_found": row[2] or 0,
            "domains_with_icp": row[3] or 0,
            "icp_api_supplement": row[4] or 0,
        } if row else {}

        return jsonify(_serialize(template))


@api.route("/templates/<template_id>/urls")
def template_urls(template_id):
    task_id = request.args.get("task_id", "")
    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503

        if task_id:
            cur.execute("""
                SELECT da.asset_id, da.task_id, da.url, da.host, da.port, da.scheme,
                       da.title, da.engine, da.discovered_at,
                       ir.icp_number, ir.icp_api ->> 'company_name' AS icp_company,
                       ir.domain AS icp_domain
                FROM discovered_assets da
                LEFT JOIN icp_results ir
                    ON ir.asset_id = da.asset_id
                WHERE da.template_id = %s AND da.task_id = %s
                ORDER BY da.discovered_at DESC
            """, (template_id, task_id))
        else:
            cur.execute("""
                SELECT da.asset_id, da.task_id, da.url, da.host, da.port, da.scheme,
                       da.title, da.engine, da.discovered_at,
                       ir.icp_number, ir.icp_api ->> 'company_name' AS icp_company,
                       ir.domain AS icp_domain
                FROM discovered_assets da
                LEFT JOIN icp_results ir
                    ON ir.asset_id = da.asset_id
                WHERE da.template_id = %s
                ORDER BY da.discovered_at DESC
            """, (template_id,))

        columns = ("asset_id", "task_id", "url", "host", "port", "scheme", "title", "engine",
                   "discovered_at", "icp_number", "icp_company", "icp_domain")
        return jsonify(_serialize(_rows_to_dicts(cur, columns)))


@api.route("/templates/<template_id>/domains")
def template_domains(template_id):
    task_id = request.args.get("task_id", "")
    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503

        if task_id:
            cur.execute("""
                SELECT host_result_id, task_id, template_name, host, is_ip, extracted_at
                FROM host_results
                WHERE template_id = %s AND task_id = %s
                ORDER BY host
            """, (template_id, task_id))
        else:
            cur.execute("""
                SELECT host_result_id, task_id, template_name, host, is_ip, extracted_at
                FROM host_results
                WHERE template_id = %s
                ORDER BY host
            """, (template_id,))

        columns = ("host_result_id", "task_id", "template_name", "host", "is_ip", "extracted_at")
        return jsonify(_serialize(_rows_to_dicts(cur, columns)))


@api.route("/templates/<template_id>/icp")
def template_icp(template_id):
    task_id = request.args.get("task_id", "")
    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503

        if task_id:
            cur.execute("""
                SELECT DISTINCT ir.icp_result_id, ir.task_id, ir.ip_address, ir.domain,
                       ir.icp_number, ir.source,
                       ir.icp_api ->> 'company_name' AS company,
                       ir.queried_at, ir.asset_id
                FROM icp_results ir
                WHERE ir.template_id = %s AND ir.task_id = %s
                ORDER BY ir.domain
            """, (template_id, task_id))
        else:
            cur.execute("""
                SELECT DISTINCT ir.icp_result_id, ir.task_id, ir.ip_address, ir.domain,
                       ir.icp_number, ir.source,
                       ir.icp_api ->> 'company_name' AS company,
                       ir.queried_at, ir.asset_id
                FROM icp_results ir
                WHERE ir.template_id = %s
                ORDER BY ir.domain
            """, (template_id,))

        columns = ("icp_result_id", "task_id", "ip_address", "domain",
                   "icp_number", "source", "company", "queried_at", "asset_id")
        return jsonify(_serialize(_rows_to_dicts(cur, columns)))


@api.route("/templates/<template_id>/vulns")
def template_vulns(template_id):
    task_id = request.args.get("task_id", "")
    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503

        if task_id:
            cur.execute("""
                SELECT result_id, task_id, protocol, severity, matched_url, raw_line, scanned_at
                FROM scan_results
                WHERE template_id = %s AND task_id = %s
                ORDER BY scanned_at DESC
            """, (template_id, task_id))
        else:
            cur.execute("""
                SELECT result_id, task_id, protocol, severity, matched_url, raw_line, scanned_at
                FROM scan_results
                WHERE template_id = %s
                ORDER BY scanned_at DESC
            """, (template_id,))

        columns = ("result_id", "task_id", "protocol", "severity", "matched_url", "raw_line", "scanned_at")
        return jsonify(_serialize(_rows_to_dicts(cur, columns)))


@api.route("/tasks")
def tasks():
    limit = request.args.get("limit", 20, type=int)
    offset = request.args.get("offset", 0, type=int)
    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503
        cur.execute("""
            SELECT task_id, task_type, engine, status, current_step,
                   step1_assets, step2_vulns, step3_hosts, step4_icp,
                   output_dir, error_message, started_at, completed_at
            FROM scan_tasks ORDER BY started_at DESC LIMIT %s OFFSET %s
        """, (limit, offset))
        columns = ("task_id", "task_type", "engine", "status", "current_step",
                   "step1_assets", "step2_vulns", "step3_hosts", "step4_icp",
                   "output_dir", "error_message", "started_at", "completed_at")
        return jsonify(_serialize(_rows_to_dicts(cur, columns)))


def _sync_output_dir_from_checkpoint(cur, task_id: str):
    """从断点快照回写 output_dir（停止/异常时补全 DB 记录）。"""
    from pathlib import Path as _P
    cur.execute(
        "SELECT state->>'output_dir' FROM checkpoint_snapshots WHERE task_id = %s",
        (task_id,),
    )
    row = cur.fetchone()
    if row and row[0] and _P(row[0]).is_dir():
        cur.execute(
            "UPDATE scan_tasks SET output_dir = %s WHERE task_id = %s",
            (row[0], task_id),
        )


def _run_scan_bg(task_id: str, scan_type: str, poc: str, engine: str,
                  resume_dir: str | None = None, region: str = ""):
    """后台线程执行扫描，完成后通过 DB 状态通知前端。"""
    from pathlib import Path as _Path
    from .log_handler import DBLogHandler
    import logging

    stop_event = threading.Event()
    _scan_stop_events[task_id] = stop_event

    # 安装 DB 日志处理器，将 pipeline 日志实时写入 scan_logs
    db_handler = DBLogHandler(task_id, level=logging.INFO)
    pipeline_logger = logging.getLogger("vulnscan.pipeline")
    orche_logger = logging.getLogger("vulnscan.pipeline.orchestrator")
    pipeline_logger.addHandler(db_handler)
    orche_logger.addHandler(db_handler)

    from ..database.connection import get_cursor as _get_cursor
    from ..database.dao import complete_scan_task, insert_scan_log

    rf_dir = _Path(resume_dir) if resume_dir else None

    try:
        if scan_type == "categorized-incremental":
            from ..pipeline.orchestrator import run_categorized_incremental
            results = run_categorized_incremental(poc, engine,
                                                   resume_from_dir=rf_dir,
                                                   task_id=task_id,
                                                   stop_event=stop_event,
                                                   region=region)
        else:
            from ..pipeline.orchestrator import run_categorized
            results = run_categorized(poc, engine,
                                       resume_from_dir=rf_dir,
                                       task_id=task_id,
                                       stop_event=stop_event,
                                       region=region)

        step4_count = results.get("step4", 0)
        real_output_dir = results.get("output_dir", "")
        with _get_cursor() as cur:
            if cur is not None:
                # 回写真实输出目录（创建任务时用了占位字符串）
                if real_output_dir:
                    cur.execute(
                        "UPDATE scan_tasks SET output_dir = %s WHERE task_id = %s",
                        (real_output_dir, task_id),
                    )
                complete_scan_task(cur, task_id, "completed", {
                    "step1": results.get("step1", 0),
                    "step2": results.get("step2", 0),
                    "step3": results.get("step3", 0),
                    "step4": step4_count,
                })
                insert_scan_log(cur, task_id, None, "INFO", "扫描完成")

        logger.info("后台扫描完成: %s [%s]", task_id, scan_type)
    except Exception as e:
        from ..pipeline.orchestrator import StopScanException
        if isinstance(e, StopScanException):
            logger.info("后台扫描已停止: %s", task_id)
            with _get_cursor() as cur:
                if cur is not None:
                    _sync_output_dir_from_checkpoint(cur, task_id)
                    insert_scan_log(cur, task_id, None, "WARNING", "扫描被用户停止")
        else:
            logger.error("后台扫描失败: %s %s", task_id, str(e))
            with _get_cursor() as cur:
                if cur is not None:
                    complete_scan_task(cur, task_id, "failed", {}, str(e))
                    insert_scan_log(cur, task_id, None, "ERROR", f"扫描失败: {e}")
    finally:
        pipeline_logger.removeHandler(db_handler)
        orche_logger.removeHandler(db_handler)
        _scan_stop_events.pop(task_id, None)
        _scan_threads.pop(task_id, None)


@api.route("/scans", methods=["POST"])
def trigger_scan():
    """触发一次扫描任务（后台执行）。"""
    body = request.get_json(silent=True) or {}
    scan_type = body.get("type", "categorized")
    poc = body.get("poc") or POC_DIR
    engine = body.get("engine", "fofa")
    region = (body.get("region") or "").strip()

    if scan_type not in ("categorized", "categorized-incremental"):
        return jsonify({"error": "无效的扫描类型"}), 400
    if engine not in ("fofa", "hunter"):
        return jsonify({"error": "无效的搜索引擎"}), 400

    import os
    if not os.path.isdir(poc):
        return jsonify({"error": f"POC 目录不存在: {poc}"}), 400

    from ..database.connection import get_cursor
    from ..database.dao import create_scan_task

    task_id = None
    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503
        task_id = create_scan_task(
            cur, scan_type, engine,
            "web-triggered",
        )

    if task_id:
        t = threading.Thread(
            target=_run_scan_bg,
            args=(task_id, scan_type, poc, engine, None, region),
            daemon=True,
        )
        _scan_threads[task_id] = t
        t.start()
        logger.info("启动后台扫描: %s type=%s poc=%s engine=%s region=%s", task_id, scan_type, poc, engine, region)

    return jsonify({"task_id": task_id, "status": "started"})


@api.route("/scans/<task_id>")
def scan_status(task_id):
    """查询扫描任务状态。"""
    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503
        cur.execute("""
            SELECT task_id, task_type, engine, status, current_step,
                   step1_assets, step2_vulns, step3_hosts, step4_icp,
                   output_dir, error_message, started_at, completed_at
            FROM scan_tasks WHERE task_id = %s
        """, (task_id,))
        columns = ("task_id", "task_type", "engine", "status", "current_step",
                   "step1_assets", "step2_vulns", "step3_hosts", "step4_icp",
                   "output_dir", "error_message", "started_at", "completed_at")
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "task not found"}), 404
        return jsonify(_serialize(dict(zip(columns, row))))


@api.route("/scans/<task_id>/logs")
def scan_logs(task_id):
    """查询扫描日志。支持 since_id 增量轮询。"""
    from ..database.dao import get_scan_logs, get_scan_logs_since

    since = request.args.get("since", 0, type=int)
    limit = request.args.get("limit", 200, type=int)
    offset = request.args.get("offset", 0, type=int)

    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503

        if since > 0:
            logs = get_scan_logs_since(cur, task_id, since)
        else:
            logs = get_scan_logs(cur, task_id, limit, offset)

        return jsonify(_serialize(logs))


@api.route("/scans/<task_id>/stop", methods=["POST"])
def stop_scan(task_id):
    """停止正在运行的扫描任务。"""
    stop_event = _scan_stop_events.get(task_id)

    # 情况 1：正常停止（stop_event 存在）
    if stop_event is not None:
        stop_event.set()

    # 情况 2：stop_event 不存在（服务重启导致内存丢失），允许强制标记停止
    with get_cursor() as cur:
        if cur is not None:
            cur.execute(
                "SELECT status FROM scan_tasks WHERE task_id = %s",
                (task_id,),
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "task not found"}), 404

            current_status = row[0]
            if current_status not in ("running", "started"):
                return jsonify({"error": f"任务状态为 {current_status}，无法停止"}), 400

            # 写入日志记录强制停止
            from ..database.dao import insert_scan_log
            if stop_event is None:
                insert_scan_log(cur, task_id, None, "WARNING",
                                "强制停止：服务可能重启导致线程丢失")
            cur.execute(
                "UPDATE scan_tasks SET status = 'stopped', completed_at = NOW() WHERE task_id = %s",
                (task_id,),
            )

    logger.info("停止扫描: %s (stop_event=%s)", task_id, stop_event is not None)
    return jsonify({"task_id": task_id, "status": "stopped"})


@api.route("/scans/<task_id>/resume", methods=["POST"])
def resume_scan(task_id):
    """继续已停止的扫描任务。"""
    from pathlib import Path

    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503
        cur.execute(
            "SELECT task_type, engine, status, output_dir FROM scan_tasks WHERE task_id = %s",
            (task_id,),
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "task not found"}), 404

        scan_type, engine, status, output_dir = row

        if status != "stopped":
            return jsonify({"error": f"任务状态为 {status}，只能继续已停止的任务"}), 400

        if not output_dir or not Path(output_dir).is_dir():
            return jsonify({"error": f"输出目录不存在: {output_dir}"}), 400

        # 重置为 running，保留已有计数
        cur.execute(
            "UPDATE scan_tasks SET status = 'running', error_message = NULL, completed_at = NULL WHERE task_id = %s",
            (task_id,),
        )

    resume_dir = Path(output_dir)

    # 推断 POC 路径（优先取 checkpoint，回退到默认）
    from ..pipeline.checkpoint import load_checkpoint_file
    cp = load_checkpoint_file(resume_dir)
    poc = (cp or {}).get("poc_path", POC_DIR) if cp else POC_DIR

    t = threading.Thread(
        target=_run_scan_bg,
        args=(task_id, scan_type, poc, engine, output_dir),
        daemon=True,
    )
    _scan_threads[task_id] = t
    t.start()
    logger.info("恢复扫描: %s type=%s engine=%s dir=%s", task_id, scan_type, engine, output_dir)

    return jsonify({"task_id": task_id, "status": "running"})


@api.route("/scans/<task_id>/logs", methods=["DELETE"])
def delete_scan_logs(task_id):
    """删除指定任务的扫描日志。"""
    from ..database.dao import delete_scan_logs as dao_delete_logs

    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503

        count = dao_delete_logs(cur, task_id)
        logger.info("删除扫描日志: %s (%d 条)", task_id, count)
        return jsonify({"task_id": task_id, "deleted": count})


@api.route("/scans/<task_id>", methods=["DELETE"])
def delete_scan_task(task_id):
    """删除扫描任务及其所有关联数据（日志、资产、扫描结果、ICP 等）。"""
    # 如果任务正在运行，先停止
    if task_id in _scan_threads:
        stop_event = _scan_stop_events.get(task_id)
        if stop_event:
            stop_event.set()
        _scan_threads.pop(task_id, None)
        _scan_stop_events.pop(task_id, None)

    from ..database.dao import delete_scan_task as dao_delete_task

    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503

        stats = dao_delete_task(cur, task_id)
        logger.info("删除扫描任务: %s %s", task_id, stats)
        return jsonify({"task_id": task_id, "deleted": stats})


# === MIIT ICP 备案直接查询 ===

@api.route("/icp/query", methods=["POST"])
def icp_query():
    """使用 MIIT 官方 API 查询 ICP 备案信息。"""
    body = request.get_json(silent=True) or {}
    search = (body.get("search") or "").strip()
    if not search:
        return jsonify({"error": "请提供查询关键词（域名/单位名称）"}), 400

    try:
        from ..pipeline.miit_icp import query_icp_single
        result = query_icp_single(search)
        if result.get("code") == 200:
            items = result.get("params", {}).get("list", [])
            total = result.get("params", {}).get("total", 0)
            return jsonify({"items": _serialize(items), "total": total, "search": search})
        else:
            return jsonify({"error": result.get("message", "查询失败"), "items": [], "total": 0})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# === 漏洞综合视图（跨模板） ===

@api.route("/vulnerabilities")
def vulnerabilities():
    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)
    severity_filter = request.args.get("severity", "")
    search = request.args.get("search", "")
    has_icp = request.args.get("has_icp", "")

    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503

        where = []
        params = []

        if severity_filter:
            where.append("sr.severity = %s")
            params.append(severity_filter)

        if search:
            where.append("(pt.name ILIKE %s OR sr.matched_url ILIKE %s)")
            params.extend([f"%{search}%", f"%{search}%"])

        _host_expr = "(regexp_match(sr.matched_url, '^https?://([^/:]+)'))[1]"

        # ICP 过滤：host 级别精确匹配
        if has_icp == "1":
            where.append(f"""EXISTS (
                SELECT 1 FROM host_results hr3
                JOIN icp_results ir3 ON ir3.task_id = hr3.task_id
                    AND (ir3.ip_address = hr3.host OR ir3.domain = hr3.host)
                WHERE hr3.template_id = sr.template_id
                  AND hr3.task_id = sr.task_id
                  AND hr3.host = {_host_expr}
                  AND (ir3.icp_number IS NOT NULL OR ir3.icp_api IS NOT NULL)
            )""")
        elif has_icp == "0":
            where.append(f"""NOT EXISTS (
                SELECT 1 FROM host_results hr3
                JOIN icp_results ir3 ON ir3.task_id = hr3.task_id
                    AND (ir3.ip_address = hr3.host OR ir3.domain = hr3.host)
                WHERE hr3.template_id = sr.template_id
                  AND hr3.task_id = sr.task_id
                  AND hr3.host = {_host_expr}
                  AND (ir3.icp_number IS NOT NULL OR ir3.icp_api IS NOT NULL)
            )""")

        where_clause = "WHERE " + " AND ".join(where) if where else ""

        # 统计总数
        cur.execute(f"""
            SELECT COUNT(*)
            FROM scan_results sr
            JOIN poc_templates pt ON pt.template_id = sr.template_id
            {where_clause}
        """, params)
        total = cur.fetchone()[0]

        cur.execute(f"""
            SELECT pt.name AS vuln_name,
                   sr.severity,
                   sr.matched_url AS asset,
                   sr.scanned_at,
                   ir.icp_domain,
                   ir.icp_number,
                   ir.icp_company
            FROM scan_results sr
            JOIN poc_templates pt ON pt.template_id = sr.template_id
            LEFT JOIN LATERAL (
                SELECT ir2.domain AS icp_domain,
                       ir2.icp_number,
                       ir2.icp_api ->> 'company_name' AS icp_company
                FROM host_results hr
                JOIN icp_results ir2
                    ON ir2.task_id = hr.task_id
                    AND (ir2.ip_address = hr.host OR ir2.domain = hr.host)
                WHERE hr.template_id = sr.template_id
                  AND hr.task_id = sr.task_id
                  AND hr.host = (regexp_match(sr.matched_url, '^https?://([^/:]+)'))[1]
                  AND (ir2.icp_number IS NOT NULL OR ir2.icp_api IS NOT NULL)
                LIMIT 1
            ) ir ON true
            {where_clause}
            ORDER BY sr.scanned_at DESC
            LIMIT %s OFFSET %s
        """, params + [limit, offset])

        columns = ("vuln_name", "severity", "asset", "scanned_at",
                   "icp_domain", "icp_number", "icp_company")
        items = _serialize(_rows_to_dicts(cur, columns))

        return jsonify({"items": items, "total": total, "limit": limit, "offset": offset})


@api.route("/vulnerabilities/export")
def vulnerabilities_export():
    """导出漏洞综合数据为 CSV。"""
    import csv
    import io
    from flask import Response

    severity_filter = request.args.get("severity", "")
    search = request.args.get("search", "")
    has_icp = request.args.get("has_icp", "")

    with get_cursor() as cur:
        if cur is None:
            return jsonify({"error": "database not available"}), 503

        where = []
        params = []

        if severity_filter:
            where.append("sr.severity = %s")
            params.append(severity_filter)

        if search:
            where.append("(pt.name ILIKE %s OR sr.matched_url ILIKE %s)")
            params.extend([f"%{search}%", f"%{search}%"])

        _host_expr = "(regexp_match(sr.matched_url, '^https?://([^/:]+)'))[1]"

        if has_icp == "1":
            where.append(f"""EXISTS (
                SELECT 1 FROM host_results hr2
                JOIN icp_results ir3 ON ir3.task_id = hr2.task_id
                    AND (ir3.ip_address = hr2.host OR ir3.domain = hr2.host)
                WHERE hr2.template_id = sr.template_id
                  AND hr2.task_id = sr.task_id
                  AND hr2.host = {_host_expr}
                  AND (ir3.icp_number IS NOT NULL OR ir3.icp_api IS NOT NULL)
            )""")
        elif has_icp == "0":
            where.append(f"""NOT EXISTS (
                SELECT 1 FROM host_results hr2
                JOIN icp_results ir3 ON ir3.task_id = hr2.task_id
                    AND (ir3.ip_address = hr2.host OR ir3.domain = hr2.host)
                WHERE hr2.template_id = sr.template_id
                  AND hr2.task_id = sr.task_id
                  AND hr2.host = {_host_expr}
                  AND (ir3.icp_number IS NOT NULL OR ir3.icp_api IS NOT NULL)
            )""")

        where_clause1 = "WHERE " + " AND ".join(where) if where else ""

        where_clause = "WHERE " + " AND ".join(where) if where else ""

        cur.execute(f"""
            SELECT pt.name AS vuln_name,
                   sr.severity,
                   sr.matched_url AS asset,
                   sr.scanned_at,
                   ir.icp_domain,
                   ir.icp_number,
                   ir.icp_company
            FROM scan_results sr
            JOIN poc_templates pt ON pt.template_id = sr.template_id
            LEFT JOIN LATERAL (
                SELECT ir2.domain AS icp_domain,
                       ir2.icp_number,
                       ir2.icp_api ->> 'company_name' AS icp_company
                FROM host_results hr
                JOIN icp_results ir2
                    ON ir2.task_id = hr.task_id
                    AND (ir2.ip_address = hr.host OR ir2.domain = hr.host)
                WHERE hr.template_id = sr.template_id
                  AND hr.task_id = sr.task_id
                  AND hr.host = (regexp_match(sr.matched_url, '^https?://([^/:]+)'))[1]
                  AND (ir2.icp_number IS NOT NULL OR ir2.icp_api IS NOT NULL)
                LIMIT 1
            ) ir ON true
            {where_clause}
            ORDER BY sr.scanned_at DESC
        """, params)

        columns = ("vuln_name", "severity", "asset", "scanned_at",
                   "icp_domain", "icp_number", "icp_company")
        rows = _rows_to_dicts(cur, columns)

    # 生成 CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["漏洞名称", "严重度", "资产URL", "域名", "ICP备案号", "备案主体", "扫描时间"])
    for row in rows:
        writer.writerow([
            row.get("vuln_name", ""),
            row.get("severity", ""),
            row.get("asset", ""),
            row.get("icp_domain", ""),
            row.get("icp_number", ""),
            row.get("icp_company", ""),
            row.get("scanned_at", ""),
        ])

    csv_content = output.getvalue()
    output.close()

    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities.csv"},
    )


# === 配置文件管理 ===

import os as _os
from pathlib import Path as _Path

_CONFIG_FILE = str(_Path(__file__).resolve().parent.parent.parent / ".env")


@api.route("/config")
def get_config():
    """读取 .env 配置文件内容。"""
    try:
        if _os.path.isfile(_CONFIG_FILE):
            with open(_CONFIG_FILE, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            content = ""
        return jsonify({"path": _CONFIG_FILE, "content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api.route("/config", methods=["PUT"])
def update_config():
    """更新 .env 配置文件内容。"""
    body = request.get_json(silent=True) or {}
    content = body.get("content", "")
    if not isinstance(content, str):
        return jsonify({"error": "content 必须是字符串"}), 400

    try:
        # 备份旧文件（如果存在）
        backup_path = _CONFIG_FILE + ".bak"
        if _os.path.isfile(_CONFIG_FILE):
            import shutil
            shutil.copy2(_CONFIG_FILE, backup_path)

        with open(_CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write(content)

        # 重新加载环境变量
        from ..config import _load_dotenv
        _load_dotenv()

        logger.info("配置文件已更新: %s", _CONFIG_FILE)
        return jsonify({"path": _CONFIG_FILE, "saved": True, "backup": backup_path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

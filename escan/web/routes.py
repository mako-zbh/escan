"""eScan REST API — FastAPI 路由（迁移自 Flask Blueprint）。

所有端点前缀: /api
SSE 流端点: /api/scans/{task_id}/stream, /api/scans/{task_id}/logs/stream
"""

from __future__ import annotations

import csv
import io
import os
import threading
import time
from pathlib import Path as FsPath

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from fastapi.responses import Response, StreamingResponse

from ..config import POC_DIR
from ..database.connection import get_cursor
from ..database.dao import (
    get_db_stats,
    create_scan_task,
    complete_scan_task,
    update_task_current_step,
    insert_scan_log,
    get_scan_logs,
    get_scan_logs_since,
    delete_scan_logs as dao_delete_logs,
    delete_scan_task as dao_delete_task,
    upsert_poc_template,
)
from ..logging_config import get_logger
from ..utils.network import is_ipv4

from .models import (
    ScanTriggerRequest, ScanTriggerResponse,
    TaskResponse, TaskListResponse,
    StatsResponse,
    TemplateItem, TemplateListResponse, TemplateDetailResponse,
    AssetResponse, HostResponse, ICPResultResponse,
    ICPQueryRequest, ICPQueryResponse,
    VulnerabilityItem, VulnerabilityListResponse,
    VulnResultResponse,
    ScanLogResponse,
    ConfigResponse, ConfigUpdateRequest, ConfigUpdateResponse,
    StopScanResponse, DeleteScanResponse, DeleteLogsResponse,
    ProxyStatusResponse, ProxyTestRequest, ProxyTestResponse,
    ProxyBatchTestRequest, ProxyBatchAddRequest, ProxyBatchTestResponse,
    ProxyAddRequest, ProxyRemoveRequest, ProxyToggleRequest,
)

router = APIRouter()
logger = get_logger("web.routes")

# 后台扫描管理
_scan_threads: dict[str, threading.Thread] = {}
_scan_stop_events: dict[str, threading.Event] = {}


# --- 辅助函数 ---

def _rows_to_dicts(rows, columns):
    return [dict(zip(columns, row)) for row in rows]


def _serialize(obj):
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(v) for v in obj]
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return obj


def _sync_output_dir_from_checkpoint(cur, task_id: str):
    """从断点快照回写 output_dir。"""
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


# --- Health ---

@router.get("/health", tags=["System"])
async def health():
    return {"status": "ok"}


# --- Stats ---

@router.get("/stats", response_model=StatsResponse, tags=["System"])
async def stats():
    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")
        return _serialize(get_db_stats(cur))


@router.get("/severity", tags=["System"])
async def severity():
    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")
        cur.execute("""
            SELECT severity, COUNT(*) FROM scan_results
            WHERE severity IS NOT NULL GROUP BY severity ORDER BY COUNT(*) DESC
        """)
        return dict(cur.fetchall())


# --- Templates ---

@router.get("/templates", response_model=TemplateListResponse, tags=["Templates"])
async def list_templates(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    severity: str = Query(default=""),
    search: str = Query(default=""),
    has_icp: str = Query(default=""),
):
    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")

        inner_where = []
        outer_where = []
        params: list = []

        if severity:
            inner_where.append("pt.severity = %s")
            params.append(severity)

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

        return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/templates/{template_id}", response_model=TemplateDetailResponse, tags=["Templates"])
async def template_detail(template_id: str):
    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")

        cur.execute("""
            SELECT template_id, name, severity, tags, fofa_query, file_path,
                   api_truncated, created_at, updated_at
            FROM poc_templates WHERE template_id = %s
        """, (template_id,))
        t_columns = ("template_id", "name", "severity", "tags", "fofa_query",
                     "file_path", "api_truncated", "created_at", "updated_at")
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="template not found")

        template = dict(zip(t_columns, row))

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

        return _serialize(template)


@router.get("/templates/{template_id}/urls", tags=["Templates"])
async def template_urls(template_id: str, task_id: str = Query(default="")):
    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")

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
        return _serialize(_rows_to_dicts(cur, columns))


@router.get("/templates/{template_id}/domains", tags=["Templates"])
async def template_domains(template_id: str, task_id: str = Query(default="")):
    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")

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
        return _serialize(_rows_to_dicts(cur, columns))


@router.get("/templates/{template_id}/icp", tags=["Templates"])
async def template_icp(template_id: str, task_id: str = Query(default="")):
    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")

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
        return _serialize(_rows_to_dicts(cur, columns))


@router.get("/templates/{template_id}/vulns", tags=["Templates"])
async def template_vulns(template_id: str, task_id: str = Query(default="")):
    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")

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
        return _serialize(_rows_to_dicts(cur, columns))


# --- Tasks ---

@router.get("/tasks", response_model=TaskListResponse, tags=["Tasks"])
async def list_tasks(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")
        cur.execute("""
            SELECT task_id, task_type, engine, status, current_step,
                   step1_assets, step2_vulns, step3_hosts, step4_icp,
                   output_dir, error_message, started_at, completed_at
            FROM scan_tasks ORDER BY started_at DESC LIMIT %s OFFSET %s
        """, (limit, offset))
        columns = ("task_id", "task_type", "engine", "status", "current_step",
                   "step1_assets", "step2_vulns", "step3_hosts", "step4_icp",
                   "output_dir", "error_message", "started_at", "completed_at")
        items = _serialize(_rows_to_dicts(cur, columns))

    # count separately for simplicity
    with get_cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM scan_tasks")
        total = cur.fetchone()[0] if cur else 0

    return {"items": items, "total": total}


# --- Scans ---

def _run_scan_bg(task_id: str, scan_type: str, poc: str, engine: str,
                 resume_dir: str | None = None, region: str = "",
                 size: int = 100):
    """后台线程执行扫描。"""
    from pathlib import Path as _Path
    from .sse import sse_manager

    stop_event = threading.Event()
    _scan_stop_events[task_id] = stop_event

    from ..database.connection import get_cursor as _get_cursor
    from ..database.dao import complete_scan_task as dao_complete, insert_scan_log

    rf_dir = _Path(resume_dir) if resume_dir else None

    def _publish_progress(step, message, current=None, total=None):
        """同步发布进度到 SSE（线程安全）。"""
        try:
            sse_manager.publish_sync(task_id, "progress", {
                "step": step, "message": message,
                "current": current, "total": total,
            })
        except Exception:
            pass

    def _publish_log(log_id, step, level, message, created_at):
        """发布日志到 SSE（线程安全）。"""
        try:
            sse_manager.publish_sync(f"{task_id}:logs", "log", {
                "id": log_id, "step": step, "level": level,
                "message": message, "created_at": created_at,
            })
        except Exception:
            pass

    try:
        # 写入启动日志（DB + SSE）
        from ..database.dao import insert_scan_log as _insert_log
        with _get_cursor() as cur:
            if cur is not None:
                _insert_log(cur, task_id, None, "INFO", "扫描已启动")
        _publish_log(None, None, "INFO", "扫描已启动", None)

        if scan_type == "categorized-incremental":
            from ..pipeline.orchestrator import run_categorized_incremental
            results = run_categorized_incremental(poc, engine,
                                                   resume_from_dir=rf_dir,
                                                   task_id=task_id,
                                                   stop_event=stop_event,
                                                   region=region,
                                                   size=size)
        else:
            from ..pipeline.orchestrator import run_categorized
            results = run_categorized(poc, engine,
                                       resume_from_dir=rf_dir,
                                       task_id=task_id,
                                       stop_event=stop_event,
                                       region=region,
                                       size=size)

        step4_count = results.get("step4", 0)
        real_output_dir = results.get("output_dir", "")
        _publish_progress(None, "扫描完成", current=1, total=1)

        with _get_cursor() as cur:
            if cur is not None:
                if real_output_dir:
                    cur.execute(
                        "UPDATE scan_tasks SET output_dir = %s WHERE task_id = %s",
                        (real_output_dir, task_id),
                    )
                dao_complete(cur, task_id, "completed", {
                    "step1": results.get("step1", 0),
                    "step2": results.get("step2", 0),
                    "step3": results.get("step3", 0),
                    "step4": step4_count,
                })
                insert_scan_log(cur, task_id, None, "INFO", "扫描完成")

        sse_manager.close_task_sync(task_id)
        sse_manager.close_task_sync(f"{task_id}:logs")

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
                    dao_complete(cur, task_id, "failed", {}, str(e))
                    insert_scan_log(cur, task_id, None, "ERROR", f"扫描失败: {e}")

        _publish_progress(None, f"扫描失败: {e}")
        sse_manager.close_task_sync(task_id)
        sse_manager.close_task_sync(f"{task_id}:logs")
    finally:
        _scan_stop_events.pop(task_id, None)
        _scan_threads.pop(task_id, None)


@router.post("/scans", response_model=ScanTriggerResponse, status_code=200, tags=["Scans"])
async def trigger_scan(body: ScanTriggerRequest):
    scan_type = body.type
    poc = body.poc or POC_DIR
    engine = body.engine
    region = body.region

    if scan_type not in ("categorized", "categorized-incremental"):
        raise HTTPException(status_code=400, detail="无效的扫描类型")
    if engine not in ("fofa", "hunter"):
        raise HTTPException(status_code=400, detail="无效的搜索引擎")

    if not os.path.isdir(poc):
        raise HTTPException(status_code=400, detail=f"POC 目录不存在: {poc}")

    task_id = None
    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")
        task_id = create_scan_task(cur, scan_type, engine, "web-triggered")

    if task_id:
        t = threading.Thread(
            target=_run_scan_bg,
            args=(task_id, scan_type, poc, engine, None, region),
            daemon=True,
        )
        _scan_threads[task_id] = t
        t.start()
        logger.info("启动后台扫描: %s type=%s poc=%s engine=%s region=%s size=%s",
                    task_id, scan_type, poc, engine, region, body.size)

    return {"task_id": task_id, "status": "started"}


@router.get("/scans/{task_id}", tags=["Scans"])
async def scan_status(task_id: str):
    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")
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
            raise HTTPException(status_code=404, detail="task not found")
        return _serialize(dict(zip(columns, row)))


@router.get("/scans/{task_id}/logs", tags=["Scans"])
async def scan_logs(
    task_id: str,
    since: int = Query(default=0),
    limit: int = Query(default=200, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
):
    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")

        if since > 0:
            logs = get_scan_logs_since(cur, task_id, since)
        else:
            logs = get_scan_logs(cur, task_id, limit, offset)

        return _serialize(logs)


@router.get("/scans/{task_id}/stream", tags=["SSE"])
async def scan_progress_stream(task_id: str):
    """SSE 端点 — 实时推送扫描进度事件。"""
    from .sse import sse_progress_generator
    return StreamingResponse(
        sse_progress_generator(task_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/scans/{task_id}/logs/stream", tags=["SSE"])
async def scan_logs_stream(task_id: str):
    """SSE 端点 — 实时推送扫描日志行。"""
    from .sse import sse_log_generator
    return StreamingResponse(
        sse_log_generator(task_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/scans/{task_id}/stop", tags=["Scans"])
async def stop_scan(task_id: str):
    stop_event = _scan_stop_events.get(task_id)

    if stop_event is not None:
        stop_event.set()

    with get_cursor() as cur:
        if cur is not None:
            cur.execute(
                "SELECT status FROM scan_tasks WHERE task_id = %s",
                (task_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="task not found")

            current_status = row[0]
            if current_status not in ("running", "started"):
                raise HTTPException(status_code=400, detail=f"任务状态为 {current_status}，无法停止")

            if stop_event is None:
                insert_scan_log(cur, task_id, None, "WARNING",
                                "强制停止：服务可能重启导致线程丢失")
            cur.execute(
                "UPDATE scan_tasks SET status = 'stopped', completed_at = NOW() WHERE task_id = %s",
                (task_id,),
            )

    logger.info("停止扫描: %s (stop_event=%s)", task_id, stop_event is not None)
    return {"task_id": task_id, "status": "stopped"}


@router.post("/scans/{task_id}/resume", tags=["Scans"])
async def resume_scan(task_id: str):
    from pathlib import Path

    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")
        cur.execute(
            "SELECT task_type, engine, status, output_dir FROM scan_tasks WHERE task_id = %s",
            (task_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="task not found")

        scan_type, engine, status, output_dir = row

        if status != "stopped":
            raise HTTPException(status_code=400, detail=f"任务状态为 {status}，只能继续已停止的任务")

        if not output_dir or not Path(output_dir).is_dir():
            raise HTTPException(status_code=400, detail=f"输出目录不存在: {output_dir}")

        cur.execute(
            "UPDATE scan_tasks SET status = 'running', error_message = NULL, completed_at = NULL WHERE task_id = %s",
            (task_id,),
        )

    resume_dir = Path(output_dir)

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

    return {"task_id": task_id, "status": "running"}


@router.delete("/scans/{task_id}/logs", tags=["Scans"])
async def delete_scan_logs(task_id: str):
    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")
        count = dao_delete_logs(cur, task_id)
        logger.info("删除扫描日志: %s (%d 条)", task_id, count)
        return {"task_id": task_id, "deleted": count}


@router.delete("/scans/{task_id}", tags=["Scans"])
async def delete_scan_task(task_id: str):
    if task_id in _scan_threads:
        stop_event = _scan_stop_events.get(task_id)
        if stop_event:
            stop_event.set()
        _scan_threads.pop(task_id, None)
        _scan_stop_events.pop(task_id, None)

    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")
        stats = dao_delete_task(cur, task_id)
        logger.info("删除扫描任务: %s %s", task_id, stats)
        return {"task_id": task_id, "deleted": stats}


# --- ICP Query ---

@router.post("/icp/query", tags=["ICP"])
async def icp_query(body: ICPQueryRequest):
    search = body.search.strip()
    if not search:
        raise HTTPException(status_code=400, detail="请提供查询关键词（域名/单位名称）")

    try:
        from ..pipeline.miit_icp import query_icp_single
        result = query_icp_single(search)
        if result.get("code") == 200:
            items = result.get("params", {}).get("list", [])
            total = result.get("params", {}).get("total", 0)
            return {"items": _serialize(items), "total": total, "search": search}
        else:
            return {"error": result.get("message", "查询失败"), "items": [], "total": 0, "search": search}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Vulnerabilities ---

@router.get("/vulnerabilities", response_model=VulnerabilityListResponse, tags=["Vulnerabilities"])
async def list_vulnerabilities(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    severity: str = Query(default=""),
    search: str = Query(default=""),
    has_icp: str = Query(default=""),
):
    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")

        where = []
        params: list = []

        if severity:
            where.append("sr.severity = %s")
            params.append(severity)

        if search:
            where.append("(pt.name ILIKE %s OR sr.matched_url ILIKE %s)")
            params.extend([f"%{search}%", f"%{search}%"])

        _host_expr = "(regexp_match(sr.matched_url, '^https?://([^/:]+)'))[1]"

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

        return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/vulnerabilities/export", tags=["Vulnerabilities"])
async def vulnerabilities_export(
    severity: str = Query(default=""),
    search: str = Query(default=""),
    has_icp: str = Query(default=""),
):
    with get_cursor() as cur:
        if cur is None:
            raise HTTPException(status_code=503, detail="database not available")

        where = []
        params: list = []

        if severity:
            where.append("sr.severity = %s")
            params.append(severity)

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
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities.csv"},
    )


# --- Config ---

_CONFIG_FILE = str(FsPath(__file__).resolve().parent.parent.parent / ".env")


@router.get("/config", tags=["Config"])
async def get_config():
    try:
        if os.path.isfile(_CONFIG_FILE):
            with open(_CONFIG_FILE, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            content = ""
        return {"path": _CONFIG_FILE, "content": content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/config", tags=["Config"])
async def update_config(body: ConfigUpdateRequest):
    content = body.content
    if not isinstance(content, str):
        raise HTTPException(status_code=400, detail="content 必须是字符串")

    try:
        backup_path = _CONFIG_FILE + ".bak"
        if os.path.isfile(_CONFIG_FILE):
            import shutil
            shutil.copy2(_CONFIG_FILE, backup_path)

        with open(_CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write(content)

        from ..config import _load_dotenv
        _load_dotenv()

        logger.info("配置文件已更新: %s", _CONFIG_FILE)
        return {"path": _CONFIG_FILE, "saved": True, "backup": backup_path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Proxy Pool Management ---

_PROXY_TOGGLE_KEYS = ["PROXY_ENABLED_FOFA", "PROXY_ENABLED_HUNTER", "PROXY_ENABLED_NUCLEI", "PROXY_ENABLED_ICP", "PROXY_ENABLED_DEEPSEEK"]


def _get_proxy_file_path() -> FsPath:
    """代理文件绝对路径。"""
    from ..config import ROOT_DIR, PROXY_FILE
    p = FsPath(PROXY_FILE)
    if not p.is_absolute():
        p = ROOT_DIR / p
    return p


def _write_proxy_file(lines: list[str]) -> None:
    """原子写入代理文件（先写临时文件再 rename）。"""
    import tempfile
    path = _get_proxy_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, str(path))
    except Exception:
        os.unlink(tmp)
        raise


def _read_dotenv() -> dict[str, str]:
    """读取 .env 文件为 dict。"""
    env_file = FsPath(__file__).resolve().parent.parent.parent / ".env"
    result: dict[str, str] = {}
    if not env_file.is_file():
        return result
    with open(env_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip().strip("\"'")
    return result


def _write_dotenv(data: dict[str, str]) -> None:
    """回写 .env，保留原有注释和空行，仅更新匹配的 key=value 行，追加新增 key。"""
    env_file = FsPath(__file__).resolve().parent.parent.parent / ".env"
    backup = str(env_file) + ".bak"

    if env_file.is_file():
        import shutil
        shutil.copy2(str(env_file), backup)

    original_lines: list[str] = []
    if env_file.is_file():
        original_lines = env_file.read_text(encoding="utf-8").splitlines()

    new_lines = []
    updated_keys = set()
    for line in original_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.split("=", 1)[0].strip()
            if k in data:
                new_lines.append(f"{k}={data[k]}")
                updated_keys.add(k)
                continue
        new_lines.append(line)

    for k, v in data.items():
        if k not in updated_keys:
            new_lines.append(f"{k}={v}")

    env_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    from ..config import _load_dotenv
    _load_dotenv()


def _reload_proxy_pool():
    """强制重新加载代理池单例。"""
    from ..utils import proxy as proxy_mod
    proxy_mod._pool = None
    proxy_mod._pool_initialized = False


@router.get("/proxy/status", response_model=ProxyStatusResponse, tags=["Proxy"])
async def proxy_status():
    """获取代理池状态：代理列表、健康状态、组件开关。"""
    from ..utils.proxy import get_proxy_pool
    from ..config import (
        PROXY_ENABLED_FOFA, PROXY_ENABLED_HUNTER, PROXY_ENABLED_NUCLEI,
        PROXY_ENABLED_ICP, PROXY_ENABLED_DEEPSEEK,
        PROXY_STRATEGY, PROXY_COOLDOWN, PROXY_MAX_FAILURES,
    )

    pool = get_proxy_pool()

    proxy_file = _get_proxy_file_path()
    if proxy_file.is_file():
        raw_lines = [
            l for l in proxy_file.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
    else:
        raw_lines = []

    pool_status = pool.status() if pool else {
        "total": len(raw_lines), "available": len(raw_lines), "in_cooldown": 0,
        "strategy": PROXY_STRATEGY, "cooldown_seconds": PROXY_COOLDOWN,
        "max_failures": PROXY_MAX_FAILURES, "proxies": [
            {"url": u, "failures": 0, "in_cooldown": False, "cooldown_remaining": 0}
            for u in raw_lines
        ],
    }

    pool_status["toggles"] = {
        "fofa": PROXY_ENABLED_FOFA,
        "hunter": PROXY_ENABLED_HUNTER,
        "nuclei": PROXY_ENABLED_NUCLEI,
        "icp": PROXY_ENABLED_ICP,
        "deepseek": PROXY_ENABLED_DEEPSEEK,
    }
    pool_status["file_path"] = str(proxy_file)
    pool_status["pool_loaded"] = pool is not None

    return pool_status


@router.post("/proxy/test", response_model=ProxyTestResponse, tags=["Proxy"])
async def proxy_test(body: ProxyTestRequest):
    """测试单个代理的连通性。"""
    import time as _time
    import requests as _requests

    url = body.url.strip()
    test_urls = ["https://www.baidu.com", "https://httpbin.org/ip"]
    proxy_dict = {"http": url, "https": url}

    start = _time.monotonic()
    try:
        for test_url in test_urls:
            resp = _requests.get(test_url, proxies=proxy_dict, timeout=10)
            if resp.status_code >= 500:
                raise RuntimeError(f"{test_url} returned {resp.status_code}")
        latency = (_time.monotonic() - start) * 1000
        return {"url": url, "success": True, "latency_ms": round(latency, 1), "error": None}
    except Exception as e:
        latency = (_time.monotonic() - start) * 1000
        return {"url": url, "success": False, "latency_ms": round(latency, 1), "error": str(e)}


@router.post("/proxy/add", tags=["Proxy"])
async def proxy_add(body: ProxyAddRequest):
    """向代理文件追加一个代理。"""
    url = body.url.strip()
    path = _get_proxy_file_path()

    lines = []
    if path.is_file():
        lines = [
            l.strip() for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]

    if url in lines:
        raise HTTPException(status_code=400, detail="代理已存在")

    lines.append(url)
    _write_proxy_file(lines)
    _reload_proxy_pool()

    logger.info("代理已添加: %s", url)
    return {"message": "添加成功", "url": url, "total": len(lines)}


@router.post("/proxy/batch-test", response_model=ProxyBatchTestResponse, tags=["Proxy"])
async def proxy_batch_test(body: ProxyBatchTestRequest):
    """批量测试代理连通性（并发测试）。"""
    import time as _time
    import asyncio
    import requests as _requests

    test_urls = ["https://www.baidu.com", "https://httpbin.org/ip"]

    async def _test_one(url: str) -> dict:
        url = url.strip()
        proxy_dict = {"http": url, "https": url}
        start = _time.monotonic()
        try:
            for tu in test_urls:
                resp = await asyncio.to_thread(
                    _requests.get, tu, proxies=proxy_dict, timeout=10
                )
                if resp.status_code >= 500:
                    raise RuntimeError(f"{tu} returned {resp.status_code}")
            latency = (_time.monotonic() - start) * 1000
            return {"url": url, "success": True, "latency_ms": round(latency, 1), "error": None}
        except Exception as e:
            latency = (_time.monotonic() - start) * 1000
            return {"url": url, "success": False, "latency_ms": round(latency, 1), "error": str(e)}

    tasks = [_test_one(u) for u in body.urls]
    results = await asyncio.gather(*tasks)

    success_count = sum(1 for r in results if r["success"])
    return ProxyBatchTestResponse(
        results=results,
        total=len(results),
        success_count=success_count,
        fail_count=len(results) - success_count,
    )


@router.post("/proxy/batch-add", tags=["Proxy"])
async def proxy_batch_add(body: ProxyBatchAddRequest):
    """批量添加代理（可选先测试后添加）。"""
    import time as _time
    import asyncio
    import requests as _requests

    all_urls = [u.strip() for u in body.urls if u.strip()]

    # 1) 可选先测试
    passed_urls: set[str] = set()
    failed_results: list[dict] = []

    if body.test_before_add:
        test_urls = ["https://www.baidu.com", "https://httpbin.org/ip"]

        async def _test_one(url: str) -> dict:
            proxy_dict = {"http": url, "https": url}
            start = _time.monotonic()
            try:
                for tu in test_urls:
                    resp = await asyncio.to_thread(
                        _requests.get, tu, proxies=proxy_dict, timeout=10
                    )
                    if resp.status_code >= 500:
                        raise RuntimeError(f"{tu} returned {resp.status_code}")
                latency = (_time.monotonic() - start) * 1000
                return {"url": url, "success": True, "latency_ms": round(latency, 1), "error": None}
            except Exception as e:
                latency = (_time.monotonic() - start) * 1000
                return {"url": url, "success": False, "latency_ms": round(latency, 1), "error": str(e)}

        task_results = await asyncio.gather(*[_test_one(u) for u in all_urls])
        for tr in task_results:
            if tr["success"]:
                passed_urls.add(tr["url"])
            else:
                failed_results.append(tr)
        candidate_urls = list(passed_urls)
    else:
        candidate_urls = all_urls

    # 2) 读取现有代理
    path = _get_proxy_file_path()
    existing: set[str] = set()
    if path.is_file():
        existing = set(
            l.strip() for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#")
        )

    # 3) 去重 + 写入
    new_urls = [u for u in candidate_urls if u not in existing]
    skipped = len(candidate_urls) - len(new_urls)

    if new_urls:
        all_lines = list(existing) + new_urls
        _write_proxy_file(all_lines)
        _reload_proxy_pool()

    logger.info(
        "批量添加代理: 请求=%d, 新增=%d, 跳过=%d, 失败=%d",
        len(all_urls), len(new_urls), skipped, len(failed_results),
    )
    return {
        "message": f"批量添加完成: 新增 {len(new_urls)} 个, 跳过 {skipped} 个"
                    + (f", 失败 {len(failed_results)} 个" if failed_results else ""),
        "total_requested": len(all_urls),
        "added": len(new_urls),
        "skipped": skipped,
        "failed": len(failed_results),
        "failed_details": failed_results if failed_results else None,
    }


@router.delete("/proxy/remove", tags=["Proxy"])
async def proxy_remove(body: ProxyRemoveRequest):
    """从代理文件删除一个代理。"""
    url = body.url.strip()
    path = _get_proxy_file_path()

    if not path.is_file():
        raise HTTPException(status_code=404, detail="代理文件不存在")

    lines = [
        l.strip() for l in path.read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]

    if url not in lines:
        raise HTTPException(status_code=404, detail="代理不存在")

    lines.remove(url)
    _write_proxy_file(lines)
    _reload_proxy_pool()

    logger.info("代理已删除: %s", url)
    return {"message": "删除成功", "url": url, "total": len(lines)}


@router.put("/proxy/toggle", tags=["Proxy"])
async def proxy_toggle(body: ProxyToggleRequest):
    """更新各组件的代理开关（写 .env）。"""
    env_data = _read_dotenv()

    toggle_map = {
        "PROXY_ENABLED_FOFA": body.fofa,
        "PROXY_ENABLED_HUNTER": body.hunter,
        "PROXY_ENABLED_NUCLEI": body.nuclei,
        "PROXY_ENABLED_ICP": body.icp,
        "PROXY_ENABLED_DEEPSEEK": body.deepseek,
    }

    changed = {}
    for key, val in toggle_map.items():
        if val is not None:
            env_data[key] = "1" if val else "0"
            changed[key] = "1" if val else "0"

    if changed:
        _write_dotenv(env_data)
        _reload_proxy_pool()

    logger.info("代理开关已更新: %s", changed)
    return {"message": "开关已更新", "toggles": changed}

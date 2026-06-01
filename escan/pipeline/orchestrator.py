"""扫描流水线编排器 — 分类扫描模式

每个模板的 FOFA 查询结果独立保存，Nuclei 仅用对应模板扫描其专属资产，
ICP 结果按模板名分类输出，避免全量交叉扫描。

4 步骤：
Step 1: YAML tags → FOFA 查询 → 按模板名分类资产
Step 2: 分类资产 → Nuclei 扫描（每模板仅扫描专属资产）
Step 3: 漏洞结果 → 按模板提取 IP/域名
Step 4: IP → ICP 备案查询（按模板名分段）
"""

import json
import os
import threading
from pathlib import Path

from ..config import POC_DIR, SEARCH_ENGINE
from ..logging_config import get_logger
from ..utils.network import extract_tags_from_yaml, is_ipv4, extract_host_port
from ..utils.files import timestamp_dir
from .fofa import query_fofa_multiple, query_fofa
from .nuclei import scan as nuclei_scan_fn
from .icp import batch_query_icp, format_output, enrich_icp_with_api
from .cache import (
    get_cached_assets,
    set_cached_assets,
    get_scan_stats,
)

logger = get_logger("pipeline.orchestrator")


class StopScanException(Exception):
    """扫描被用户主动停止。"""
    pass


def _check_stop(stop_event: threading.Event | None):
    """检查停止标志，若被设置则抛出 StopScanException。"""
    if stop_event and stop_event.is_set():
        raise StopScanException("扫描已停止")


def _build_region_clause(region: str) -> str:
    """将地域输入转为 FOFA/Hunter 地域过滤片段。

    规则：2-3 位纯大写字母 → country="XX"，其余 → region="XX"
    空字符串 → 不追加过滤。
    """
    region = (region or "").strip()
    if not region:
        return ""
    if region.isascii() and region.isupper() and 2 <= len(region) <= 3 and region.isalpha():
        return f'country="{region}"'
    return f'region="{region}"'


def _resolve_query_fn(engine: str):
    """根据引擎名返回对应的批量查询函数。"""
    if engine == "hunter":
        from .hunter import query_hunter_multiple
        return query_hunter_multiple
    return query_fofa_multiple


def _resolve_single_query_fn(engine: str):
    """根据引擎名返回对应的单条查询函数。"""
    if engine == "hunter":
        from .hunter import query_hunter
        return query_hunter
    return query_fofa


def get_status() -> dict:
    """获取扫描缓存状态。"""
    return get_scan_stats()


# --- 分类扫描（Categorized）---

def _asset_record(asset, engine: str, query_used: str) -> dict:
    """构造单条资产记录。

    asset: FofaAsset 对象（fofa/hunter 统一返回）或 URL 字符串（向后兼容）。
    """
    from .fofa import FofaAsset, _normalize_dedup_key

    if isinstance(asset, FofaAsset):
        host = asset.ip or asset.host
        return {
            "url": asset.url, "host": host, "port": asset.port,
            "scheme": asset.scheme, "query_used": query_used,
            "title": asset.title,
            "_dedup_key": asset.dedup_key,
        }

    # 向后兼容：纯 URL 字符串
    url = asset
    scheme = "http"
    if "://" in url:
        scheme = url.split("://")[0]
        host_part = url.split("://")[1].split("/")[0]
    else:
        host_part = url.split("/")[0]
    if ":" in host_part:
        host, port_str = host_part.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 443 if scheme == "https" else 80
    else:
        host = host_part
        port = 443 if scheme == "https" else 80
    return {
        "url": url, "host": host, "port": port,
        "scheme": scheme, "query_used": query_used,
        "_dedup_key": _normalize_dedup_key(scheme, host, port),
    }


def _collect_categorized_assets(
    yaml_files: list[str], out_dir: Path, engine: str = "fofa",
    task_id: str = None, skip_existing: bool = False,
    region: str = "",
) -> dict[str, list[str]]:
    """Step 1 核心：逐模板查询 FOFA，资产按模板名分类保存（即时写入）。

    region: 可选地域筛选，如 "CN" → country="CN"，"北京" → region="北京"

    Returns:
        {template_name: [asset_urls]}
    """
    from ..database.connection import get_cursor
    from ..database.dao import insert_discovered_assets as db_insert_assets
    from ..database.dao import upsert_poc_template
    from ..utils.network import extract_yaml_id

    query_fn = _resolve_query_fn(engine)
    cat_dir = out_dir / "categorized"
    cat_dir.mkdir(parents=True, exist_ok=True)

    categorized: dict[str, list[str]] = {}
    template_id_map: dict[str, str] = {}  # filename → real YAML id

    for filepath in yaml_files:
        filename = os.path.splitext(os.path.basename(filepath))[0]

        # 取 YAML 真实 id，回退至文件名
        real_id = extract_yaml_id(filepath) or filename
        template_id_map[filename] = real_id

        asset_file = cat_dir / f"{filename}_assets.txt"

        # 恢复模式：跳过已有资产文件
        if skip_existing and asset_file.is_file():
            assets = [
                l for l in asset_file.read_text(encoding="utf-8").splitlines()
                if l.strip()
            ]
            categorized[filename] = assets
            logger.info("  [%s] 跳过 (资产文件已存在) → %d 条", filename, len(assets))
            continue

        tags = extract_tags_from_yaml(filepath)
        if not tags:
            logger.warning("  %s → 无 tags，跳过", filename)
            continue

        # 追回地域过滤
        region_clause = _build_region_clause(region)
        if region_clause:
            tags = f"{tags} && {region_clause}"

        try:
            assets = query_fn([tags])
            # assets 已按去重键去重（FofaAsset 列表），转为 URL 字符串用于文件输出
            categorized[filename] = assets
            logger.info(
                "  [%s] %s → %d 条资产", filename, tags[:60], len(assets)
            )
        except Exception as e:
            logger.error(
                "  [%s] 查询失败 | 模板: %s | 查询: %s | 错误: %s: %s",
                filename, filename, tags[:100], type(e).__name__, e,
            )
            categorized[filename] = []

        # 即时写入资产文件（崩溃安全）
        if categorized[filename]:
            asset_urls = [a.url if hasattr(a, "url") else a for a in categorized[filename]]
            asset_file.write_text(
                "\n".join(asset_urls) + "\n", encoding="utf-8"
            )

        # 写入数据库
        if task_id and categorized[filename]:
            with get_cursor() as cur:
                if cur is not None:
                    from ..database.dao import get_existing_asset_keys

                    # 确保模板记录存在（满足 FK 约束）
                    upsert_poc_template(cur, {
                        "id": real_id,
                        "name": filename,
                        "severity": None,
                    })

                    records = [
                        _asset_record(a, engine, tags)
                        for a in categorized[filename]
                    ]

                    # 跨任务去重：查询已有资产并过滤
                    hosts = list({r["host"] for r in records if r.get("host")})
                    existing_keys = get_existing_asset_keys(cur, hosts)
                    if existing_keys:
                        before = len(records)
                        records = [r for r in records if r.get("_dedup_key") not in existing_keys]
                        skipped = before - len(records)
                        if skipped:
                            logger.info(
                                "  [%s] 跨任务去重: 跳过 %d 条已有资产",
                                filename, skipped,
                            )

                    if records:
                        try:
                            db_insert_assets(cur, task_id, real_id, records, engine)
                        except Exception as e:
                            logger.error(
                                "  [%s] 入库失败 | 模板: %s | 记录数: %d | 错误: %s: %s",
                                filename, filename, len(records), type(e).__name__, e,
                            )

    # 汇总 JSON 方便程序读取
    _categorized_urls = {
        k: [a.url if hasattr(a, "url") else a for a in v]
        for k, v in categorized.items()
    }
    (cat_dir / "categorized_assets.json").write_text(
        json.dumps(_categorized_urls, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # 写入扫描覆盖数据（先确保模板记录存在，满足 FK 约束）
    if task_id:
        from ..database.dao import upsert_template_coverage
        from ..database.dao import upsert_poc_template as _upsert_tpl
        with get_cursor() as cur:
            if cur is not None:
                for name, assets in categorized.items():
                    real_id = template_id_map.get(name, name)
                    _upsert_tpl(cur, {"id": real_id, "name": name})
                    upsert_template_coverage(cur, task_id, real_id, {
                        "has_assets": bool(assets),
                        "asset_count": len(assets),
                    })

    total = sum(len(v) for v in categorized.values())
    logger.info(
        "分类资产收集完成: %d 个模板, %d 条资产 → %s",
        len(categorized), total, cat_dir,
    )
    return categorized


def run_categorized_step1(poc_path: str, out_dir: Path, engine: str = "fofa",
                          task_id: str = None, skip_existing: bool = False,
                          region: str = "") -> int:
    """分类 Step 1：收集并分类资产。"""
    if os.path.isfile(poc_path):
        yaml_files = [poc_path]
    else:
        yaml_files = [
            os.path.join(poc_path, f) for f in os.listdir(poc_path)
            if f.endswith((".yaml", ".yml"))
        ]

    if not yaml_files:
        logger.error("%s 下未找到 YAML 文件", poc_path)
        return 0

    logger.info("分类 Step 1 (%s): 读取 %d 个 POC 模板", engine.upper(), len(yaml_files))
    categorized = _collect_categorized_assets(
        yaml_files, out_dir, engine, task_id, skip_existing=skip_existing,
        region=region,
    )
    return sum(len(v) for v in categorized.values())


def run_categorized_step2(poc_path: str, out_dir: Path,
                          task_id: str = None, skip_existing: bool = False,
                          stop_event: threading.Event | None = None) -> int:
    """分类 Step 2：每个模板只扫描其专属资产，结果合并输出。"""
    from ..database.connection import get_cursor
    from ..database.dao import insert_scan_results as db_insert_results
    from ..database.dao import upsert_poc_template
    from ..utils.network import extract_yaml_id

    cat_dir = out_dir / "categorized"
    if not cat_dir.is_dir():
        logger.error("分类目录不存在: %s，请先执行 Step 1", cat_dir)
        return 0

    if os.path.isfile(poc_path):
        templates = {os.path.splitext(os.path.basename(poc_path))[0]: poc_path}
    else:
        templates = {}
        for f in os.listdir(poc_path):
            if f.endswith((".yaml", ".yml")):
                templates[os.path.splitext(f)[0]] = os.path.join(poc_path, f)

    # 构建 filename → real YAML id 映射
    id_map: dict[str, str] = {}
    for name, tpath in templates.items():
        real_id = extract_yaml_id(tpath) or name
        id_map[name] = real_id

    total_hits = 0
    all_lines: list[str] = []
    coverage: dict[str, dict] = {}  # template_name → {was_scanned, hits}

    for name, tpath in templates.items():
        real_id = id_map[name]
        _check_stop(stop_event)

        result_file = cat_dir / f"{name}_results.txt"

        # 恢复模式：结果文件已存在则跳过
        if skip_existing and result_file.is_file():
            lines = [
                l for l in result_file.read_text(encoding="utf-8").splitlines()
                if l.strip()
            ]
            coverage[name] = {"was_scanned": True, "hits_found": len(lines)}
            if lines:
                all_lines.extend(lines)
                total_hits += len(lines)
            logger.info("  [%s] 跳过 (结果文件已存在) → %d 个漏洞", name, len(lines))
            continue

        asset_file = cat_dir / f"{name}_assets.txt"
        if not asset_file.is_file():
            logger.debug("  [%s] 无资产文件，跳过", name)
            continue

        assets = [
            l for l in asset_file.read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]
        if not assets:
            logger.debug("  [%s] 资产为空，跳过", name)
            continue

        # 写入临时目标文件供 nuclei 使用
        tmp_targets = str(cat_dir / f"_{name}_targets.tmp")
        Path(tmp_targets).write_text("\n".join(assets) + "\n", encoding="utf-8")

        nuclei_scan_fn(tmp_targets, tpath, str(result_file))

        hits = 0
        if result_file.is_file():
            lines = [
                l for l in result_file.read_text(encoding="utf-8").splitlines()
                if l.strip()
            ]
            if lines:
                all_lines.extend(lines)
                total_hits += len(lines)
                hits = len(lines)
                logger.info("  [%s] 发现 %d 个漏洞", name, hits)

                # 写入数据库
                if task_id:
                    with get_cursor() as cur:
                        if cur is not None:
                            upsert_poc_template(cur, {"id": real_id, "name": name})
                            db_insert_results(cur, task_id, real_id, lines)

        coverage[name] = {"was_scanned": True, "hits_found": hits}

        # 清理临时文件
        if os.path.isfile(tmp_targets):
            os.remove(tmp_targets)

    # 写入扫描覆盖数据
    if task_id and coverage:
        from ..database.dao import upsert_template_coverage
        from ..database.dao import upsert_poc_template as _upsert_tpl
        with get_cursor() as cur:
            if cur is not None:
                for name, cov in coverage.items():
                    real_id = id_map.get(name, name)
                    _upsert_tpl(cur, {"id": real_id, "name": name})
                    upsert_template_coverage(cur, task_id, real_id, cov)

    # 合并所有结果到 nuclei_results.txt
    merged_file = out_dir / "nuclei_results.txt"
    merged_file.write_text("\n".join(all_lines) + "\n", encoding="utf-8")
    logger.info(
        "分类 Step 2 完成: %d 个模板扫描, %d 个漏洞 → %s",
        len(templates), total_hits, merged_file,
    )
    return total_hits


def run_categorized_step3(out_dir: Path, task_id: str = None,
                          skip_existing: bool = False) -> int:
    """分类 Step 3：从每个模板的 nuclei 结果提取 host，保留模板标签（即时写入）。"""
    from ..database.connection import get_cursor
    from ..database.dao import insert_host_results as db_insert_hosts

    cat_dir = out_dir / "categorized"
    if not cat_dir.is_dir():
        logger.error("分类目录不存在: %s", cat_dir)
        return 0

    all_hosts: set[str] = set()
    template_hosts: dict[str, list[str]] = {}

    for result_file in sorted(cat_dir.iterdir()):
        if not result_file.name.endswith("_results.txt"):
            continue
        template_name = result_file.name[:-len("_results.txt")]
        target_file = cat_dir / f"{template_name}_targets.txt"

        # 恢复模式：跳过已有 targets 文件
        if skip_existing and target_file.is_file():
            hosts = set(
                h for h in target_file.read_text(encoding="utf-8").splitlines()
                if h.strip()
            )
            template_hosts[template_name] = sorted(hosts)
            all_hosts.update(hosts)
            logger.info("  [%s] 跳过 (targets 文件已存在) → %d 个 host", template_name, len(hosts))
            continue

        hosts = set()
        for line in result_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            for prefix in ("http://", "https://"):
                idx = line.find(prefix)
                if idx != -1:
                    line = line[idx:]
                    break
            r = extract_host_port(line)
            if r:
                _, hostname, _ = r
                hosts.add(hostname)

        template_hosts[template_name] = sorted(hosts)
        all_hosts.update(hosts)
        logger.info("  [%s] 提取 %d 个 host", template_name, len(hosts))

        # 即时写入 targets 文件（崩溃安全）
        if hosts:
            target_file.write_text("\n".join(sorted(hosts)) + "\n", encoding="utf-8")

        # 实时写入数据库
        if task_id and hosts:
            with get_cursor() as cur:
                if cur is not None:
                    db_insert_hosts(cur, task_id, template_name, list(hosts))

    # 汇总 targets.txt（兼容）
    targets_out = out_dir / "targets.txt"
    targets_out.write_text(
        "\n".join(sorted(all_hosts)) + "\n", encoding="utf-8"
    )

    ip_count = sum(1 for h in all_hosts if is_ipv4(h))
    domain_count = len(all_hosts) - ip_count
    logger.info(
        "分类 Step 3 完成: %d 个模板, %d 个 host（IP: %d, 域名: %d）",
        len(template_hosts), len(all_hosts), ip_count, domain_count,
    )

    # 写入覆盖数据
    if task_id and template_hosts:
        from ..database.dao import upsert_template_coverage
        from ..database.dao import upsert_poc_template as _upsert_tpl
        with get_cursor() as cur:
            if cur is not None:
                for name in template_hosts:
                    _upsert_tpl(cur, {"id": name, "name": name})
                    upsert_template_coverage(cur, task_id, name, {
                        "hosts_extracted": len(template_hosts[name]),
                    })

    return len(all_hosts)


def run_categorized_step4(out_dir: Path, task_id: str = None,
                          skip_existing: bool = False,
                          processed_templates: set | None = None,
                          stop_event: threading.Event | None = None) -> int:
    """分类 Step 4：从 nuclei_results.txt 按模板名分组提取 host，分别 ICP 查询。"""
    from ..database.connection import get_cursor
    from ..database.dao import insert_icp_results as db_insert_icp

    nuclei_file = out_dir / "nuclei_results.txt"
    if not nuclei_file.is_file():
        logger.error("nuclei_results.txt 不存在: %s", nuclei_file)
        return 0

    # 恢复模式：从已有 icp_results.txt 解析已处理的模板
    already_processed: set[str] = set(processed_templates) if processed_templates else set()
    icp_out = out_dir / "icp_results.txt"
    if skip_existing and not already_processed and icp_out.is_file():
        for line in icp_out.read_text(encoding="utf-8").splitlines():
            if line.startswith("模板: "):
                already_processed.add(line[4:].strip())

    # 从 nuclei_results.txt 按模板名分组提取 host
    # 格式: [template_name] [protocol] [severity] url
    template_hosts: dict[str, set[str]] = {}
    for line in nuclei_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or not line.startswith("["):
            continue
        end = line.find("]")
        if end == -1:
            continue
        template_name = line[1:end]

        for prefix in ("http://", "https://"):
            idx = line.find(prefix)
            if idx != -1:
                url_part = line[idx:]
                r = extract_host_port(url_part)
                if r:
                    _, hostname, _ = r
                    template_hosts.setdefault(template_name, set()).add(hostname)
                break

    if not template_hosts:
        logger.warning("nuclei_results.txt 中未提取到 host")
        return 0

    total_ips = 0
    new_entries: list[str] = []

    for template_name in sorted(template_hosts):
        _check_stop(stop_event)

        # 恢复模式：跳过已处理的模板
        if skip_existing and template_name in already_processed:
            logger.info("  [%s] 跳过 (ICP 已处理)", template_name)
            continue

        hosts = template_hosts[template_name]
        ips = [h for h in hosts if is_ipv4(h)]
        direct_domains = [h for h in hosts if not is_ipv4(h)]

        all_results = []
        if ips:
            all_results = batch_query_icp(ips)
            total_ips += len(ips)

        if direct_domains:
            direct_entries = [
                {"domain": d, "icp": None, "source": "targets"}
                for d in direct_domains
            ]
            all_results.append({
                "ip": "(域名)", "results": direct_entries, "error": None,
            })

        if all_results:
            all_results = enrich_icp_with_api(all_results)

        # MIIT 官方 ICP 查询补充：对域名做精确备案查询
        if all_results and direct_domains:
            try:
                from .miit_icp import query_icp_batch as miit_query_batch
                miit_results = miit_query_batch(direct_domains)
                # 合并 MIIT 结果到 all_results
                for miit_entry in miit_results:
                    if miit_entry.get("results"):
                        all_results.append(miit_entry)
            except Exception as e:
                logger.warning("MIIT ICP 查询跳过: %s", e)

        output_line = format_output(all_results, template_name)
        new_entries.append(output_line + "\n")

        with open(icp_out, "a", encoding="utf-8") as f:
            f.write(output_line + "\n")

        # 写入数据库（icp_results + icp_stats）
        if task_id and all_results:
            with get_cursor() as cur:
                if cur is not None:
                    # 构建 IP → asset_id 映射，关联资产
                    ip_asset_map = {}
                    ips_to_query = [
                        e["ip"] for e in all_results
                        if e.get("ip") and e["ip"] != "(域名)"
                    ]
                    if ips_to_query:
                        cur.execute("""
                            SELECT DISTINCT ON (host) host, asset_id
                            FROM discovered_assets
                            WHERE task_id = %s AND host = ANY(%s)
                        """, (task_id, ips_to_query))
                        ip_asset_map = {row[0]: row[1] for row in cur.fetchall()}

                    db_insert_icp(cur, task_id, all_results, template_name, ip_asset_map)

                    # 计算 ICP 统计指标
                    ips_with_data = 0
                    domains_found = 0
                    domains_with_icp = 0
                    icp_api_supplement = 0

                    for item in all_results:
                        if item.get("error") or not item.get("results"):
                            continue
                        has_data = False
                        for entry in item["results"]:
                            domains_found += 1
                            if entry.get("icp"):
                                domains_with_icp += 1
                                has_data = True
                            if entry.get("icp_api"):
                                icp_api_supplement += 1
                                has_data = True
                        if has_data:
                            ips_with_data += 1

                    from ..database.dao import upsert_template_icp_stats
                    from ..database.dao import upsert_poc_template as _upsert_tpl
                    _upsert_tpl(cur, {"id": template_name, "name": template_name})
                    upsert_template_icp_stats(cur, task_id, template_name, {
                        "ips_queried": len(ips),
                        "ips_with_data": ips_with_data,
                        "domains_found": domains_found,
                        "domains_with_icp": domains_with_icp,
                        "icp_api_supplement": icp_api_supplement,
                    })

        # 标记模板完成（供断点追踪）
        if skip_existing:
            from .checkpoint import mark_step4_template_done
            mark_step4_template_done(out_dir, task_id, template_name)

        logger.info(
            "  [%s] ICP: %d 个 IP, %d 个域名",
            template_name, len(ips), len(direct_domains),
        )

    logger.info("分类 Step 4 完成: %d 个模板, %d 个 IP → %s",
                 len(template_hosts), total_ips, icp_out)

    # 写入覆盖数据
    if task_id and template_hosts:
        from ..database.dao import upsert_template_coverage
        from ..database.dao import upsert_poc_template as _upsert_tpl
        with get_cursor() as cur:
            if cur is not None:
                for name in template_hosts:
                    if not skip_existing or name not in already_processed:
                        _upsert_tpl(cur, {"id": name, "name": name})
                        upsert_template_coverage(cur, task_id, name, {
                            "icp_queried": True,
                        })

    return total_ips


def _update_task_step(task_id: str | None, step: int):
    """更新 scan_tasks 的 current_step，失败静默忽略。"""
    if not task_id:
        return
    try:
        from ..database.connection import get_cursor
        from ..database.dao import update_task_current_step
        with get_cursor() as cur:
            if cur is not None:
                update_task_current_step(cur, task_id, step)
    except Exception:
        pass


def _count_existing_assets(out_dir: Path) -> int:
    cat_dir = out_dir / "categorized"
    total = 0
    if cat_dir.is_dir():
        for f in cat_dir.iterdir():
            if f.name.endswith("_assets.txt"):
                total += sum(1 for l in f.read_text(encoding="utf-8").splitlines() if l.strip())
    return total


def _count_existing_results(out_dir: Path) -> int:
    cat_dir = out_dir / "categorized"
    total = 0
    if cat_dir.is_dir():
        for f in cat_dir.iterdir():
            if f.name.endswith("_results.txt"):
                total += sum(1 for l in f.read_text(encoding="utf-8").splitlines() if l.strip())
    return total


def _count_existing_hosts(out_dir: Path) -> int:
    targets_file = out_dir / "targets.txt"
    if targets_file.is_file():
        return sum(1 for l in targets_file.read_text(encoding="utf-8").splitlines() if l.strip())
    return 0


def _count_icp_entries(out_dir: Path) -> int:
    icp_file = out_dir / "icp_results.txt"
    total = 0
    if icp_file.is_file():
        for line in icp_file.read_text(encoding="utf-8").splitlines():
            if "- 备案号:" in line:
                total += 1
    return total


def run_categorized(
    poc_path: str = POC_DIR, engine: str = SEARCH_ENGINE,
    resume_from_dir: Path | None = None,
    task_id: str = None,
    stop_event: threading.Event | None = None,
    region: str = "",
) -> dict:
    """执行分类扫描流水线（推荐）：每个模板独立查询+扫描，ICP 按模板分类。

    支持断点续扫：传入 resume_from_dir 从上次中断位置继续。
    task_id: 可选，外部预创建的 scan_tasks ID，传入后不再重复创建。
    stop_event: 可选，用于外部停止扫描。
    region: 可选地域筛选，如 "CN" → country="CN"，"北京" → region="北京"
    """
    from ..database.connection import get_cursor
    from ..database.dao import create_scan_task, complete_scan_task
    from .checkpoint import (
        init_checkpoint, load_checkpoint, infer_checkpoint,
        mark_step_started, mark_step_completed, get_resume_step,
    )

    if resume_from_dir:
        # --- 恢复模式 ---
        out_dir = resume_from_dir
        cp = load_checkpoint(out_dir) or infer_checkpoint(out_dir, "categorized", engine, poc_path)
        task_id = cp.get("task_id")
        region = cp.get("region", region)  # 从断点恢复 region，命令行传入的作为回退

        # 校验 task_id 在数据库中是否仍存在（可能已被前端删除）
        if task_id:
            from ..database.connection import get_cursor as _gc
            from ..database.dao import create_scan_task as _cst
            with _gc() as cur:
                if cur is not None:
                    cur.execute("SELECT 1 FROM scan_tasks WHERE task_id = %s", (task_id,))
                    if not cur.fetchone():
                        logger.warning("断点中的 task_id 已不存在 (%s)，创建新任务", task_id)
                        task_id = _cst(cur, cp["scan_type"], cp.get("engine", engine), str(out_dir))
                        cp["task_id"] = task_id

        resume_step = get_resume_step(cp)
        if resume_step is None:
            logger.info("所有步骤已完成: %s", out_dir)
            return {
                "step1": _count_existing_assets(out_dir),
                "step2": _count_existing_results(out_dir),
                "step3": _count_existing_hosts(out_dir),
                "step4": _count_icp_entries(out_dir),
            }
        logger.info("恢复扫描 (%s): 从 Step %d 继续 → %s", engine.upper(), resume_step, out_dir)
    else:
        # --- 新建模式 ---
        out_dir = timestamp_dir(
            os.path.join(os.path.dirname(POC_DIR), "output", "pipeline")
        )
        logger.info("开始分类扫描 (%s)，输出目录: %s", engine.upper(), out_dir)
        if not task_id:
            with get_cursor() as cur:
                task_id = create_scan_task(cur, "categorized", engine, str(out_dir))
        cp = init_checkpoint(out_dir, "categorized", engine, poc_path, task_id, region=region)
        resume_step = 1

    is_resume = resume_from_dir is not None
    assets_out = str(out_dir / f"{engine}_assets.txt")

    # Step 1: 分类收集资产
    if resume_step <= 1:
        mark_step_started(out_dir, task_id, 1)
        _update_task_step(task_id, 1)
        asset_count = run_categorized_step1(poc_path, out_dir, engine, task_id,
                                            skip_existing=is_resume,
                                            region=region)
        mark_step_completed(out_dir, task_id, 1)
    else:
        asset_count = _count_existing_assets(out_dir)

    # 汇总全部资产到 fofa_assets.txt（兼容）
    cat_dir = out_dir / "categorized"
    all_assets: set[str] = set()
    if cat_dir.is_dir():
        for f in cat_dir.iterdir():
            if f.name.endswith("_assets.txt"):
                for line in f.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        all_assets.add(line.strip())
    Path(assets_out).parent.mkdir(parents=True, exist_ok=True)
    Path(assets_out).write_text("\n".join(sorted(all_assets)) + "\n", encoding="utf-8")

    # Step 2: 分类扫描
    if resume_step <= 2:
        mark_step_started(out_dir, task_id, 2)
        _update_task_step(task_id, 2)
        vuln_count = run_categorized_step2(poc_path, out_dir, task_id,
                                           skip_existing=is_resume,
                                           stop_event=stop_event)
        mark_step_completed(out_dir, task_id, 2)
    else:
        vuln_count = _count_existing_results(out_dir)

    # Step 3: 分类提取
    if resume_step <= 3:
        mark_step_started(out_dir, task_id, 3)
        _update_task_step(task_id, 3)
        host_count = run_categorized_step3(out_dir, task_id,
                                           skip_existing=is_resume)
        mark_step_completed(out_dir, task_id, 3)
    else:
        host_count = _count_existing_hosts(out_dir)

    # Step 4: ICP 查询
    if resume_step <= 4:
        processed = set(cp.get("step4_templates", [])) if is_resume else None
        mark_step_started(out_dir, task_id, 4)
        _update_task_step(task_id, 4)
        ip_count = run_categorized_step4(out_dir, task_id,
                                         skip_existing=is_resume,
                                         processed_templates=processed,
                                         stop_event=stop_event)
        mark_step_completed(out_dir, task_id, 4)
    else:
        ip_count = _count_icp_entries(out_dir)

    results = {
        "step1": asset_count,
        "step2": vuln_count,
        "step3": host_count,
        "step4": ip_count,
    }

    # 标记任务完成
    if task_id:
        with get_cursor() as cur:
            complete_scan_task(cur, task_id, "completed", results)

    logger.info("分类扫描完成: %s", results)
    logger.info("输出目录: %s", out_dir)
    return results


def run_categorized_incremental(
    poc_path: str = POC_DIR, engine: str = SEARCH_ENGINE,
    resume_from_dir: Path | None = None,
    task_id: str = None,
    stop_event: threading.Event | None = None,
    region: str = "",
) -> dict:
    """增量分类扫描：跳过已缓存的查询，只扫描新资产。支持断点续扫。
    task_id: 可选，外部预创建的 scan_tasks ID，传入后不再重复创建。
    stop_event: 可选，用于外部停止扫描。
    region: 可选地域筛选，如 "CN" → country="CN"，"北京" → region="北京"
    """
    from .checkpoint import (
        init_checkpoint, load_checkpoint, infer_checkpoint,
        mark_step_started, mark_step_completed, get_resume_step,
    )

    if resume_from_dir:
        # --- 恢复模式 ---
        out_dir = resume_from_dir
        cp = load_checkpoint(out_dir) or infer_checkpoint(out_dir, "categorized_incremental", engine, poc_path)
        region = cp.get("region", region)
        task_id = cp.get("task_id")

        # 校验 task_id 在数据库中是否仍存在
        if task_id:
            from ..database.connection import get_cursor as _gc
            from ..database.dao import create_scan_task as _cst
            with _gc() as cur:
                if cur is not None:
                    cur.execute("SELECT 1 FROM scan_tasks WHERE task_id = %s", (task_id,))
                    if not cur.fetchone():
                        logger.warning("断点中的 task_id 已不存在 (%s)，创建新任务", task_id)
                        task_id = _cst(cur, cp["scan_type"], cp.get("engine", engine), str(out_dir))
                        cp["task_id"] = task_id

        resume_step = get_resume_step(cp)
        if resume_step is None:
            logger.info("所有步骤已完成: %s", out_dir)
            return {
                "step1": _count_existing_assets(out_dir),
                "step2": _count_existing_results(out_dir),
                "step3": _count_existing_hosts(out_dir),
                "step4": _count_icp_entries(out_dir),
            }
        logger.info("恢复增量扫描 (%s): 从 Step %d 继续 → %s", engine.upper(), resume_step, out_dir)
    else:
        # --- 新建模式 ---
        out_dir = timestamp_dir(
            os.path.join(os.path.dirname(POC_DIR), "output", "pipeline")
        )
        logger.info("开始增量分类扫描 (%s)，输出目录: %s", engine.upper(), out_dir)
        cp = init_checkpoint(out_dir, "categorized_incremental", engine, poc_path, task_id, region=region)
        resume_step = 1

    is_resume = resume_from_dir is not None

    # Step 1: 资产收集
    if resume_step <= 1:
        mark_step_started(out_dir, None, 1)

        if os.path.isfile(poc_path):
            yaml_files = [poc_path]
        else:
            yaml_files = [
                os.path.join(poc_path, f) for f in os.listdir(poc_path)
                if f.endswith((".yaml", ".yml"))
            ]

        if is_resume:
            # 恢复：用 step1 标准函数（自带 skip_existing + 缓存命中逻辑）
            asset_count = run_categorized_step1(poc_path, out_dir, engine,
                                                task_id=None, skip_existing=True,
                                                region=region)
        else:
            # 新建：原有缓存内联逻辑
            single_query_fn = _resolve_single_query_fn(engine)
            categorized: dict[str, list[str]] = {}
            new_count = 0
            cache_count = 0
            cat_dir = out_dir / "categorized"
            cat_dir.mkdir(parents=True, exist_ok=True)

            for filepath in yaml_files:
                template_name = os.path.splitext(os.path.basename(filepath))[0]
                tags = extract_tags_from_yaml(filepath)
                if not tags:
                    continue

                cached = get_cached_assets(tags, engine)
                if cached is not None:
                    categorized[template_name] = cached
                    cache_count += 1
                    (cat_dir / f"{template_name}_assets.txt").write_text(
                        "\n".join(cached) + "\n", encoding="utf-8"
                    )
                    continue

                try:
                    assets = single_query_fn(tags, size=100)
                    # assets 已按去重键去重（FofaAsset 列表），转为 URL 字符串用于缓存和文件
                    asset_urls = [a.url if hasattr(a, "url") else a for a in assets]
                    categorized[template_name] = asset_urls
                    set_cached_assets(tags, asset_urls, engine)
                    new_count += 1
                    logger.info("  [%s] %s → %d 条资产(新)", template_name, tags[:60], len(assets))
                except Exception as e:
                    logger.error("  [%s] 查询失败: %s", template_name, e)
                    categorized[template_name] = []

                (cat_dir / f"{template_name}_assets.txt").write_text(
                    "\n".join(categorized[template_name]) + "\n", encoding="utf-8"
                )

            (cat_dir / "categorized_assets.json").write_text(
                json.dumps(categorized, ensure_ascii=False, indent=2), encoding="utf-8"
            )

            total_assets = sum(len(v) for v in categorized.values())
            asset_count = total_assets
            logger.info(
                "增量分类 Step 1: %d 个模板, %d 条资产 (缓存%d, 新增%d)",
                len(categorized), total_assets, cache_count, new_count,
            )

        mark_step_completed(out_dir, None, 1)

        # 汇总全部资产
        assets_out = str(out_dir / f"{engine}_assets.txt")
        all_assets = set()
        cat_dir = out_dir / "categorized"
        if cat_dir.is_dir():
            for f in cat_dir.iterdir():
                if f.name.endswith("_assets.txt"):
                    for line in f.read_text(encoding="utf-8").splitlines():
                        if line.strip():
                            all_assets.add(line.strip())
        Path(assets_out).parent.mkdir(parents=True, exist_ok=True)
        Path(assets_out).write_text("\n".join(sorted(all_assets)) + "\n", encoding="utf-8")
    else:
        asset_count = _count_existing_assets(out_dir)

    # Steps 2-4
    if resume_step <= 2:
        mark_step_started(out_dir, None, 2)
        vuln_count = run_categorized_step2(poc_path, out_dir, task_id,
                                           skip_existing=is_resume,
                                           stop_event=stop_event)
        mark_step_completed(out_dir, None, 2)
    else:
        vuln_count = _count_existing_results(out_dir)

    if resume_step <= 3:
        mark_step_started(out_dir, None, 3)
        host_count = run_categorized_step3(out_dir, task_id=None,
                                           skip_existing=is_resume)
        mark_step_completed(out_dir, None, 3)
    else:
        host_count = _count_existing_hosts(out_dir)

    if resume_step <= 4:
        processed = set(cp.get("step4_templates", [])) if is_resume else None
        mark_step_started(out_dir, None, 4)
        ip_count = run_categorized_step4(out_dir, task_id,
                                         skip_existing=is_resume,
                                         processed_templates=processed,
                                         stop_event=stop_event)
        mark_step_completed(out_dir, None, 4)
    else:
        ip_count = _count_icp_entries(out_dir)

    results = {
        "step1": asset_count,
        "step2": vuln_count,
        "step3": host_count,
        "step4": ip_count,
    }
    logger.info("增量分类扫描完成: %s", results)
    return results

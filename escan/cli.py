"""统一 CLI 入口 — escan 命令

用法：
    escan agent convert <md>              # 单文件转换
    escan agent batch <dir>               # 批量转换
    escan pipeline categorized [<dir>]    # 分类扫描（推荐）
    escan pipeline search <query>         # 单条资产查询
"""

import os
import sys
import time
import argparse
from pathlib import Path

from .logging_config import setup_logging
from .config import POC_DIR


def cmd_agent_convert(args):
    from .agent.converter import convert_one
    setup_logging("escan")
    result = convert_one(args.input, args.output, skip_existing=not args.force)
    if result["skipped"]:
        print(f"跳过 (查重): {result['file']} → {result['matched']} ({result['level']})")
        print("使用 --force 强制重新生成")
    elif not result["success"]:
        sys.exit(1)


def cmd_agent_batch(args):
    from .agent.dedup import DedupIndex, check_batch, should_skip
    from .agent.converter import convert_batch
    setup_logging("escan")

    # 1. 查重检测（与 check 命令复用同一逻辑）
    index = DedupIndex(args.output)
    check_results = check_batch(args.dir, index)

    if not check_results:
        print(f"目录下未找到 .md 文件: {args.dir}")
        return

    # 2. 分类：已匹配（跳过）vs 新增（转换）
    matched = []
    new_files = []
    for r in check_results:
        basename = os.path.basename(r["file"])
        if should_skip(r["match"]):
            matched.append(r)
            print(f"[{r['match']['level_name']}] 跳过 {basename} → {r['match']['matched_id']} ({r['match']['reason']})")
        elif r["match"]["level"] >= 0:
            new_files.append(r)
            if r["match"]["level"] == 0:
                print(f"[无匹配] 待转换 {basename}")
            else:
                print(f"[{r['match']['level_name']}] 仅警告 仍转换 {basename} — {r['match']['reason']}")

    print(f"\n查重结果: {len(matched)} 跳过 / {len(new_files)} 新增")

    if args.force:
        # --force: 全量转换，跳过查重
        new_paths = [r["file"] for r in check_results]
    else:
        new_paths = [r["file"] for r in new_files]

    if not new_paths:
        if not args.force:
            print("没有需要转换的新文件")
        return

    # 3. 只转换目标文档（已预过滤，不再内部查重）
    results = convert_batch(
        args.dir, args.output, args.concurrency,
        skip_existing=False,
        files=new_paths,
    )
    failed = [r for r in results if not r["success"] and not r["skipped"]]
    if failed:
        sys.exit(1)


def cmd_agent_check(args):
    from .agent.dedup import DedupIndex, check_file, check_batch
    setup_logging("escan")

    input_path = args.input

    if os.path.isdir(input_path):
        index = DedupIndex(POC_DIR)
        results = check_batch(input_path, index)

        if not results:
            print(f"目录下未找到 .md 文件: {input_path}")
            return

        matched = 0
        unmatched = 0
        for r in results:
            basename = os.path.basename(r["file"])
            if r["match"]["level"] > 0:
                matched += 1
                print(f"[{r['match']['level_name']}] {basename} → {r['match']['matched_id']} ({r['match']['reason']})")
            else:
                unmatched += 1
                print(f"[无匹配] {basename}")

        print(f"\n总计: {len(results)} 个文件, {matched} 个匹配, {unmatched} 个未匹配")
    else:
        index = DedupIndex(POC_DIR)
        result = check_file(input_path, index)
        match = result["match"]

        print(f"文档: {result['title']}")
        print(f"FOFA: {result['fofa'][:80]}")

        if match["level"] > 0:
            print(f"\n匹配结果: {match['level_name']}")
            print(f"匹配模板: {match['matched_id']}")
            print(f"文件:     {match['matched_file']}")
            print(f"原因:     {match['reason']}")
        else:
            print("\n未匹配到现有模板，可安全转换")


def _latest_output_dir() -> Path | None:
    """查找最新的 output/pipeline/ 时间戳目录。"""
    from .config import OUTPUT_DIR

    pipeline_dir = Path(OUTPUT_DIR) / "pipeline"
    if not pipeline_dir.is_dir():
        return None
    dirs = sorted(
        [d for d in pipeline_dir.iterdir() if d.is_dir()],
        reverse=True,
    )
    return dirs[0] if dirs else None


def cmd_pipeline_categorized(args):
    from .pipeline.orchestrator import (
        run_categorized,
        run_categorized_step1,
        run_categorized_step2,
        run_categorized_step3,
        run_categorized_step4,
    )
    setup_logging("escan")
    poc = args.poc or POC_DIR
    engine = getattr(args, "engine", "fofa")
    step = getattr(args, "step", None)
    out_dir_str = getattr(args, "dir", None)
    do_resume = getattr(args, "resume", False)

    if do_resume and (step or out_dir_str):
        print("错误: --resume 不能与 --step/--dir 同时使用")
        sys.exit(1)

    # --resume：从最新输出目录恢复
    if do_resume:
        latest = _latest_output_dir()
        if not latest:
            print("错误: 未找到已有的输出目录")
            sys.exit(1)
        from .pipeline.checkpoint import load_checkpoint, infer_checkpoint, get_resume_step
        cp = load_checkpoint(latest)
        if cp:
            resume_step = get_resume_step(cp)
            if resume_step is None:
                print(f"所有步骤已完成: {latest}")
                return
            print(f"恢复扫描 ({engine}): {latest} (从 Step {resume_step} 继续)")
        else:
            cp = infer_checkpoint(latest, "categorized", engine, poc)
            resume_step = get_resume_step(cp)
            if resume_step is None:
                print(f"所有步骤已完成 (推断): {latest}")
                return
            print(f"恢复扫描 ({engine}): {latest} (推断: 从 Step {resume_step} 继续)")
        results = run_categorized(poc, engine, resume_from_dir=latest)
        print(f"分类扫描完成: 资产 {results['step1']}, 漏洞 {results['step2']}, "
              f"主机 {results['step3']}, ICP {results['step4']}")
        return

    # 指定目录 → 在该目录上执行单步
    if out_dir_str:
        out_dir = Path(out_dir_str)
        if not out_dir.is_dir():
            print(f"错误: 目录不存在: {out_dir}")
            sys.exit(1)

        step_map = {
            1: lambda: run_categorized_step1(poc, out_dir, engine),
            2: lambda: run_categorized_step2(poc, out_dir),
            3: lambda: run_categorized_step3(out_dir),
            4: lambda: run_categorized_step4(out_dir),
        }

        if step:
            count = step_map[step]()
            step_names = {1: "资产收集", 2: "Nuclei 扫描", 3: "Host 提取", 4: "ICP 查询"}
            print(f"Step {step} ({step_names[step]}) 完成: {count} 条")
        else:
            print("未指定 --step，请指定步骤: --step 1|2|3|4")
        return

    # 指定 step 但无 dir → 找最新输出目录
    if step:
        latest = _latest_output_dir()
        if not latest:
            print("错误: 未找到已有的输出目录，请先执行一次全量分类扫描")
            sys.exit(1)

        out_dir = latest
        print(f"使用最新输出目录: {out_dir}")

        step_map = {
            1: lambda: run_categorized_step1(poc, out_dir, engine),
            2: lambda: run_categorized_step2(poc, out_dir),
            3: lambda: run_categorized_step3(out_dir),
            4: lambda: run_categorized_step4(out_dir),
        }
        count = step_map[step]()
        step_names = {1: "资产收集", 2: "Nuclei 扫描", 3: "Host 提取", 4: "ICP 查询"}
        print(f"Step {step} ({step_names[step]}) 完成: {count} 条")
        return

    # 无 step 无 dir 无 resume → 完整分类扫描
    print(f"分类扫描 ({engine}): 每个模板独立查询+扫描 → {poc}")
    results = run_categorized(poc, engine)
    print(f"分类扫描完成: 资产 {results['step1']}, 漏洞 {results['step2']}, "
          f"主机 {results['step3']}, ICP {results['step4']}")


def cmd_pipeline_categorized_incremental(args):
    from .pipeline.orchestrator import run_categorized_incremental
    setup_logging("escan")
    poc = args.poc or POC_DIR
    engine = getattr(args, "engine", "fofa")
    do_resume = getattr(args, "resume", False)

    if do_resume:
        latest = _latest_output_dir()
        if not latest:
            print("错误: 未找到已有的输出目录")
            sys.exit(1)
        from .pipeline.checkpoint import load_checkpoint, infer_checkpoint, get_resume_step
        cp = load_checkpoint(latest)
        if cp:
            resume_step = get_resume_step(cp)
            if resume_step is None:
                print(f"所有步骤已完成: {latest}")
                return
            print(f"恢复增量扫描 ({engine}): {latest} (从 Step {resume_step} 继续)")
        else:
            cp = infer_checkpoint(latest, "categorized_incremental", engine, poc)
            resume_step = get_resume_step(cp)
            if resume_step is None:
                print(f"所有步骤已完成 (推断): {latest}")
                return
            print(f"恢复增量扫描 ({engine}): {latest} (推断: 从 Step {resume_step} 继续)")
        results = run_categorized_incremental(poc, engine, resume_from_dir=latest)
        if results["step1"] == 0:
            print("全部命中缓存，无新资产")
        else:
            print(f"增量分类扫描完成 ({engine}): 资产 {results['step1']}, 漏洞 {results['step2']}")
        return

    results = run_categorized_incremental(poc, engine)
    if results["step1"] == 0:
        print("全部命中缓存，无新资产")
    else:
        print(f"增量分类扫描完成 ({engine}): 资产 {results['step1']}, 漏洞 {results['step2']}")


def cmd_pipeline_status(args):
    from .pipeline.orchestrator import get_status
    setup_logging("escan")
    stats = get_status()
    print("=== 扫描缓存状态 ===")
    print(f"FOFA 缓存查询:  {stats['fofa_cached_queries']} 条")
    print(f"Hunter 缓存查询: {stats.get('hunter_cached_queries', 0)} 条")
    print(f"已扫描模板:     {stats['templates_scanned']} 个")
    print(f"去重资产:       {stats['unique_assets']} 个")
    print(f"累计命中:       {stats['total_hits']} 条漏洞")

    from .database.connection import get_cursor
    from .database.dao import get_db_stats
    with get_cursor() as cur:
        if cur is not None:
            s = get_db_stats(cur)
            if s:
                print(f"\n=== 数据库统计 ===")
                print(f"POC 模板:     {s.get('template_count', 0)} 条")
                print(f"扫描任务:     {s.get('task_count', 0)} 条")
                print(f"发现资产:     {s.get('asset_count', 0)} 条")
                print(f"扫描结果:     {s.get('vuln_count', 0)} 条")
                print(f"ICP 备案:     {s.get('icp_count', 0)} 条")
                print(f"查询缓存:     {s.get('active_cache_count', 0)} 条活跃 / {s.get('cache_count', 0)} 总计")
                sd = s.get("severity_dist", {})
                if sd:
                    print(f"漏洞分布:     {sd}")
                print(f"Schema 版本: v{s.get('schema_version', 0)}")


def cmd_pipeline_search(args):
    from .pipeline.orchestrator import _resolve_single_query_fn
    from .utils.files import write_output

    setup_logging("escan")
    engine = args.engine
    query_fn = _resolve_single_query_fn(engine)
    assets = query_fn(args.query, args.size)
    ts = time.strftime("%Y%m%d_%H%M%S")
    content = "\n".join(assets) + "\n"
    path = write_output(engine, f"query_{ts}.txt", content)
    print(f"[{engine.upper()}] 查询: {args.query}")
    print(f"结果: {len(assets)} 条资产 → {path}")


def main():
    def cmd_server(args):
        from .web.launcher import launch
        launch()

    parser = argparse.ArgumentParser(
        description="eScan — 漏洞扫描工具链 v2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
子命令:
  escan agent convert <md>        单文件转换（默认跳过已有 POC）
  escan agent convert <md> --force  强制重新生成
  escan agent check <md|dir>      查重检测（支持单文件或目录）
  escan agent batch <dir>         批量转换（默认增量，跳过重复）
  escan agent batch <dir> --force   强制全量生成
  escan pipeline categorized [<poc_dir>]  分类扫描（每模板独立查询+扫描）
  escan pipeline categorized --step 4     对最新结果执行 ICP 分类
  escan pipeline categorized --step 4 --dir <dir>  指定目录执行 ICP
  escan pipeline categorized-incremental [<poc_dir>] 增量分类扫描
  escan pipeline search <query>   单条资产查询（支持 --engine fofa|hunter）
  escan pipeline status           查看扫描缓存状态
  escan server                    启动 Web 服务（API :5050 + 前端 :3000）
        """,
    )
    sub = parser.add_subparsers(dest="command")

    # --- agent ---
    agent_parser = sub.add_parser("agent", help="AI 模板生成")
    agent_sub = agent_parser.add_subparsers(dest="agent_cmd")

    convert_parser = agent_sub.add_parser("convert", help="单文件转换")
    convert_parser.add_argument("input", help="Markdown 漏洞报告")
    convert_parser.add_argument("-o", "--output", default=POC_DIR, help="输出目录")
    convert_parser.add_argument("--force", action="store_true", help="强制重新生成（忽略查重）")
    convert_parser.set_defaults(func=cmd_agent_convert)

    check_parser = agent_sub.add_parser("check", help="查重检测（不生成 POC）")
    check_parser.add_argument("input", help="Markdown 漏洞报告")
    check_parser.set_defaults(func=cmd_agent_check)

    batch_parser = agent_sub.add_parser("batch", help="批量目录转换")
    batch_parser.add_argument("dir", help="包含 .md 文件的目录")
    batch_parser.add_argument("-o", "--output", default=POC_DIR, help="输出目录")
    batch_parser.add_argument("-c", "--concurrency", type=int, default=3, help="并行数")
    batch_parser.add_argument("--force", action="store_true", help="强制全量重新生成（忽略查重）")
    batch_parser.set_defaults(func=cmd_agent_batch)

    # --- pipeline ---
    pipe_parser = sub.add_parser("pipeline", help="扫描流水线")
    pipe_sub = pipe_parser.add_subparsers(dest="pipeline_cmd")

    engine_help = "资产搜索引擎（fofa / hunter），默认 fofa"

    search_parser = pipe_sub.add_parser("search", help="单条资产查询")
    search_parser.add_argument("query", help="查询语句")
    search_parser.add_argument("-s", "--size", type=int, default=100, help="返回数量")
    search_parser.add_argument("--engine", choices=["fofa", "hunter"], default="fofa", help=engine_help)
    search_parser.set_defaults(func=cmd_pipeline_search)

    cat_parser = pipe_sub.add_parser("categorized", help="分类扫描（每模板独立查询+扫描）")
    cat_parser.add_argument("poc", nargs="?", help="POC 模板目录（默认 nuclei-poc/）")
    cat_parser.add_argument("--engine", choices=["fofa", "hunter"], default="fofa", help=engine_help)
    cat_parser.add_argument("--step", type=int, choices=[1, 2, 3, 4],
                            help="仅执行指定步骤（1:资产 2:Nuclei 3:Host 4:ICP）")
    cat_parser.add_argument("--dir", help="指定已有输出目录（配合 --step 使用）")
    cat_parser.add_argument("--resume", action="store_true", help="从最新输出目录自动恢复中断的扫描")
    cat_parser.set_defaults(func=cmd_pipeline_categorized)

    cat_incr_parser = pipe_sub.add_parser(
        "categorized-incremental", help="增量分类扫描（跳过缓存）"
    )
    cat_incr_parser.add_argument("poc", nargs="?", help="POC 模板目录（默认 nuclei-poc/）")
    cat_incr_parser.add_argument("--engine", choices=["fofa", "hunter"], default="fofa", help=engine_help)
    cat_incr_parser.add_argument("--resume", action="store_true", help="从最新输出目录自动恢复中断的增量扫描")
    cat_incr_parser.set_defaults(func=cmd_pipeline_categorized_incremental)

    status_parser = pipe_sub.add_parser("status", help="查看扫描缓存状态")
    status_parser.set_defaults(func=cmd_pipeline_status)

    # --- server ---
    server_parser = sub.add_parser("server", help="启动 Web 服务（API + 前端）")
    server_parser.set_defaults(func=cmd_server)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

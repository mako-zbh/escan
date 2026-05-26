#!/usr/bin/env python3
"""
数据库初始化脚本 — 创建数据库并执行所有迁移。

用法:
    uv run python scripts/init_db.py            # 使用 .env 配置
    uv run python scripts/init_db.py --create   # 先 CREATE DATABASE 再迁移
    uv run python scripts/init_db.py --drop     # 删除旧库后重建
"""

import os
import sys
from pathlib import Path

# 确保项目根在 sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

from escan.config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
from escan.database.models import MIGRATIONS, get_current_version


def _connect(dbname: str = "postgres"):
    """连接到 PostgreSQL，返回连接。"""
    kwargs = dict(host=DB_HOST, port=DB_PORT, user=DB_USER)
    if DB_PASSWORD:
        kwargs["password"] = DB_PASSWORD
    conn = psycopg2.connect(dbname=dbname, **kwargs)
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    return conn


def create_database():
    """创建数据库（如不存在）。"""
    print(f"连接: {DB_HOST}:{DB_PORT} 用户: {DB_USER}")
    conn = _connect("postgres")
    cur = conn.cursor()
    cur.execute(
        "SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,)
    )
    if cur.fetchone():
        print(f"数据库 {DB_NAME} 已存在，跳过创建")
    else:
        cur.execute(f'CREATE DATABASE "{DB_NAME}"')
        print(f"数据库 {DB_NAME} 已创建")
    cur.close()
    conn.close()


def drop_database():
    """删除数据库。"""
    conn = _connect("postgres")
    cur = conn.cursor()
    cur.execute(
        "SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,)
    )
    if cur.fetchone():
        cur.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = %s AND pid <> pg_backend_pid()",
            (DB_NAME,),
        )
        cur.execute(f'DROP DATABASE "{DB_NAME}"')
        print(f"数据库 {DB_NAME} 已删除")
    else:
        print(f"数据库 {DB_NAME} 不存在")
    cur.close()
    conn.close()


def run_migrations():
    """连接目标数据库，执行所有迁移。"""
    conn = _connect(DB_NAME)
    cur = conn.cursor()

    current = get_current_version(cur)
    print(f"当前 Schema 版本: v{current}")

    if current >= len(MIGRATIONS):
        print("已是最新版本，无需迁移")
        cur.close()
        conn.close()
        return

    for version, description, sql in MIGRATIONS:
        if version > current:
            print(f"执行迁移 v{version}: {description} ... ", end="", flush=True)
            cur.execute(sql)
            cur.execute(
                "INSERT INTO schema_version (version, description) VALUES (%s, %s)",
                (version, description),
            )
            print("OK")

    print(f"迁移完成: v{current} → v{len(MIGRATIONS)}")
    cur.close()
    conn.close()


def print_status():
    """打印数据库当前状态。"""
    conn = _connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("SELECT COALESCE(MAX(version), 0) FROM schema_version")
    version = cur.fetchone()[0]
    print(f"Schema 版本: v{version} / 最新: v{len(MIGRATIONS)}")
    print()

    tables = [
        "poc_templates", "scan_tasks", "discovered_assets", "scan_results",
        "host_results", "icp_results", "query_cache", "dedup_index",
        "scan_logs", "checkpoint_snapshots", "template_scan_coverage",
        "template_icp_stats", "global_url_registry",
    ]
    print(f"{'表名':<30} {'行数':>8}")
    print("-" * 40)
    for t in tables:
        try:
            cur.execute(f"SELECT COUNT(*) FROM {t}")
            count = cur.fetchone()[0]
            print(f"{t:<30} {count:>8}")
        except Exception:
            print(f"{t:<30} {'(不存在)':>8}")

    cur.close()
    conn.close()


def main():
    args = sys.argv[1:]

    if not DB_HOST or not DB_PASSWORD:
        print("错误: 请在 .env 中配置 DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD")
        sys.exit(1)

    if "--drop" in args:
        drop_database()
        create_database()
    elif "--create" in args:
        create_database()
    elif "--status" in args:
        print_status()
        return

    run_migrations()
    print()
    print_status()


if __name__ == "__main__":
    main()

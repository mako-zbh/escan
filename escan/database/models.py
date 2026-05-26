"""数据库 DDL — 建表 + 迁移系统。

用法:
    from ..database.connection import get_cursor
    with get_cursor() as cur:
        init_db(cur)    # 创建所有表
        migrate(cur)    # 增量迁移
"""

from ..logging_config import get_logger

logger = get_logger("database.models")

# --- 迁移列表: (version, description, sql) ---

MIGRATIONS = [
    (1, "Initial schema: 8 tables", """
-- 1. POC 模板（精简：仅 id + name + severity）
CREATE TABLE IF NOT EXISTS poc_templates (
    template_id  TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    severity     TEXT,
    tags         TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_poc_severity ON poc_templates(severity);
CREATE INDEX IF NOT EXISTS idx_poc_created  ON poc_templates(created_at DESC);

-- 2. 扫描任务
CREATE TABLE IF NOT EXISTS scan_tasks (
    task_id       UUID PRIMARY KEY,
    task_type     TEXT NOT NULL,
    engine        TEXT NOT NULL DEFAULT 'fofa',
    status        TEXT NOT NULL DEFAULT 'running',
    step1_assets  INTEGER DEFAULT 0,
    step2_vulns   INTEGER DEFAULT 0,
    step3_hosts   INTEGER DEFAULT 0,
    step4_icp     INTEGER DEFAULT 0,
    output_dir    TEXT,
    error_message TEXT,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_tasks_type    ON scan_tasks(task_type);
CREATE INDEX IF NOT EXISTS idx_tasks_status  ON scan_tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_started ON scan_tasks(started_at DESC);

-- 3. 发现资产
CREATE TABLE IF NOT EXISTS discovered_assets (
    asset_id      UUID PRIMARY KEY,
    task_id       UUID NOT NULL REFERENCES scan_tasks(task_id) ON DELETE CASCADE,
    template_id   TEXT NOT NULL REFERENCES poc_templates(template_id) ON DELETE CASCADE,
    url           TEXT NOT NULL,
    host          TEXT,
    port          INTEGER,
    scheme        TEXT DEFAULT 'http',
    title         TEXT,
    engine        TEXT NOT NULL DEFAULT 'fofa',
    query_used    TEXT,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(task_id, template_id, url)
);
CREATE INDEX IF NOT EXISTS idx_assets_task     ON discovered_assets(task_id);
CREATE INDEX IF NOT EXISTS idx_assets_template ON discovered_assets(template_id);
CREATE INDEX IF NOT EXISTS idx_assets_host     ON discovered_assets(host);
CREATE INDEX IF NOT EXISTS idx_assets_url      ON discovered_assets(url);
CREATE INDEX IF NOT EXISTS idx_assets_engine   ON discovered_assets(engine);

-- 4. 扫描结果
CREATE TABLE IF NOT EXISTS scan_results (
    result_id    UUID PRIMARY KEY,
    task_id      UUID NOT NULL REFERENCES scan_tasks(task_id) ON DELETE CASCADE,
    template_id  TEXT NOT NULL REFERENCES poc_templates(template_id) ON DELETE CASCADE,
    asset_id     UUID REFERENCES discovered_assets(asset_id) ON DELETE SET NULL,
    protocol     TEXT,
    severity     TEXT,
    matched_url  TEXT NOT NULL,
    raw_line     TEXT,
    scanned_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_results_task     ON scan_results(task_id);
CREATE INDEX IF NOT EXISTS idx_results_template ON scan_results(template_id);
CREATE INDEX IF NOT EXISTS idx_results_asset    ON scan_results(asset_id);
CREATE INDEX IF NOT EXISTS idx_results_severity ON scan_results(severity);
CREATE INDEX IF NOT EXISTS idx_results_scanned  ON scan_results(scanned_at DESC);

-- 5. ICP 备案
CREATE TABLE IF NOT EXISTS icp_results (
    icp_result_id UUID PRIMARY KEY,
    task_id       UUID NOT NULL REFERENCES scan_tasks(task_id) ON DELETE CASCADE,
    ip_address    TEXT,
    domain        TEXT,
    icp_number    TEXT,
    source        TEXT NOT NULL DEFAULT 'aizhan',
    icp_api       JSONB,
    queried_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_icp_task      ON icp_results(task_id);
CREATE INDEX IF NOT EXISTS idx_icp_ip        ON icp_results(ip_address);
CREATE INDEX IF NOT EXISTS idx_icp_domain    ON icp_results(domain);
CREATE INDEX IF NOT EXISTS idx_icp_number    ON icp_results(icp_number);

-- 6. 查询缓存
CREATE TABLE IF NOT EXISTS query_cache (
    query_hash   TEXT PRIMARY KEY,
    query_string TEXT NOT NULL,
    engine       TEXT NOT NULL DEFAULT 'fofa',
    assets       JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON query_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_cache_engine  ON query_cache(engine);

-- 7. 去重索引
CREATE TABLE IF NOT EXISTS dedup_index (
    template_id TEXT PRIMARY KEY REFERENCES poc_templates(template_id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    tags        TEXT,
    cve_list    JSONB DEFAULT '[]'::jsonb,
    method      TEXT DEFAULT 'GET',
    path        TEXT,
    fofa_hash   TEXT,
    path_hash   TEXT,
    file_path   TEXT,
    indexed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dedup_cve       ON dedup_index USING gin(cve_list);
CREATE INDEX IF NOT EXISTS idx_dedup_fofa_hash ON dedup_index(fofa_hash);
CREATE INDEX IF NOT EXISTS idx_dedup_path_hash ON dedup_index(path_hash);

-- 8. 迁移版本
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT
);
"""),

(2, "Add dedup constraints + host_results table", """
-- scan_results 去重：同一任务同一模板同一 URL 不重复
CREATE UNIQUE INDEX IF NOT EXISTS idx_results_dedup
    ON scan_results(task_id, template_id, matched_url);

-- Step 3 主机提取结果表
CREATE TABLE IF NOT EXISTS host_results (
    host_result_id UUID PRIMARY KEY,
    task_id        UUID NOT NULL REFERENCES scan_tasks(task_id) ON DELETE CASCADE,
    template_name  TEXT NOT NULL,
    host           TEXT NOT NULL,
    is_ip          BOOLEAN DEFAULT false,
    extracted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(task_id, template_name, host)
);
CREATE INDEX IF NOT EXISTS idx_host_results_task     ON host_results(task_id);
CREATE INDEX IF NOT EXISTS idx_host_results_template ON host_results(template_name);
CREATE INDEX IF NOT EXISTS idx_host_results_host     ON host_results(host);

-- icp_results 去重：同一任务同一 IP+域名 不重复
CREATE UNIQUE INDEX IF NOT EXISTS idx_icp_dedup
    ON icp_results(task_id, ip_address, domain);
"""),

(3, "Add checkpoint_snapshots for scan resume", """
CREATE TABLE IF NOT EXISTS checkpoint_snapshots (
    task_id      UUID PRIMARY KEY REFERENCES scan_tasks(task_id) ON DELETE CASCADE,
    output_dir   TEXT NOT NULL,
    scan_type    TEXT NOT NULL,
    engine       TEXT NOT NULL DEFAULT 'fofa',
    state        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""),

(4, "Schema refinement: coverage, ICP stats, URL registry, FOFA linking, materialized views", """
-- === Part 1: ALTER existing tables ===

ALTER TABLE poc_templates
    ADD COLUMN IF NOT EXISTS file_path TEXT,
    ADD COLUMN IF NOT EXISTS fofa_query TEXT,
    ADD COLUMN IF NOT EXISTS api_truncated BOOLEAN DEFAULT FALSE;

ALTER TABLE scan_tasks
    ADD COLUMN IF NOT EXISTS total_templates INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS templates_with_hits INTEGER DEFAULT 0;

ALTER TABLE discovered_assets
    ADD COLUMN IF NOT EXISTS url_hash TEXT,
    ADD COLUMN IF NOT EXISTS response_status INTEGER;

ALTER TABLE host_results
    ADD COLUMN IF NOT EXISTS template_id TEXT;

ALTER TABLE query_cache
    ADD COLUMN IF NOT EXISTS template_id TEXT,
    ADD COLUMN IF NOT EXISTS result_count INTEGER,
    ADD COLUMN IF NOT EXISTS truncated BOOLEAN DEFAULT FALSE;

-- === Part 2: New tables ===

CREATE TABLE IF NOT EXISTS template_scan_coverage (
    coverage_id      UUID PRIMARY KEY,
    task_id          UUID NOT NULL REFERENCES scan_tasks(task_id) ON DELETE CASCADE,
    template_id      TEXT NOT NULL REFERENCES poc_templates(template_id) ON DELETE CASCADE,
    has_assets       BOOLEAN NOT NULL DEFAULT FALSE,
    asset_count      INTEGER NOT NULL DEFAULT 0,
    was_scanned      BOOLEAN NOT NULL DEFAULT FALSE,
    hits_found       INTEGER NOT NULL DEFAULT 0,
    hosts_extracted  INTEGER NOT NULL DEFAULT 0,
    icp_queried      BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE(task_id, template_id)
);
CREATE INDEX IF NOT EXISTS idx_coverage_task ON template_scan_coverage(task_id);
CREATE INDEX IF NOT EXISTS idx_coverage_template ON template_scan_coverage(template_id);
CREATE INDEX IF NOT EXISTS idx_coverage_was_scanned ON template_scan_coverage(was_scanned);

CREATE TABLE IF NOT EXISTS template_icp_stats (
    icp_stats_id         UUID PRIMARY KEY,
    task_id              UUID NOT NULL REFERENCES scan_tasks(task_id) ON DELETE CASCADE,
    template_id          TEXT NOT NULL REFERENCES poc_templates(template_id) ON DELETE CASCADE,
    ips_queried          INTEGER NOT NULL DEFAULT 0,
    ips_with_data        INTEGER NOT NULL DEFAULT 0,
    domains_found        INTEGER NOT NULL DEFAULT 0,
    domains_with_icp     INTEGER NOT NULL DEFAULT 0,
    icp_api_supplement   INTEGER NOT NULL DEFAULT 0,
    UNIQUE(task_id, template_id)
);
CREATE INDEX IF NOT EXISTS idx_icp_stats_task ON template_icp_stats(task_id);
CREATE INDEX IF NOT EXISTS idx_icp_stats_template ON template_icp_stats(template_id);

CREATE TABLE IF NOT EXISTS global_url_registry (
    url_hash        TEXT PRIMARY KEY,
    canonical_url   TEXT NOT NULL,
    first_seen_task UUID REFERENCES scan_tasks(task_id) ON DELETE SET NULL,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    template_count  INTEGER NOT NULL DEFAULT 1,
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_url_registry_first_task ON global_url_registry(first_seen_task);
CREATE INDEX IF NOT EXISTS idx_url_registry_template_count ON global_url_registry(template_count DESC);

-- === Part 3: New indexes on modified columns ===

CREATE INDEX IF NOT EXISTS idx_poc_fofa_query ON poc_templates(fofa_query);
CREATE INDEX IF NOT EXISTS idx_assets_url_hash ON discovered_assets(url_hash);
CREATE INDEX IF NOT EXISTS idx_host_results_template_id ON host_results(template_id);
CREATE INDEX IF NOT EXISTS idx_cache_template ON query_cache(template_id);
CREATE INDEX IF NOT EXISTS idx_cache_truncated ON query_cache(truncated);

-- === Part 4: Materialized views ===

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_task_summary AS
SELECT
    t.task_id, t.task_type, t.engine, t.status, t.started_at, t.completed_at,
    t.total_templates, t.templates_with_hits,
    COUNT(DISTINCT da.template_id) FILTER (WHERE da.asset_id IS NOT NULL) AS templates_with_assets,
    COUNT(DISTINCT da.asset_id) AS total_assets,
    COUNT(DISTINCT da.url_hash) AS unique_urls,
    COUNT(DISTINCT sr.result_id) AS total_vulnerabilities,
    COUNT(DISTINCT hr.host) AS unique_hosts,
    COUNT(DISTINCT icp.icp_result_id) AS total_icp_entries,
    COUNT(DISTINCT tsc.template_id) FILTER (WHERE tsc.was_scanned AND tsc.hits_found = 0) AS templates_scanned_no_hits,
    COUNT(DISTINCT tsc.template_id) FILTER (WHERE NOT tsc.was_scanned AND tsc.has_assets) AS templates_with_assets_not_scanned
FROM scan_tasks t
LEFT JOIN discovered_assets da ON da.task_id = t.task_id
LEFT JOIN scan_results sr ON sr.task_id = t.task_id
LEFT JOIN host_results hr ON hr.task_id = t.task_id
LEFT JOIN icp_results icp ON icp.task_id = t.task_id
LEFT JOIN template_scan_coverage tsc ON tsc.task_id = t.task_id
GROUP BY t.task_id;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_template_effectiveness AS
SELECT
    pt.template_id, pt.name, pt.severity, pt.fofa_query,
    COUNT(DISTINCT tsc.task_id) AS tasks_scanned,
    SUM(tsc.asset_count) AS total_assets_found,
    SUM(tsc.hits_found) AS total_hits,
    CASE WHEN SUM(tsc.asset_count) > 0
         THEN ROUND(SUM(tsc.hits_found)::NUMERIC / SUM(tsc.asset_count) * 100, 1)
         ELSE 0
    END AS hit_rate_pct
FROM poc_templates pt
LEFT JOIN template_scan_coverage tsc ON tsc.template_id = pt.template_id
GROUP BY pt.template_id, pt.name, pt.severity, pt.fofa_query
ORDER BY total_hits DESC;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_cross_template_urls AS
SELECT
    gur.url_hash, gur.canonical_url, gur.template_count,
    gur.first_seen_at, gur.last_seen_at,
    array_agg(DISTINCT da.template_id ORDER BY da.template_id) AS template_ids
FROM global_url_registry gur
JOIN discovered_assets da ON da.url_hash = gur.url_hash
WHERE gur.template_count > 1
GROUP BY gur.url_hash, gur.canonical_url, gur.template_count, gur.first_seen_at, gur.last_seen_at
ORDER BY gur.template_count DESC;
"""),

(5, "Add scan_logs table + current_step on scan_tasks", """
CREATE TABLE IF NOT EXISTS scan_logs (
    id          BIGSERIAL PRIMARY KEY,
    task_id     UUID NOT NULL REFERENCES scan_tasks(task_id) ON DELETE CASCADE,
    step        INTEGER,
    level       TEXT NOT NULL DEFAULT 'INFO',
    message     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scan_logs_task ON scan_logs(task_id, created_at);

ALTER TABLE scan_tasks
    ADD COLUMN IF NOT EXISTS current_step INTEGER DEFAULT 0;
"""),

(6, "Add template_id + asset_id to icp_results for direct linkage", """
ALTER TABLE icp_results
    ADD COLUMN IF NOT EXISTS template_id TEXT,
    ADD COLUMN IF NOT EXISTS asset_id UUID REFERENCES discovered_assets(asset_id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_icp_template_id ON icp_results(template_id);
CREATE INDEX IF NOT EXISTS idx_icp_asset_id ON icp_results(asset_id);
"""),

]


def get_current_version(cursor) -> int:
    cursor.execute("SELECT COALESCE(MAX(version), 0) FROM schema_version")
    row = cursor.fetchone()
    return row[0] if row else 0


def init_db(cursor):
    """创建所有表（IF NOT EXISTS 安全重复执行）。"""
    for v, desc, sql in MIGRATIONS:
        cursor.execute(sql)
    logger.info("数据库表初始化完成")


def migrate(cursor):
    """增量迁移：只执行新版本。"""
    current = get_current_version(cursor)
    applied = 0
    for version, description, sql in MIGRATIONS:
        if version > current:
            cursor.execute(sql)
            cursor.execute(
                "INSERT INTO schema_version (version, description) VALUES (%s, %s)",
                (version, description),
            )
            logger.info("迁移 v%d: %s", version, description)
            applied += 1
    if applied == 0:
        logger.info("数据库已是最新版本 (v%d)", current)

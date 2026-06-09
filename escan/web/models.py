"""Pydantic request/response models for the eScan API."""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field


# --- Scan ---

class ScanTriggerRequest(BaseModel):
    type: str = Field(default="categorized", description="Scan type: categorized / categorized-incremental")
    engine: str = Field(default="fofa", pattern=r"^(fofa|hunter)$")
    poc: str | None = None
    region: str = ""
    size: int = Field(default=100, ge=1, le=10000, description="每模板资产数")


class ScanTriggerResponse(BaseModel):
    task_id: str
    status: str = "started"


# --- Tasks ---

class TaskResponse(BaseModel):
    task_id: str
    task_type: str
    engine: str
    status: str
    current_step: int
    step1_assets: int
    step2_vulns: int
    step3_hosts: int
    step4_icp: int
    output_dir: str | None = None
    error_message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


class TaskListResponse(BaseModel):
    items: list[TaskResponse]
    total: int


# --- Stats ---

class StatsResponse(BaseModel):
    template_count: int = 0
    task_count: int = 0
    asset_count: int = 0
    vuln_count: int = 0
    host_count: int = 0
    icp_count: int = 0
    cache_count: int = 0
    active_cache_count: int = 0
    schema_version: int = 0
    severity_dist: dict[str, int] = Field(default_factory=dict)
    recent_tasks: list[dict] = Field(default_factory=list)


# --- Templates ---

class TemplateItem(BaseModel):
    template_id: str
    name: str
    severity: str | None = None
    fofa_query: str | None = None
    file_path: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    asset_count: int = 0
    hit_count: int = 0
    domain_count: int = 0
    icp_count: int = 0


class TemplateListResponse(BaseModel):
    items: list[TemplateItem]
    total: int
    limit: int
    offset: int


class TemplateDetailResponse(BaseModel):
    template_id: str
    name: str
    severity: str | None = None
    tags: str | None = None
    fofa_query: str | None = None
    file_path: str | None = None
    api_truncated: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None
    tasks: list[dict] = Field(default_factory=list)
    icp_summary: dict = Field(default_factory=dict)


# --- Assets / URLs ---

class AssetResponse(BaseModel):
    asset_id: str
    task_id: str
    url: str
    host: str | None = None
    port: int | None = None
    scheme: str | None = None
    title: str | None = None
    engine: str | None = None
    discovered_at: datetime | None = None
    icp_number: str | None = None
    icp_company: str | None = None
    icp_domain: str | None = None


# --- Hosts ---

class HostResponse(BaseModel):
    host_result_id: str
    task_id: str
    template_name: str
    host: str
    is_ip: bool = False
    extracted_at: datetime | None = None


# --- ICP ---

class ICPResultResponse(BaseModel):
    icp_result_id: str
    task_id: str
    ip_address: str | None = None
    domain: str | None = None
    icp_number: str | None = None
    source: str | None = None
    company: str | None = None
    queried_at: datetime | None = None
    asset_id: str | None = None


class ICPQueryRequest(BaseModel):
    search: str = Field(min_length=1)


class ICPQueryResponse(BaseModel):
    items: list[dict] = Field(default_factory=list)
    total: int = 0
    search: str = ""


# --- Vulnerabilities ---

class VulnerabilityItem(BaseModel):
    vuln_name: str | None = None
    severity: str | None = None
    asset: str | None = None
    scanned_at: datetime | None = None
    icp_domain: str | None = None
    icp_number: str | None = None
    icp_company: str | None = None


class VulnerabilityListResponse(BaseModel):
    items: list[VulnerabilityItem]
    total: int
    limit: int
    offset: int


class VulnResultResponse(BaseModel):
    result_id: str
    task_id: str
    protocol: str | None = None
    severity: str | None = None
    matched_url: str
    raw_line: str | None = None
    scanned_at: datetime | None = None


# --- Scan Logs ---

class ScanLogResponse(BaseModel):
    id: int
    task_id: str
    step: int | None = None
    level: str = "INFO"
    message: str
    created_at: datetime | None = None


# --- Config ---

class ConfigResponse(BaseModel):
    path: str
    content: str


class ConfigUpdateRequest(BaseModel):
    content: str


class ConfigUpdateResponse(BaseModel):
    path: str
    saved: bool = True
    backup: str = ""


# --- Generic ---

class ErrorResponse(BaseModel):
    error: str


class MessageResponse(BaseModel):
    message: str


class DeleteScanResponse(BaseModel):
    task_id: str
    deleted: dict[str, int]


class DeleteLogsResponse(BaseModel):
    task_id: str
    deleted: int


class StopScanResponse(BaseModel):
    task_id: str
    status: str


# --- SSE ---

class SSEProgressEvent(BaseModel):
    step: int | None = None
    message: str
    current: int | None = None
    total: int | None = None


class SSELogEvent(BaseModel):
    id: int
    step: int | None = None
    level: str = "INFO"
    message: str
    created_at: str | None = None


# --- Proxy Pool ---

class ProxyStatusItem(BaseModel):
    url: str
    failures: int = 0
    in_cooldown: bool = False
    cooldown_remaining: float = 0


class ProxyStatusResponse(BaseModel):
    total: int = 0
    available: int = 0
    in_cooldown: int = 0
    strategy: str = "round_robin"
    cooldown_seconds: float = 60
    max_failures: int = 3
    proxies: list[ProxyStatusItem] = Field(default_factory=list)
    toggles: dict = Field(default_factory=dict)
    file_path: str = ""
    pool_loaded: bool = False


class ProxyTestRequest(BaseModel):
    url: str = Field(min_length=5)


class ProxyTestResponse(BaseModel):
    url: str
    success: bool
    latency_ms: float = 0
    error: str | None = None


class ProxyBatchTestRequest(BaseModel):
    urls: list[str] = Field(min_length=1, description="待测试的代理 URL 列表")


class ProxyBatchAddRequest(BaseModel):
    urls: list[str] = Field(min_length=1, description="待添加的代理 URL 列表")
    test_before_add: bool = Field(default=False, description="验证通过后才添加")


class ProxyBatchTestResponse(BaseModel):
    results: list[ProxyTestResponse]
    total: int
    success_count: int
    fail_count: int


class ProxyAddRequest(BaseModel):
    url: str = Field(min_length=5)


class ProxyRemoveRequest(BaseModel):
    url: str


class ProxyToggleRequest(BaseModel):
    fofa: bool | None = None
    hunter: bool | None = None
    nuclei: bool | None = None
    icp: bool | None = None
    deepseek: bool | None = None

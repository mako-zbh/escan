"""POC 查重与增量引擎 — MD 文档与现有 YAML 模板的多级匹配。

四级匹配：
  L1: CVE 编号完全一致 (99%)  — 直接跳过
  L2: FOFA tags + 请求路径一致 (95%) — 跳过
  L3: FOFA tags 一致 (80%) — 默认跳过
  L4: 标题相似度 > 0.8 (60%) — 仅警告，不跳过
"""

import hashlib
import re
from difflib import SequenceMatcher
from pathlib import Path

from ..config import POC_DIR
from ..logging_config import get_logger

logger = get_logger("agent.dedup")

# 匹配结果级别
MATCH_NONE = 0
MATCH_CVE = 1       # L1
MATCH_FOFA_PATH = 2  # L2
MATCH_FOFA = 3       # L3
MATCH_TITLE = 4      # L4 (仅警告)

LEVEL_NAMES = {1: "L1-CVE", 2: "L2-FOFA+Path", 3: "L3-FOFA", 4: "L4-Title"}


def _clean_quotes(s: str) -> str:
    """智能去除首尾配对引号，保留内部的引号（如 FOFA body=\"...\"）。"""
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        return s[1:-1]
    return s


class DedupIndex:
    """现有 YAML 模板的查重索引。优先从数据库加载，数据库不可用时回退到文件扫描。"""

    def __init__(self, poc_dir: str = POC_DIR):
        self._poc_dir = poc_dir
        self.by_id: dict[str, dict] = {}
        self.by_cve: dict[str, list[str]] = {}
        self.by_fofa: dict[str, list[str]] = {}
        self.by_path: dict[str, list[str]] = {}
        self._build(poc_dir)

    def _build(self, poc_dir: str) -> None:
        """构建索引：优先从数据库加载，否则扫描 YAML 文件。"""
        if self._load_from_db():
            logger.info(
                "Dedup 索引 (DB): %d 模板, %d CVE, %d FOFA, %d Path",
                len(self.by_id), len(self.by_cve),
                len(self.by_fofa), len(self.by_path),
            )
            return

        self._load_from_files(poc_dir)

    def _load_from_db(self) -> bool:
        """从数据库 dedup_index 表加载索引。仅对默认 POC_DIR 使用 DB。"""
        if self._poc_dir != POC_DIR:
            return False
        from ..database.connection import get_cursor
        from ..database.dao import load_dedup_index

        with get_cursor() as cur:
            if cur is None:
                return False
            entries = load_dedup_index(cur)
            if not entries:
                return False

            for e in entries:
                tid = e["id"]
                cve_list = e.get("cve_list") or []
                # psycopg2 自动解析 JSONB 为 list，但字符串需要处理
                if isinstance(cve_list, str):
                    import json
                    cve_list = json.loads(cve_list)

                entry = {
                    "id": tid,
                    "name": e.get("name", ""),
                    "tags": e.get("tags", ""),
                    "method": e.get("method", "GET"),
                    "path": e.get("path", ""),
                    "cve_list": cve_list,
                    "file": e.get("file", ""),
                }
                self.by_id[tid] = entry

                for cve in cve_list:
                    self.by_cve.setdefault(cve, []).append(tid)

                fofa_hash = e.get("fofa_hash")
                if fofa_hash:
                    self.by_fofa.setdefault(fofa_hash, []).append(tid)

                method = e.get("method", "GET")
                path = e.get("path", "")
                if method and path:
                    path_key = f"{method}:{path}"
                    self.by_path.setdefault(path_key, []).append(tid)

            return True

    def _load_from_files(self, poc_dir: str) -> None:
        """扫描 YAML 文件构建索引，并同步到数据库。"""
        poc_path = Path(poc_dir)
        if not poc_path.is_dir():
            return

        entries = []
        for yaml_file in sorted(poc_path.glob("*.yaml")):
            if yaml_file.stat().st_size < 50:
                continue
            entry = self._index_one(yaml_file)
            if entry:
                entries.append(entry)

        logger.info(
            "Dedup 索引 (文件): %d 模板, %d CVE, %d FOFA, %d Path",
            len(self.by_id), len(self.by_cve),
            len(self.by_fofa), len(self.by_path),
        )

        if entries and self._poc_dir == POC_DIR:
            self._sync_to_db(entries)

    @staticmethod
    def _sync_to_db(entries: list[dict]) -> None:
        """将索引条目同步到数据库。"""
        from ..database.connection import get_cursor
        from ..database.dao import upsert_poc_template, rebuild_dedup_index

        with get_cursor() as cur:
            if cur is None:
                return
            # 先确保 poc_templates 有记录（FK 约束）
            for e in entries:
                upsert_poc_template(cur, {
                    "template_id": e["id"],
                    "name": e["name"],
                    "severity": e.get("severity"),
                    "tags": e.get("tags"),
                })
            count = rebuild_dedup_index(cur, entries)
            logger.info("Dedup 索引同步至 DB: %d 条", count)

    def _index_one(self, filepath: Path) -> dict | None:
        """索引单个 YAML 文件。"""
        try:
            text = filepath.read_text(encoding="utf-8")
        except Exception:
            return None

        tid = self._extract(text, r"^id:\s*(.+)")
        if not tid:
            return None

        name = self._extract(text, r"^\s*name:\s*(.+)") or ""
        tags = self._extract(text, r"^\s*tags:\s*(.+)") or ""
        method = self._extract(text, r"^\s*(?:-\s*)?method:\s*(.+)") or "GET"
        path = self._extract(text, r'^\s*(?:-\s*)?"\s*\{\{BaseURL\}\}(.+?)"') or ""

        cve_list = list(set(re.findall(r"CVE-\d{4}-\d{4,}", name + " " + text)))

        tags_clean = _clean_quotes(tags)
        method_clean = method.upper()
        path_clean = path.strip('"').strip("'")

        fofa_hash = _hash(tags_clean) if tags_clean else ""
        path_key = f"{method_clean}:{path_clean}" if method_clean and path_clean else ""
        path_hash = _hash(path_key) if path_key else ""

        entry = {
            "id": tid,
            "name": _clean_quotes(name),
            "tags": tags_clean,
            "method": method_clean,
            "path": path_clean,
            "cve_list": cve_list,
            "file": str(filepath),
            "fofa_hash": fofa_hash,
            "path_hash": path_hash,
        }

        self.by_id[tid] = entry

        for cve in cve_list:
            self.by_cve.setdefault(cve, []).append(tid)

        if fofa_hash:
            self.by_fofa.setdefault(fofa_hash, []).append(tid)

        if path_key:
            self.by_path.setdefault(path_key, []).append(tid)

        return entry

    @staticmethod
    def _extract(text: str, pattern: str) -> str:
        m = re.search(pattern, text, re.MULTILINE)
        return m.group(1).strip() if m else ""


def _hash(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()[:12]


def _parse_md_features(md_content: str) -> dict:
    """从 MD 文档中提取用于查重的特征。"""
    # 标题
    title = ""
    title_m = re.search(r"^#\s+(.+)", md_content, re.MULTILINE)
    if title_m:
        title = title_m.group(1).strip()

    # FOFA 语法
    fofa = ""
    fofa_m = re.search(r"##\s*Fofa[^\n]*\n+(.+?)(?=\n##\s|\Z)", md_content, re.MULTILINE | re.DOTALL)
    if fofa_m:
        fofa = fofa_m.group(1).strip()

    # CVE
    cve_list = re.findall(r"CVE-\d{4}-\d{4,}", md_content)

    # 请求方法和路径（从 POC 表格中提取）
    method = "GET"
    path = ""
    poc_section = False
    for line in md_content.split("\n"):
        if "## 漏洞POC" in line:
            poc_section = True
            continue
        if poc_section:
            if line.startswith("## "):
                break
            # 匹配 HTTP 方法 + 路径
            m = re.match(r"\|?\s*(GET|POST|PUT|DELETE)\s+(\S+)", line, re.IGNORECASE)
            if m:
                method = m.group(1).upper()
                path = m.group(2)
                break

    return {
        "title": title,
        "fofa": fofa,
        "cve_list": cve_list,
        "method": method,
        "path": path,
    }


def check_dedup(md_content: str, index: DedupIndex) -> dict:
    """对 MD 文档执行四级查重匹配。

    Returns:
        {
            "level": int,          # 0=无匹配, 1-4=匹配级别
            "level_name": str,     # 级别名称
            "matched_id": str,     # 匹配到的模板 ID（如有）
            "matched_file": str,   # 匹配到的 YAML 文件路径
            "reason": str,         # 匹配原因描述
        }
    """
    feats = _parse_md_features(md_content)
    result = {"level": MATCH_NONE, "level_name": "", "matched_id": "", "matched_file": "", "reason": ""}

    # L1: CVE 编号
    for cve in feats["cve_list"]:
        if cve in index.by_cve:
            tid = index.by_cve[cve][0]
            entry = index.by_id[tid]
            result.update(
                level=MATCH_CVE,
                level_name=LEVEL_NAMES[MATCH_CVE],
                matched_id=tid,
                matched_file=entry["file"],
                reason=f"CVE 一致: {cve} → {tid}",
            )
            return result

    # L2: FOFA + 路径
    if feats["fofa"]:
        tag_hash = _hash(feats["fofa"])
        fofa_ids = set(index.by_fofa.get(tag_hash, []))
        path_key = f"{feats['method']}:{feats['path']}"
        path_ids = set(index.by_path.get(path_key, []))

        intersection = fofa_ids & path_ids
        if intersection:
            tid = sorted(intersection)[0]
            entry = index.by_id[tid]
            result.update(
                level=MATCH_FOFA_PATH,
                level_name=LEVEL_NAMES[MATCH_FOFA_PATH],
                matched_id=tid,
                matched_file=entry["file"],
                reason=f"FOFA + 路径一致: {path_key} → {tid}",
            )
            return result

    # L3: 仅 FOFA
    if feats["fofa"]:
        tag_hash = _hash(feats["fofa"])
        if tag_hash in index.by_fofa:
            tid = index.by_fofa[tag_hash][0]
            entry = index.by_id[tid]
            result.update(
                level=MATCH_FOFA,
                level_name=LEVEL_NAMES[MATCH_FOFA],
                matched_id=tid,
                matched_file=entry["file"],
                reason=f"FOFA 一致: {feats['fofa'][:60]} → {tid}",
            )
            return result

    # L4: 标题相似度（仅提示，不跳过）
    if feats["title"]:
        best_score = 0
        best_tid = ""
        for tid, entry in index.by_id.items():
            score = SequenceMatcher(None, feats["title"].lower(), entry["name"].lower()).ratio()
            if score > best_score:
                best_score = score
                best_tid = tid

        if best_score > 0.8:
            entry = index.by_id[best_tid]
            result.update(
                level=MATCH_TITLE,
                level_name=LEVEL_NAMES[MATCH_TITLE],
                matched_id=best_tid,
                matched_file=entry["file"],
                reason=f"标题相似度 {best_score:.0%}: '{feats['title'][:40]}' ≈ '{entry['name'][:40]}' → {best_tid}",
            )
            return result

    return result


def should_skip(match_result: dict) -> bool:
    """根据匹配级别判断是否应跳过生成。L1-L3 跳过，L4 仅警告。"""
    return match_result["level"] in (MATCH_CVE, MATCH_FOFA_PATH, MATCH_FOFA)


def check_file(md_path: str, index: DedupIndex) -> dict:
    """对单个 MD 文件执行查重检测，返回文件信息 + 匹配结果。"""
    with open(md_path, encoding="utf-8") as f:
        md_content = f.read()

    match = check_dedup(md_content, index)
    feats = _parse_md_features(md_content)

    return {
        "file": md_path,
        "title": feats["title"],
        "fofa": feats["fofa"],
        "match": match,
    }


def check_batch(input_dir: str, index: DedupIndex | None = None) -> list[dict]:
    """对目录下所有 .md 文件执行查重检测，返回结果列表。"""
    import os

    if index is None:
        index = DedupIndex()

    md_files = sorted(
        os.path.join(input_dir, f)
        for f in os.listdir(input_dir)
        if f.endswith(".md")
    )

    return [check_file(md, index) for md in md_files]

"""修复现有 POC YAML 中被 AI 错误写入的分类标签 → 用 markdown 源的 FOFA 语句替换。

用法:
    uv run python scripts/fix_existing_tags.py --dry-run    # 预览，不写文件
    uv run python scripts/fix_existing_tags.py              # 执行修复
"""

import os
import re
import sys
import yaml
from difflib import SequenceMatcher
from pathlib import Path

POC_DIR = Path(__file__).resolve().parent.parent / "nuclei-poc"
MD_DIR = Path("/Users/zbh/Documents/project/js/yuque-dl/download/Day漏洞库（2026）/漏洞库-2026年1月-12月(未分类)")

# FOFA 合法查询判断
_FOFA_FIELD_RE = re.compile(
    r'(?:^|[|&()\s])(body|title|header|cert|domain|host|ip|port|protocol|server'
    r'|country|region|city|os|app|banner|base_protocol|icon_hash'
    r'|product|product_version|icp|asn|org)\s*[=!]',
    re.IGNORECASE,
)
_QUOTED_RE = re.compile(r"^['\"].*['\"]$")


def md_title_to_yaml_id(title: str) -> str:
    """将中文标题转为 yaml id 风格: 全小写英文+连字符"""
    # 提取 CVE 编号
    cve_m = re.search(r"CVE-\d{4}-\d{4,}", title)
    cve = cve_m.group(0).lower() if cve_m else ""

    # 提取英文产品名
    en_parts = re.findall(r"[A-Za-z][A-Za-z0-9._-]{2,}", title)
    en_name = "-".join(p.lower().rstrip("._-") for p in en_parts)

    # 提取中文关键词用于生成简拼
    cn_parts = re.findall(r"[一-鿿]{2,}", title)

    # 生成一些候选匹配键
    candidates = []
    if cve:
        candidates.append(cve)
    if en_name:
        candidates.append(en_name)
    # 纯中文标题
    cn_clean = re.sub(r"[^一-鿿]", "", title)
    if cn_clean:
        candidates.append(cn_clean[:8])

    return candidates


def build_md_index(md_dir: Path) -> list[dict]:
    """构建 markdown 文件索引: [(filename, title, fofa_query, full_path), ...]"""
    index = []
    for f in sorted(md_dir.iterdir()):
        if not f.suffix == ".md":
            continue
        content = f.read_text(encoding="utf-8")

        # 提取标题
        title_m = re.search(r"^#\s+(.+)", content, re.MULTILINE)
        title = title_m.group(1).strip() if title_m else f.stem

        # 提取 FOFA 查询
        fofa = ""
        fofa_m = re.search(
            r"##\s*Fofa[^\n]*\n+(.+?)(?=\n##\s|\Z)",
            content, re.MULTILINE | re.DOTALL,
        )
        if fofa_m:
            fofa = fofa_m.group(1).strip()

        index.append({
            "filename": f.name,
            "title": title,
            "fofa": fofa,
            "path": str(f),
        })
    return index


def _normalize(s: str) -> str:
    """激进标准化：去空格、去标点、全小写，保留中英文字符。"""
    return re.sub(r"[\s\-_.：:，,（）()【】\[\]{}]", "", s).lower()


def find_best_match(yaml_name: str, yaml_id: str, md_index: list[dict]) -> dict | None:
    """为 YAML 模板找到最佳匹配的 markdown 文件。

    匹配策略（按优先级）：
    1. 标准化后 YAML id 是 MD 文件名的子串（反之亦然）
    2. CVE 编号完全匹配
    3. YAML info.name 与 MD 标题的相似度
    4. 提取 YAML id 中的关键词在 MD 文件名中
    """
    best_score = 0
    best_md = None

    yaml_norm = _normalize(yaml_name)
    yaml_id_norm = _normalize(yaml_id)

    # 从 YAML name/id 中提取 CVE 编号
    yaml_cve = set(re.findall(r"CVE-\d{4}-\d{4,}", yaml_name + yaml_id, re.IGNORECASE))

    for md in md_index:
        md_name_norm = _normalize(md["filename"])
        md_cve = set(re.findall(r"CVE-\d{4}-\d{4,}", md["filename"] + md["title"], re.IGNORECASE))

        # 策略 1: 标准化后的 id 互相包含
        if yaml_id_norm and len(yaml_id_norm) > 4:
            if yaml_id_norm in md_name_norm or md_name_norm in yaml_id_norm:
                best_md = md
                best_score = 1.0
                break  # 精确匹配，直接返回

        # 策略 2: CVE 编号匹配
        if yaml_cve and md_cve and yaml_cve & md_cve:
            score = 0.98
            if score > best_score:
                best_score = score
                best_md = md
            continue

        # 策略 3: 名称相似度
        name_score = SequenceMatcher(None, yaml_norm, md_name_norm).ratio()
        title_score = SequenceMatcher(None, yaml_name, md["title"]).ratio()
        score = max(name_score, title_score)

        if score > best_score:
            best_score = score
            best_md = md

    if best_score >= 0.65 and best_md:
        return best_md
    return None


def is_valid_fofa(tags: str) -> bool:
    """检查 tags 是否已是合法的 FOFA 查询语句。"""
    if not tags or not tags.strip():
        return False
    tags = tags.strip()
    if tags in ('""', "''"):
        return False
    if _FOFA_FIELD_RE.search(tags):
        return True
    if _QUOTED_RE.match(tags):
        return True
    return False


def inject_fofa_into_yaml_file(yaml_path: str, fofa_query: str) -> bool:
    """直接修改 YAML 文件的 tags 行，写入 FOFA 查询语句。"""
    with open(yaml_path, encoding="utf-8") as f:
        content = f.read()

    if "'" in fofa_query:
        quoted = fofa_query.replace('"', '\\"')
        tags_line = f'tags: "{quoted}"'
    else:
        tags_line = f"tags: '{fofa_query}'"

    new_content = re.sub(
        r'^(\s*)tags\s*:\s*.*$',
        rf'\1{tags_line}',
        content,
        count=1,
        flags=re.MULTILINE,
    )

    if new_content == content:
        return False  # 没变化

    with open(yaml_path, "w", encoding="utf-8") as f:
        f.write(new_content)
    return True


def main():
    dry_run = "--dry-run" in sys.argv

    md_index = build_md_index(MD_DIR)
    print(f"Markdown 索引: {len(md_index)} 个文件")

    fixed = 0
    matched = 0
    unmatched = 0
    already_ok = 0

    for f in sorted(POC_DIR.glob("*.yaml")):
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue

        if not isinstance(doc, dict):
            continue

        info = doc.get("info", {})
        tags = info.get("tags", "")
        name = info.get("name", "")
        yaml_id = doc.get("id", "")

        if not isinstance(tags, str):
            tags = ""
        tags = tags.strip()

        # 已经是合法 FOFA → 跳过
        if is_valid_fofa(tags):
            already_ok += 1
            continue

        # 找匹配的 markdown
        md = find_best_match(name, yaml_id, md_index)
        if not md or not md["fofa"]:
            unmatched += 1
            print(f"未匹配: {f.name}  (name={name[:40]}  tags={tags[:50]})")
            continue

        matched += 1

        if dry_run:
            print(f"[DRY-RUN] {f.name}")
            print(f"  MD:  {md['filename']}")
            print(f"  旧:  {tags[:70]}")
            print(f"  新:  {md['fofa'][:70]}")
        else:
            ok = inject_fofa_into_yaml_file(str(f), md["fofa"])
            if ok:
                fixed += 1
                print(f"已修复: {f.name}  ← {md['filename']}")
            else:
                print(f"无变化: {f.name}")

    print(f"\n===== 汇总 =====")
    print(f"已合法:           {already_ok}")
    print(f"匹配并修复:       {fixed if not dry_run else matched} (dry-run)")
    print(f"匹配到但无 FOFA:  {unmatched}")
    print(f"文件总数:         {already_ok + matched + unmatched}")

    if dry_run:
        print("\n使用 'uv run python scripts/fix_existing_tags.py' 执行实际修复")


if __name__ == "__main__":
    main()

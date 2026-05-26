"""核心转换器 — Markdown 漏洞报告 → Nuclei YAML 模板"""

import os
import re
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import yaml as _yaml

from ..config import (
    DEEPSEEK_API,
    DEEPSEEK_API_KEY,
    DEEPSEEK_MODEL,
    POC_DIR,
    AGENT_CONCURRENCY,
)
from ..logging_config import get_logger
from ..utils.retry import retry
from ..utils.files import write_output
from .prompts import build_system_prompt, load_examples_by_type, classify_vuln
from .ocr import ocr_markdown_images, extract_images_base64
from .validator import validate_and_retry
from .dedup import DedupIndex, check_dedup, should_skip

logger = get_logger("agent.converter")


# --- Markdown 解析 ---

def parse_markdown(md_content: str) -> dict:
    """解析漏洞报告 markdown，提取标题、FOFA语法、POC、状态码。"""
    result = {"title": "", "fofa": "", "poc": "", "status": ""}

    title_m = re.search(r"^#\s+(.+)", md_content, re.MULTILINE)
    if title_m:
        result["title"] = title_m.group(1).strip()

    fofa_m = re.search(r"##\s*Fofa[^\n]*\n+(.+?)(?=\n##\s|\Z)", md_content, re.MULTILINE | re.DOTALL)
    if fofa_m:
        result["fofa"] = fofa_m.group(1).strip()

    # POC 表格解析
    poc_lines = []
    in_poc = False
    for line in md_content.split("\n"):
        if "## 漏洞POC" in line:
            in_poc = True
            continue
        if in_poc:
            if line.startswith("## "):
                break
            cleaned = re.sub(r"^\|?\s*", "", line)
            cleaned = re.sub(r"\s*\|?\s*$", "", cleaned)
            cleaned = cleaned.replace("<br/>", "\n").replace("<br>", "\n")
            if cleaned and cleaned != "---":
                poc_lines.append(cleaned)
    result["poc"] = "\n".join(poc_lines)

    status_m = re.search(r"##\s*响应代码特征\s*\n(\d+)", md_content, re.MULTILINE)
    if status_m:
        result["status"] = status_m.group(1).strip()

    return result


# --- DeepSeek API ---

@retry(max_retries=3, base_delay=2.0, max_delay=30.0)
def call_deepseek(messages: list[dict]) -> str:
    """调用 DeepSeek API 生成 YAML 模板。"""
    if not DEEPSEEK_API_KEY:
        raise RuntimeError("请设置 DEEPSEEK_API_KEY 环境变量")

    payload = {
        "model": DEEPSEEK_MODEL,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 8192,
        "thinking": {"type": "enabled"},
    }

    resp = requests.post(
        DEEPSEEK_API,
        json=payload,
        headers={
            "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
            "Content-Type": "application/json",
        },
        timeout=180,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"DeepSeek API {resp.status_code}: {resp.text[:500]}")
    return resp.json()["choices"][0]["message"]["content"]


def extract_yaml(response: str) -> str:
    """从 API 回复中提取 YAML 代码块。"""
    pattern = re.compile(r"```ya?ml\s*(.+?)```", re.DOTALL)
    m = pattern.search(response)
    if m:
        return m.group(1).strip()
    return response.strip()


def extract_id(yaml_content: str, fallback: str) -> str:
    """从 YAML 的 id 字段提取文件名标识。"""
    id_match = re.search(r"^id:\s*(.+)", yaml_content, re.MULTILINE)
    return id_match.group(1).strip() if id_match else fallback


# --- 消息构建 ---

def build_messages(
    md_content: str,
    md_dir: str,
    use_vision: bool = False,
) -> list[dict]:
    """构建 DeepSeek API messages。

    三种模式：
    - vision:  图片 base64 直发 DeepSeek（需要 vision 模型）
    - ocr:     GLM-OCR 提取文字后发给 DeepSeek
    - text:    纯文本，根据漏洞类型推断关键词
    """
    info = parse_markdown(md_content)
    vuln_type = classify_vuln(info["title"], info["poc"])
    examples = load_examples_by_type(vuln_type)
    system_msg = build_system_prompt(info["title"], info["poc"], examples)

    if use_vision:
        images = extract_images_base64(md_content, md_dir)
        vision_note = "请识别下面的响应截图中返回的内容关键词（通常高亮标记），作为 matchers 的 word 匹配词。"
    else:
        images = []
        ocr_text = ocr_markdown_images(md_content, md_dir)
        if ocr_text:
            vision_note = (
                "以下是响应截图的 OCR 识别结果，请从中提取关键词作为 matchers 的 word 匹配词：\n"
                + ocr_text
            )
        else:
            vision_note = (
                "根据漏洞类型和请求上下文，推断响应中可能出现的关键词作为 matchers 匹配词。"
                "一般 SQL 注入回显会包含数据库错误信息、字段名、或 UNION SELECT 返回的标记值。"
            )

    user_text = f"""# 漏洞名称
{info['title']}

# FOFA 语法
{info['fofa']}

# 原始 HTTP 请求
{info['poc']}

# 响应状态码
{info['status']}

# 漏洞类型
{vuln_type}

# 响应关键词识别
{vision_note}"""

    content = [{"type": "text", "text": user_text}] + images
    user_content = content if len(content) > 1 else user_text

    return [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": user_content},
    ]


# --- 转换入口 ---

def _inject_tags(yaml_content: str, fofa_query: str | None) -> str:
    """将 YAML 中的 tags 字段强制替换为原始 markdown 的 FOFA 查询语句。

    防止 AI 在 tags 中填入分类标签（如 cve,sqli）而非 FOFA 语法。
    """
    if not fofa_query or not fofa_query.strip():
        return yaml_content

    fofa = fofa_query.strip()

    # 确定 YAML 引号策略：优先单引号（FOFA 中双引号更常见）
    if "'" in fofa:
        # 含单引号 → 用双引号包裹，内部双引号转义
        quoted = fofa.replace('"', '\\"')
        tags_line = f'tags: "{quoted}"'
    else:
        tags_line = f"tags: '{fofa}'"

    return re.sub(
        r'^(\s*)tags\s*:\s*.*$',
        rf'\1{tags_line}',
        yaml_content,
        count=1,
        flags=re.MULTILINE,
    )


def convert_one(
    md_path: str,
    output_dir: str = POC_DIR,
    skip_existing: bool = True,
    dedup_index: DedupIndex | None = None,
) -> dict:
    """转换单个 MD 文件为 Nuclei YAML 模板。

    Args:
        md_path:       Markdown 文件路径
        output_dir:    YAML 输出目录
        skip_existing: 是否跳过已有 POC（查重 + 增量）
        dedup_index:   共享的去重索引（批量模式复用）

    Returns:
        {"file": md_path, "output": yaml_path, "success": bool,
         "skipped": bool, "matched": str, "level": str, "error": str}
    """
    result = {
        "file": md_path, "output": "", "success": False,
        "skipped": False, "matched": "", "level": "", "error": "",
    }

    try:
        md_dir = os.path.dirname(os.path.abspath(md_path))
        with open(md_path, encoding="utf-8") as f:
            md_content = f.read()

        basename = os.path.splitext(os.path.basename(md_path))[0]

        # 提取原始 FOFA 查询语句，用于强制写入 YAML 的 tags 字段
        md_info = parse_markdown(md_content)
        fofa_query = md_info.get("fofa", "")

        # --- 查重检查（调用 API 之前） ---
        if skip_existing:
            if dedup_index is None:
                dedup_index = DedupIndex(output_dir)
            match = check_dedup(md_content, dedup_index)
            if should_skip(match):
                logger.info(
                    "跳过 (查重 %s): %s → %s",
                    match["level_name"], basename, match["matched_id"],
                )
                result["skipped"] = True
                result["matched"] = match["matched_id"]
                result["level"] = match["level_name"]
                return result
            elif match["level"] == 4:
                logger.warning("标题相似 (L4): %s — %s", basename, match["reason"])

        use_vision = "chat" in DEEPSEEK_MODEL.lower()
        logger.info("转换: %s (模式: %s)", basename,
                     "vision" if use_vision else "OCR+text")

        # 构建消息并调用 API
        messages = build_messages(md_content, md_dir, use_vision)
        response = call_deepseek(messages)
        yaml_content = _inject_tags(extract_yaml(response), fofa_query)

        # 提取 id 作为文件名
        template_id = extract_id(yaml_content, basename)
        output_path = os.path.join(output_dir, f"{template_id}.yaml")
        os.makedirs(output_dir, exist_ok=True)

        # 校验并在失败时重试
        def regenerate(error_msg: str) -> str:
            messages.append({
                "role": "user",
                "content": f"上一次生成的 YAML 校验失败：{error_msg}\n请修正后重新生成完整的 YAML。",
            })
            new_response = call_deepseek(messages)
            return _inject_tags(extract_yaml(new_response), fofa_query)

        final_yaml = validate_and_retry(yaml_content, output_path, regenerate)
        if final_yaml is None:
            failed_path = write_output("_failed", f"{template_id}.yaml", yaml_content)
            result["error"] = f"YAML 校验失败，原始内容已保存至 {failed_path}"
            logger.error(result["error"])
            return result

        # 原子写入：先写临时文件，再 rename（线程安全）
        tmp_path = output_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(final_yaml + "\n")
        os.replace(tmp_path, output_path)

        logger.info("已生成: %s", output_path)
        result["output"] = output_path
        result["success"] = True

    except Exception as e:
        logger.error("转换失败: %s — %s", os.path.basename(md_path), e)
        result["error"] = str(e)

    return result


def convert_batch(
    input_dir: str,
    output_dir: str = POC_DIR,
    concurrency: int = AGENT_CONCURRENCY,
    skip_existing: bool = True,
    files: list[str] | None = None,
) -> list[dict]:
    """并行批量转换目录下的 .md 文件。

    Args:
        input_dir:     包含 .md 文件的目录
        output_dir:    YAML 输出目录
        concurrency:   并行度（默认 3）
        skip_existing: 是否查重跳过（默认开）
        files:         要处理的文件列表，None 则自动扫描 input_dir

    Returns:
        结果列表，每项含 file/output/success/skipped/matched/level/error
    """
    if files is not None:
        md_files = sorted(files)
    else:
        md_files = sorted(
            os.path.join(input_dir, f)
            for f in os.listdir(input_dir)
            if f.endswith(".md")
        )

    if not md_files:
        logger.warning("目录下未找到 .md 文件: %s", input_dir)
        return []

    # 预构建去重索引（所有线程共享）
    dedup_index = DedupIndex(output_dir) if skip_existing else None

    logger.info(
        "批量转换 %d 个文件，并发数: %d, 查重: %s",
        len(md_files), concurrency,
        "开" if skip_existing else "关",
    )

    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {
            executor.submit(
                convert_one, md, output_dir, skip_existing, dedup_index
            ): md
            for md in md_files
        }
        for future in as_completed(futures):
            results.append(future.result())

    # 统计
    ok = sum(1 for r in results if r["success"])
    skipped = sum(1 for r in results if r["skipped"])
    fail = sum(1 for r in results if not r["success"] and not r["skipped"])

    logger.info(
        "批量转换完成: 成功 %d, 跳过(查重) %d, 失败 %d",
        ok, skipped, fail,
    )

    if skipped:
        logger.info("跳过的文件:")
        for r in results:
            if r["skipped"]:
                logger.info("  - %s → %s (%s)", r["file"], r["matched"], r["level"])

    if fail:
        logger.warning("失败文件:")
        for r in results:
            if not r["success"] and not r["skipped"]:
                logger.warning("  - %s: %s", r["file"], r["error"])

    return results

"""YAML 模板校验 — 调用 nuclei -validate"""

import re
import subprocess
import os

from ..logging_config import get_logger
from ..utils.network import find_nuclei

logger = get_logger("agent.validator")

# nuclei 启动时会在 stderr 输出 banner（ASCII art + 版本号），校验错误需要过滤掉
_NUCLEI_BANNER_PATTERNS = [
    r"^\s*__\s+_\s*$",
    r"^\s*_\|_\|_\\__,_\\___/_\\___/_/",
    r"^\s*projectdiscovery\.io",
    r"^\s*\[VER\]\s",
    r"^\s*\[INF\]\s",
    r"^\s*\[WRN\]\s",
    r"^\s*\[DBG\]\s",
]


def _clean_error(stderr: str, stdout: str) -> str:
    """从 nuclei 输出中提取真正的校验错误，过滤掉 banner 和日志噪音。"""
    lines = (stderr + stdout).split("\n")
    error_lines = []
    for line in lines:
        # 去掉 ANSI 转义码
        clean = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
        if not clean:
            continue
        if any(re.match(p, clean) for p in _NUCLEI_BANNER_PATTERNS):
            continue
        if clean.startswith(("___", "/ _", "/ /", "/_/", "  / _", "  / /", "  /_/", "  \\___")):
            continue
        if re.match(r"^\[(VER|INF|WRN|DBG)\]\s", clean):
            continue
        error_lines.append(clean)
    return "\n".join(error_lines) if error_lines else (stderr or stdout)


def validate_yaml(filepath: str) -> tuple[bool, str]:
    """使用 nuclei 校验 YAML 模板。

    Returns:
        (is_valid, error_message)
    """
    try:
        nuclei = find_nuclei()
    except FileNotFoundError as e:
        logger.warning("nuclei 未找到，跳过校验: %s", e)
        return True, ""  # 没有 nuclei 时不阻塞生成

    # nuclei 2.x: -templates-validate, 3.x: -validate
    for flag in ("-validate", "-templates-validate"):
        result = subprocess.run(
            [nuclei, flag, "-t", filepath],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            continue  # 此 flag 存在且成功
        # 检查是否是 "unknown flag" 错误
        if any(kw in (result.stderr + result.stdout).lower() for kw in ("unknown flag", "flag provided but not defined")):
            continue
        # 真正的校验错误，过滤掉 banner
        return False, _clean_error(result.stderr, result.stdout)

    return True, ""


def validate_and_retry(
    yaml_content: str,
    output_path: str,
    regenerate_fn,
    max_attempts: int = 2,
) -> str | None:
    """校验 YAML，校验失败则重新生成。

    Args:
        yaml_content:   初始 YAML 内容
        output_path:    预期的输出路径
        regenerate_fn:  重新生成函数，返回新 YAML 内容
        max_attempts:   最多重新生成次数

    Returns:
        最终 YAML 内容，或 None（全部失败时）
    """
    # 先写入临时文件
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(yaml_content + "\n")

    for attempt in range(max_attempts + 1):
        is_valid, error = validate_yaml(output_path)
        if is_valid:
            logger.info("YAML 校验通过: %s", os.path.basename(output_path))
            return yaml_content

        logger.warning(
            "YAML 校验失败 (第 %d 次): %s → %s",
            attempt + 1,
            os.path.basename(output_path),
            error[:200],
        )

        if attempt < max_attempts:
            logger.info("重新调用 DeepSeek 生成...")
            try:
                yaml_content = regenerate_fn(error)
            except Exception as e:
                logger.error("重新生成失败: %s", e)
        else:
            logger.error(
                "YAML 校验 %d 次后仍失败，移至 _failed/: %s",
                max_attempts + 1,
                os.path.basename(output_path),
            )
            return None

    return None

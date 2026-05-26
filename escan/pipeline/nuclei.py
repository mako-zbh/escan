"""Nuclei 扫描器 — 调用 nuclei CLI"""

import subprocess
import os

from ..logging_config import get_logger
from ..utils.network import find_nuclei

logger = get_logger("pipeline.nuclei")


def scan(
    target_file: str,
    template: str,
    output_file: str,
    concurrency: int = 20,
    severity: str | None = None,
    extra_args: list[str] | None = None,
) -> int:
    """调用 nuclei 执行扫描。

    Returns:
        nuclei 进程退出码
    """
    nuclei = find_nuclei()

    cmd = [
        nuclei,
        "-l", target_file,
        "-t", template,
        "-o", output_file,
        "-c", str(concurrency),
        "-silent",
    ]
    if severity:
        cmd.extend(["-s", severity])
    if extra_args:
        cmd.extend(extra_args)

    logger.info("执行 nuclei: %s", " ".join(cmd))

    result = subprocess.run(cmd, check=False, text=True, capture_output=True)
    if result.stdout:
        logger.debug(result.stdout.strip())
    if result.stderr:
        logger.warning(result.stderr.strip())
    if result.returncode != 0:
        logger.warning("nuclei 退出码 %d", result.returncode)

    # 统计结果
    if os.path.isfile(output_file):
        with open(output_file, encoding="utf-8") as f:
            count = sum(1 for _ in f if _.strip())
        logger.info("Nuclei 扫描完成: 发现 %d 个漏洞 → %s", count, output_file)
    else:
        logger.info("Nuclei 扫描完成: 未发现漏洞")

    return result.returncode

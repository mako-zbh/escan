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
    # 前置校验：模板路径必须存在，否则跳过（不再调用 nuclei）
    if not os.path.isfile(template):
        logger.warning("跳过扫描：模板文件不存在 → %s", template)
        return 1

    # 前置校验：目标文件不能为空
    if not os.path.isfile(target_file) or os.path.getsize(target_file) == 0:
        logger.warning("跳过扫描：目标文件为空或不存在 → %s", target_file)
        return 1

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

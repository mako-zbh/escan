"""GLM-OCR 本地图片识别"""

import re
import os
import base64

import requests

from ..config import GLM_OCR_API
from ..logging_config import get_logger
from ..utils.retry import retry

logger = get_logger("agent.ocr")


@retry(max_retries=2, base_delay=3.0)
def ocr_image(image_path: str, prompt: str = "OCR") -> str:
    """使用本地 GLM-OCR 模型识别图片中的文字。

    Args:
        image_path: 图片绝对路径
        prompt:     OCR 提示词，默认 "OCR"

    Returns:
        识别出的文字内容
    """
    with open(image_path, "rb") as f:
        b64 = base64.b64encode(f.read()).decode("utf-8")

    ext = os.path.splitext(image_path)[1].lower()
    mime = "image/png" if ext == ".png" else "image/jpeg"

    payload = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:{mime};base64,{b64}"},
                    },
                    {"type": "text", "text": prompt},
                ],
            }
        ]
    }

    resp = requests.post(
        GLM_OCR_API,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=180,
    )
    resp.raise_for_status()

    if not resp.text or not resp.text.strip():
        raise RuntimeError("OCR 服务返回空响应，可能正在处理其他请求")

    return resp.json()["choices"][0]["message"]["content"]


def ocr_markdown_images(md_content: str, md_dir: str) -> str:
    """对 markdown 中的所有截图运行 OCR，返回汇总文字。

    Returns:
        格式化的 OCR 结果字符串，供 DeepSeek prompt 使用。
        如果没有图片或全部失败，返回空字符串。
    """
    pattern = re.compile(r"!\[.*?\]\((.*?)\)")
    results = []

    for match in pattern.finditer(md_content):
        img_rel = match.group(1)
        img_abs = (
            os.path.join(md_dir, img_rel)
            if not os.path.isabs(img_rel)
            else img_rel
        )
        if not os.path.isfile(img_abs):
            logger.warning("图片不存在，跳过: %s", img_abs)
            continue

        try:
            logger.info("OCR 识别: %s", os.path.basename(img_abs))
            text = ocr_image(img_abs)
            if text:
                results.append(f"--- 截图: {os.path.basename(img_abs)} ---\n{text}")
                logger.info("OCR 结果: %s...", text[:120])
        except Exception as e:
            logger.error("OCR 失败: %s → %s", os.path.basename(img_abs), e)

    return "\n\n".join(results)


def extract_images_base64(md_content: str, md_dir: str) -> list[dict]:
    """从 markdown 提取图片，转为 vision API 所需的 base64 data URL 格式。"""
    images = []
    pattern = re.compile(r"!\[.*?\]\((.*?)\)")
    for match in pattern.finditer(md_content):
        img_rel = match.group(1)
        img_abs = (
            os.path.join(md_dir, img_rel)
            if not os.path.isabs(img_rel)
            else img_rel
        )
        if not os.path.isfile(img_abs):
            logger.warning("图片不存在，跳过: %s", img_abs)
            continue

        ext = os.path.splitext(img_abs)[1].lower()
        mime = (
            "image/png"
            if ext == ".png"
            else "image/jpeg"
            if ext in (".jpg", ".jpeg")
            else "image/png"
        )

        with open(img_abs, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("utf-8")

        images.append({
            "type": "image_url",
            "image_url": {"url": f"data:{mime};base64,{b64}"},
        })
        logger.info("已加载图片: %s (%dKB)", os.path.basename(img_abs), len(b64) // 1024)

    return images

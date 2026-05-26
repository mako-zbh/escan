"""网络工具 — IP 校验、URL 解析"""

import re
import shutil
from ..config import NUCLEI_PATH


def is_ipv4(s: str) -> bool:
    """校验字符串是否为合法 IPv4 地址。"""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except (ValueError, TypeError):
        return False


def extract_host_port(url: str) -> tuple[str, str, int]:
    """从 URL 中提取 (scheme, hostname, port)。

    >>> extract_host_port("https://example.com:8443/path")
    ('https', 'example.com', 8443)
    >>> extract_host_port("192.168.1.1:8080")
    ('http', '192.168.1.1', 8080)
    """
    if "://" not in url:
        url = f"http://{url}"

    scheme = url.split("://")[0].lower()
    host_part = url.split("://")[1].split("/")[0]

    if ":" in host_part:
        host, port_str = host_part.rsplit(":", 1)
        port = int(port_str)
    else:
        host = host_part
        port = 443 if scheme == "https" else 80

    return scheme, host, port


def find_nuclei() -> str:
    """定位 nuclei 二进制路径。"""
    if NUCLEI_PATH:
        return NUCLEI_PATH
    found = shutil.which("nuclei")
    if found:
        return found
    raise FileNotFoundError(
        "无法找到 nuclei 二进制。请设置 NUCLEI_PATH 环境变量，"
        "或安装 nuclei: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    )


def _strip_markdown_fence(content: str) -> str:
    """去掉可能的 markdown 代码块包裹（````yaml ... ```）。"""
    content = content.strip()
    if content.startswith("```"):
        # 去掉首行的 ```yaml 或 ```
        lines = content.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        # 去掉末行的 ```
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        content = "\n".join(lines)
    return content


_TAGS_LINE_RE = re.compile(r'^\s*tags\s*:\s*(.+)', re.MULTILINE)


def _extract_tags_by_regex(content: str) -> str | None:
    """当 PyYAML 解析失败时，用正则降级提取 tags 行。"""
    m = _TAGS_LINE_RE.search(content)
    if not m:
        return None
    raw = m.group(1).strip()

    # 去掉首尾配对引号
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ('"', "'"):
        raw = raw[1:-1]

    # 处理 YAML 转义：\\" → ", \\' → '
    raw = raw.replace('\\"', '"').replace("\\'", "'")

    return raw if raw else None


_ID_LINE_RE = re.compile(r'^id\s*:\s*(.+)', re.MULTILINE)


def extract_yaml_id(filepath: str) -> str | None:
    """从 Nuclei YAML 模板提取 id 字段。先 PyYAML，失败则正则降级。"""
    import yaml

    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    try:
        doc = yaml.safe_load(content)
        if isinstance(doc, dict) and isinstance(doc.get("id"), str):
            return doc["id"].strip()
    except yaml.YAMLError:
        pass

    # 正则降级
    clean = _strip_markdown_fence(content)
    m = _ID_LINE_RE.search(clean)
    if m:
        raw = m.group(1).strip()
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ('"', "'"):
            raw = raw[1:-1]
        return raw if raw else None
    return None


def extract_tags_from_yaml(filepath: str) -> str | None:
    """从 Nuclei YAML 模板的 info.tags 字段提取 FOFA 查询语法。

    容错策略：PyYAML 解析 → 失败时用正则降级提取 tags 行。
    """
    import yaml

    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    # 1. 尝试 PyYAML 标准解析
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        doc = None

    if isinstance(doc, dict):
        info = doc.get("info", {})
        if isinstance(info, dict):
            tags = info.get("tags")
            if tags is not None:
                if isinstance(tags, str):
                    return _normalize_fofa_query(tags.strip())
                if isinstance(tags, list):
                    parts = []
                    for t in tags:
                        s = str(t).strip()
                        if not s:
                            continue
                        n = _normalize_fofa_query(s)
                        if n:
                            parts.append(n)
                    return " || ".join(parts) if parts else None

    # 2. PyYAML 失败或未提取到 tags → 降级：正则提取
    # 先去掉可能的 markdown 代码块包裹
    clean_content = _strip_markdown_fence(content) if doc is None else content
    raw_tags = _extract_tags_by_regex(clean_content)
    if raw_tags:
        return _normalize_fofa_query(raw_tags)

    return None


# FOFA 字段操作符模式，用于区分合法查询和分类标签
_FOFA_FIELD_RE = re.compile(
    r'(?:^|[|&()\s])('
    r'body|title|header|cert|domain|host|ip|port|protocol|server'
    r'|country|region|city|os|app|banner|base_protocol|icon_hash'
    r'|product|product_version|icp|asn|org'
    r')\s*[=!]',
    re.IGNORECASE,
)

# 逗号分隔的纯标识符（分类标签，非 FOFA 查询）
_TAG_LIST_RE = re.compile(r'^[a-zA-Z0-9\-_.]+(\s*,\s*[a-zA-Z0-9\-_.]+)*$')

# 完整引号包裹（FOFA 全局字符串搜索）
_QUOTED_RE = re.compile(r'^["\'].*["\']$')


def _normalize_fofa_query(tags: str) -> str | None:
    """将 tags 值标准化为合法的 FOFA 查询语法。

    - 含 FOFA 字段操作符（body=, title= 等） → 修正后返回
    - 引号包裹的搜索字符串（如 "D-Link-DIR"） → 原样返回
    - 逗号分隔的分类标签（cve,sqli） → 转为 body="cve" || body="sqli"
    - 空白标签 → 返回 None
    - 纯文本（BMC Footprints） → 包装为 body="..." 查询
    """
    if not tags or not tags.strip():
        return None

    tags = tags.strip()

    # 空引号或占位文本
    if tags in ('""', "''", "暂无", "无", "null", "NULL", "暂无FOFA"):
        return None

    # 修正常见 FOFA 语法错误：== → =
    _DOUBLE_EQ_RE = re.compile(
        r'(body|title|header|cert|domain|host|ip|port|protocol|server'
        r'|country|region|city|os|app|banner|base_protocol|icon_hash'
        r'|product|product_version|icp|asn|org'
        r')\s*==',
        re.IGNORECASE,
    )
    if _DOUBLE_EQ_RE.search(tags):
        tags = _DOUBLE_EQ_RE.sub(r'\1=', tags)

    # 已包含 FOFA 字段操作符，是合法查询
    if _FOFA_FIELD_RE.search(tags):
        return tags

    # 完整引号包裹的搜索字符串
    if _QUOTED_RE.match(tags):
        return tags

    # 逗号分隔的分类标签 → 转为 || 分隔的 body 查询
    if "," in tags and _TAG_LIST_RE.match(tags):
        parts = [p.strip().strip('"').strip("'") for p in tags.split(",") if p.strip()]
        if not parts:
            return None
        if len(parts) == 1:
            return f'body="{parts[0]}"'
        return " || ".join(f'body="{p}"' for p in parts)

    # 包含空格或含有内层引号 → 用 FOFA 全局搜索包裹
    if " " in tags or '"' in tags:
        # 内层双引号会破坏 FOFA 语法，移除后包裹
        clean = tags.replace('"', '')
        return f'"{clean}"'

    # 单个关键字 → 包装为 body 查询
    return f'body="{tags}"'


# 已知的二级+TLD 后缀（.com.cn, .co.uk 等），用于提取主域名
_MULTI_PART_TLDS = frozenset({
    # 中国
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "mil.cn",
    "ac.cn", "ah.cn", "bj.cn", "cq.cn", "fj.cn", "gd.cn", "gs.cn",
    "gz.cn", "gx.cn", "ha.cn", "hb.cn", "he.cn", "hi.cn", "hk.cn",
    "hl.cn", "hn.cn", "jl.cn", "js.cn", "jx.cn", "ln.cn", "mo.cn",
    "nm.cn", "nx.cn", "qh.cn", "sc.cn", "sd.cn", "sh.cn", "sn.cn",
    "sx.cn", "tj.cn", "tw.cn", "xj.cn", "xz.cn", "yn.cn", "zj.cn",
    # 香港/澳门/台湾
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
    "com.mo", "net.mo", "org.mo", "gov.mo", "edu.mo",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    # 其他常见
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ed.jp",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "com.br", "net.br", "org.br", "gov.br",
    "co.kr", "or.kr", "ne.kr", "go.kr", "re.kr",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.mx", "net.mx", "org.mx", "gob.mx",
    "co.il", "org.il", "net.il", "gov.il", "ac.il",
    "com.ru", "net.ru", "org.ru", "gov.ru",
})


def get_main_domain(host: str) -> str:
    """从主机名中提取主域名（用于 ICP 备案查询）。

    >>> get_main_domain("www.qq.com")
    'qq.com'
    >>> get_main_domain("szshort.weixin.qq.com")
    'qq.com'
    >>> get_main_domain("example.com.cn")
    'example.com.cn'
    >>> get_main_domain("www.example.com.cn")
    'example.com.cn'
    >>> get_main_domain("192.168.1.1")
    '192.168.1.1'
    """
    if is_ipv4(host):
        return host

    # 去掉端口
    host = host.split(":")[0].lower()

    parts = host.split(".")

    if len(parts) <= 2:
        return host

    # 检查最后 2 个部分是否为已知二级 TLD (如 com.cn)
    tld2 = ".".join(parts[-2:])
    if tld2 in _MULTI_PART_TLDS:
        if len(parts) <= 3:
            return host
        return ".".join(parts[-3:])

    # 普通 TLD：返回最后 2 个部分
    return ".".join(parts[-2:])


def load_targets(filepath: str) -> list[str]:
    """读取目标列表文件，跳过空行和 # 注释行。"""
    lines = []
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
    return lines

"""按漏洞类型分层的 Prompt 模板"""

import re
from pathlib import Path
from ..config import POC_DIR

# --- 基础 System Prompt ---

SYSTEM_PROMPT_BASE = """你是一个 Nuclei 模板生成专家。根据漏洞信息和响应截图，生成一个完整的 Nuclei YAML 模板。

## 输出格式要求
只输出一个 ```yaml 代码块，不要任何额外解释。YAML 结构如下：

```yaml
id: 模板唯一标识（英文小写+连字符）
info:
  name: 漏洞中文名称
  author: Zbh
  severity: 严重级别（critical/high/medium/low/info）
  description: 简要漏洞描述
  reference: https://github.com/Tidesec/
  tags: FOFA搜索语法

requests:
  - method: GET/POST
    path:
      - "{{BaseURL}}/path?param=value"
    headers:  # 仅保留关键请求头
      Content-Type: ...
    body: "POST 请求体（如有）"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "响应关键词1"
          - "响应关键词2"
        condition: and
```

## 注意事项
- id 基于漏洞英文名生成，唯一不重复
- tags 直接使用 FOFA 语法原文，不要修改
- path 中的 Host 头不需要，用 {{BaseURL}} 替代
- 请求头只保留关键的（Content-Type 等），去掉 Host/Content-Length/Accept-Encoding 等
- 从响应截图 OCR 结果中认真识别关键词填入 matchers.words
- body 和 path 中的特殊字符原样保留，不要转义
- 禁止使用 max-time、max-connections 等不存在的字段，超时由 DSL matcher 的 duration 控制"""

# --- 按漏洞类型的额外指令 ---

TYPE_INSTRUCTIONS = {
    "sql_injection": """
## SQL 注入专用要求
- 如果是时间盲注（payload 含 SLEEP/BENCHMARK/pg_sleep），添加 dsl 匹配器检测响应时间：
  ```yaml
  - type: dsl
    dsl:
      - "duration>=5"
  ```
- 如果响应中会回显数据库错误，将错误关键字（如 "SQL syntax", "mysql_fetch", "Warning"）填入 matchers.words""",

    "rce": """
## RCE/命令注入专用要求
- 如果是无回显的命令注入，使用 dsl 时间检测
- 如果 payload 将命令输出写入 web 可访问路径，使用多阶段验证：
  1. 第一个请求触发命令执行（写入文件）
  2. 第二个请求访问写入的文件，匹配输出内容
- 如果可以直接在响应中看到命令执行结果，在 matchers.words 中匹配执行回显的关键词（如 "root:", "uid=", 主机名等）""",

    "file_upload": """
## 文件上传专用要求
- 使用多阶段验证：
  1. 第一个请求上传文件
  2. 用 extractors 从响应中提取上传后的文件路径
  3. 第二个请求 GET 访问上传的文件，确认文件存在并且内容可控
- extractors 示例：
  ```yaml
  extractors:
    - type: regex
      part: body
      regex:
        - "上传路径的正则"
  ```""",

    "file_read": """
## 任意文件读取专用要求
- matchers.words 中匹配读取到的文件内容特征
  - Windows: "[extensions]", "WINDOWS", "Fonts"
  - Linux: "root:", "bin/bash", "/etc/passwd" 格式
- 如果是路径穿越，确保 payload 中的 ../ 在使用 {{BaseURL}} 后仍正确""",

    "info_leak": """
## 信息泄露专用要求
- matchers.words 要足够具体，避免误报
- 优先匹配响应中的敏感字段名（如 "password", "token", "secret", "private_key"）
- 如果泄露数据有固定 JSON 结构，匹配结构特征而不是通用词""",

    "ssrf": """
## SSRF 专用要求
- 使用 interactsh 进行带外验证，请求 URL 中使用 {{interactsh-url}} 占位符
- matchers 通过 interactsh_protocol 检测带外交互：
  ```yaml
  - type: word
    part: interactsh_protocol
    words:
      - "http"
  ```
- 同时保留 body 的 word 匹配，检测响应中是否有错误或成功特征""",

    "auth_bypass": """
## 认证绕过专用要求
- 验证绕过后的权限结果（访问需要登录的页面能获取内容）
- matchers 匹配原本需要认证才能看到的内容特征""",
}


def classify_vuln(title: str, poc: str) -> str:
    """根据漏洞标题和 POC 判断漏洞类型。"""
    text = (title + " " + poc).lower()

    patterns = [
        ("sql_injection", r"sql.?注入|sql.?injection|sqli|sle?ep\s*\(|union\s+select|database\s*\(\)"),
        ("rce", r"命令(注入|执行)|rce|command\s+(injection|execution|inject)|\bexec\s*\(|cmd\.exe|/bin/(sh|bash)|\bping\b.*-c\s"),
        ("file_upload", r"文件上传|file.?upload|upload.*(file|shell|马)|multipart/form-data"),
        ("file_read", r"文件(读取|下载|包含|查看)|任意文件|file.?read|path.?traversal|\.\./\.\./|目录遍历"),
        ("ssrf", r"ssrf|服务端请求伪造|server.?side.?request|url\s*=\s*http"),
        ("info_leak", r"信息(泄露|泄漏|未授)|未授|unauth|info.?leak|配置(泄露|泄漏)|敏感信息|swagger|actuator"),
        ("auth_bypass", r"认证绕过|auth.?bypass|越权|未授权访问|登录绕过"),
    ]

    for vuln_type, pattern in patterns:
        if re.search(pattern, text):
            return vuln_type

    return "default"


def build_system_prompt(title: str, poc: str, examples_text: str) -> str:
    """根据漏洞类型构建分层的 System Prompt。"""
    vuln_type = classify_vuln(title, poc)
    extra = TYPE_INSTRUCTIONS.get(vuln_type, "")
    return SYSTEM_PROMPT_BASE + extra + "\n\n## 参考模板\n" + examples_text


def load_examples_by_type(vuln_type: str, poc_dir: str = POC_DIR, limit: int = 2) -> str:
    """加载与漏洞类型匹配的 few-shot 示例。"""
    # 类型 → 文件名关键字映射
    type_keywords = {
        "sql_injection": ["sqli", "sql"],
        "rce": ["rce", "command-injection", "command-execution", "cmd-exec"],
        "file_upload": ["fileupload", "upload", "Fileupload"],
        "file_read": ["file-read", "path-traversal", "arbitrary-file-read", "traversal"],
        "ssrf": ["ssrf"],
        "info_leak": ["info-leak", "unauthorized-access", "exposure", "unauth", "config-leak"],
        "auth_bypass": ["auth-bypass", "bypass"],
    }

    keywords = type_keywords.get(vuln_type, [])
    examples = []

    poc_path = Path(poc_dir)
    if not poc_path.is_dir():
        return ""

    for f in sorted(poc_path.iterdir()):
        if not f.suffix in (".yaml", ".yml"):
            continue
        name_lower = f.name.lower()
        if keywords and not any(kw in name_lower for kw in keywords):
            continue
        examples.append(f"# 示例: {f.name}\n{f.read_text(encoding='utf-8')}")
        if len(examples) >= limit:
            break

    # 如果类型匹配的示例不够，补充通用示例
    if len(examples) < limit:
        for f in sorted(poc_path.iterdir()):
            if not f.suffix in (".yaml", ".yml"):
                continue
            name_lower = f.name.lower()
            if keywords and any(kw in name_lower for kw in keywords):
                continue
            if f.stat().st_size < 50:  # 跳过损坏文件
                continue
            examples.append(f"# 示例: {f.name}\n{f.read_text(encoding='utf-8')}")
            if len(examples) >= limit:
                break

    return "\n\n".join(examples)

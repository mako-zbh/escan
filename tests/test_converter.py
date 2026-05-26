"""单元测试 — Markdown 解析"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from escan.agent.converter import parse_markdown, extract_yaml, _inject_tags
from escan.agent.prompts import classify_vuln


SAMPLE_MD = """# 29网课系统epay存在SQL注入漏洞

## Fofa语法
body="你在看什么呢？我写的代码好看吗"

## 漏洞POC
| POST /epay/epay.php HTTP/1.1<br/>Host:<br/>Content-Type: application/x-www-form-urlencoded<br/><br/>out_trade_no=' AND SLEEP(5) AND '1'='1 |
| --- |

## 响应代码特征
200

## 响应内容特征
截图内容
"""


class TestParseMarkdown:
    def test_title(self):
        info = parse_markdown(SAMPLE_MD)
        assert info["title"] == "29网课系统epay存在SQL注入漏洞"

    def test_fofa(self):
        info = parse_markdown(SAMPLE_MD)
        assert info["fofa"] == 'body="你在看什么呢？我写的代码好看吗"'

    def test_status(self):
        info = parse_markdown(SAMPLE_MD)
        assert info["status"] == "200"

    def test_poc_contains_payload(self):
        info = parse_markdown(SAMPLE_MD)
        assert "SLEEP(5)" in info["poc"]
        assert "/epay/epay.php" in info["poc"]


class TestClassifyVuln:
    def test_sqli(self):
        assert classify_vuln("SQL注入漏洞", "") == "sql_injection"
        assert classify_vuln("存在 sqli 漏洞", "AND SLEEP(5)") == "sql_injection"

    def test_rce(self):
        assert classify_vuln("命令执行漏洞", "ping -c 4") == "rce"
        assert classify_vuln("RCE", "") == "rce"

    def test_file_upload(self):
        assert classify_vuln("文件上传漏洞", "multipart/form-data") == "file_upload"

    def test_default(self):
        assert classify_vuln("未知漏洞类型", "") == "default"


class TestExtractYaml:
    def test_extract_code_block(self):
        resp = "```yaml\nid: test\ninfo:\n  name: Test\n```"
        assert extract_yaml(resp) == "id: test\ninfo:\n  name: Test"

    def test_extract_no_block(self):
        resp = "id: test\ninfo:\n  name: Test"
        assert extract_yaml(resp) == resp


class TestInjectTags:
    def test_replace_category_tags_with_fofa(self):
        """分类标签 → FOFA 查询"""
        yaml = "id: test\ninfo:\n  name: Vuln\n  tags: cve,cve2026\n"
        result = _inject_tags(yaml, 'body="test"')
        assert "tags: 'body=\"test\"'" in result
        assert "cve,cve2026" not in result

    def test_override_even_valid_fofa(self):
        """即使已有合法 FOFA 也强制替换为原始语句"""
        yaml = 'id: test\ninfo:\n  tags: body="already"\n'
        result = _inject_tags(yaml, 'icon_hash="123"')
        assert "tags: 'icon_hash=\"123\"'" in result

    def test_empty_fofa_no_change(self):
        """markdown 无 FOFA 时保留原样"""
        yaml = "id: test\ninfo:\n  tags: sqli,rce\n"
        result = _inject_tags(yaml, "")
        assert result == yaml

    def test_none_fofa_no_change(self):
        """FOFA 为 None 时保留原样"""
        yaml = "id: test\ninfo:\n  tags: sqli,rce\n"
        result = _inject_tags(yaml, None)
        assert result == yaml

    def test_fofa_with_single_quotes(self):
        """FOFA 含单引号 → 用双引号包裹"""
        yaml = "tags: old"
        result = _inject_tags(yaml, "body='test'")
        assert 'tags: "body=\'test\'"' in result

    def test_fofa_with_both_quotes(self):
        """FOFA 同时包含单引号和双引号"""
        yaml = "tags: old"
        result = _inject_tags(yaml, '''body="x" && title='y' ''')
        assert 'tags: ' in result
        assert 'body=\\"x\\"' in result  # 双引号被转义
        assert "title='y'" in result

    def test_preserves_indentation(self):
        yaml = "id: test\ninfo:\n  name: Vuln\n  tags: old-value\n  severity: high\n"
        result = _inject_tags(yaml, 'app="test"')
        assert '  tags: \'app="test"\'' in result
        assert "  severity: high" in result  # 后续行不被影响

    def test_no_tags_line_unmodified(self):
        """无 tags 行的 YAML 不会被误修改"""
        yaml = "id: test\ninfo:\n  name: Vuln\n"
        result = _inject_tags(yaml, "body='test'")
        assert result == yaml

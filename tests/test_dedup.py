"""去重引擎测试"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from escan.agent.dedup import (
    DedupIndex,
    check_dedup,
    should_skip,
    _parse_md_features,
    MATCH_CVE,
    MATCH_FOFA_PATH,
    MATCH_FOFA,
    MATCH_TITLE,
    MATCH_NONE,
)


SAMPLE_YAML = """id: test-sqli
info:
  name: 测试系统 SQL注入漏洞 (CVE-2026-12345)
  author: Zbh
  severity: high
  tags: body="test-body-pattern"
requests:
  - method: POST
    path:
      - "{{BaseURL}}/api/login"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
"""

SAMPLE_MD_CVE = """# 测试系统 SQL注入漏洞

## Fofa语法
body="test-body-pattern"

## 漏洞POC
| POST /api/login HTTP/1.1<br/>Host:<br/>Content-Type: application/json<br/><br/>{"user":"admin' OR '1'='1"} |
| --- |

CVE-2026-12345

## 响应代码特征
200
"""

SAMPLE_MD_FOFA_PATH = """# 测试系统 另一个SQL注入

## Fofa语法
body="test-body-pattern"

## 漏洞POC
| POST /api/login HTTP/1.1<br/>Host:<br/>Content-Type: application/json<br/><br/>{"user":"admin' OR '1'='1"} |
| --- |

## 响应代码特征
200
"""

SAMPLE_MD_FOFA_ONLY = """# 测试系统 命令执行

## Fofa语法
body="test-body-pattern"

## 漏洞POC
| GET /api/rce?cmd=id HTTP/1.1 |

## 响应代码特征
200
"""

SAMPLE_MD_NEW = """# 全新漏洞

## Fofa语法
body="completely-new-product"

## 漏洞POC
| GET /api/new-vuln HTTP/1.1 |

## 响应代码特征
500
"""


class TestFeatureExtraction:
    def test_extract_cve(self):
        feats = _parse_md_features(SAMPLE_MD_CVE)
        assert "CVE-2026-12345" in feats["cve_list"]

    def test_extract_fofa(self):
        feats = _parse_md_features(SAMPLE_MD_CVE)
        assert feats["fofa"] == 'body="test-body-pattern"'

    def test_extract_method_path(self):
        feats = _parse_md_features(SAMPLE_MD_CVE)
        assert feats["method"] == "POST"
        assert "/api/login" in feats["path"]

    def test_extract_title(self):
        feats = _parse_md_features(SAMPLE_MD_CVE)
        assert "SQL注入" in feats["title"]


class TestDedupIndex:
    def test_build_index(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(SAMPLE_YAML, encoding="utf-8")
        index = DedupIndex(str(tmp_path))
        assert "test-sqli" in index.by_id
        assert "CVE-2026-12345" in index.by_cve

    def test_index_fields(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(SAMPLE_YAML, encoding="utf-8")
        index = DedupIndex(str(tmp_path))
        entry = index.by_id["test-sqli"]
        assert entry["name"] == "测试系统 SQL注入漏洞 (CVE-2026-12345)"
        assert entry["method"] == "POST"
        assert entry["path"] == "/api/login"


class TestCheckDedup:
    def test_l1_cve_match(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(SAMPLE_YAML, encoding="utf-8")
        index = DedupIndex(str(tmp_path))
        match = check_dedup(SAMPLE_MD_CVE, index)
        assert match["level"] == MATCH_CVE
        assert match["matched_id"] == "test-sqli"
        assert should_skip(match)

    def test_l2_fofa_path_match(self, tmp_path):
        # 不含 CVE 的 YAML
        yaml_no_cve = SAMPLE_YAML.replace("(CVE-2026-12345)", "")
        f = tmp_path / "test.yaml"
        f.write_text(yaml_no_cve, encoding="utf-8")
        index = DedupIndex(str(tmp_path))
        match = check_dedup(SAMPLE_MD_FOFA_PATH, index)
        assert match["level"] == MATCH_FOFA_PATH
        assert should_skip(match)

    def test_l3_fofa_match(self, tmp_path):
        yaml_no_cve = SAMPLE_YAML.replace("(CVE-2026-12345)", "")
        f = tmp_path / "test.yaml"
        f.write_text(yaml_no_cve, encoding="utf-8")
        index = DedupIndex(str(tmp_path))
        match = check_dedup(SAMPLE_MD_FOFA_ONLY, index)
        assert match["level"] == MATCH_FOFA
        assert should_skip(match)

    def test_no_match(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(SAMPLE_YAML, encoding="utf-8")
        index = DedupIndex(str(tmp_path))
        match = check_dedup(SAMPLE_MD_NEW, index)
        assert match["level"] == MATCH_NONE
        assert not should_skip(match)

    def test_l4_title_similarity(self, tmp_path):
        yaml_no_cve = SAMPLE_YAML.replace("(CVE-2026-12345)", "")
        yaml_diff_fofa = yaml_no_cve.replace(
            'body="test-body-pattern"', 'body="other-pattern"'
        )
        f = tmp_path / "test.yaml"
        f.write_text(yaml_diff_fofa, encoding="utf-8")
        index = DedupIndex(str(tmp_path))

        # 标题高度相似但 FOFA 不同
        md_similar_title = SAMPLE_MD_FOFA_PATH.replace(
            'body="test-body-pattern"', 'body="yet-another"'
        ).replace(
            "/api/login HTTP/1.1", "/api/other HTTP/1.1"
        )
        match = check_dedup(md_similar_title, index)
        # 应该是 L4（标题相似）或 NONE
        assert match["level"] in (MATCH_TITLE, MATCH_NONE)
        assert not should_skip(match)  # L4 不跳过

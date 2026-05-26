"""单元测试 — 纯函数工具"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from escan.utils.network import is_ipv4, extract_host_port, extract_tags_from_yaml


class TestIsIpv4:
    def test_valid_ips(self):
        assert is_ipv4("192.168.1.1")
        assert is_ipv4("10.0.0.1")
        assert is_ipv4("255.255.255.255")
        assert is_ipv4("0.0.0.0")

    def test_invalid_ips(self):
        assert not is_ipv4("256.1.1.1")
        assert not is_ipv4("1.2.3.256")
        assert not is_ipv4("192.168.1")
        assert not is_ipv4("abc.def.ghi.jkl")
        assert not is_ipv4("example.com")
        assert not is_ipv4("")

    def test_edge_cases(self):
        assert not is_ipv4("192.168.1.1.1")
        assert not is_ipv4("192.168.1.-1")


class TestExtractHostPort:
    def test_full_url(self):
        scheme, host, port = extract_host_port("https://example.com:8443/path")
        assert scheme == "https"
        assert host == "example.com"
        assert port == 8443

    def test_default_ports(self):
        _, _, port = extract_host_port("http://example.com")
        assert port == 80
        _, _, port = extract_host_port("https://example.com")
        assert port == 443

    def test_no_scheme(self):
        scheme, host, port = extract_host_port("192.168.1.1:8080")
        assert scheme == "http"
        assert host == "192.168.1.1"
        assert port == 8080

    def test_ip_only(self):
        scheme, host, port = extract_host_port("10.0.0.1")
        assert scheme == "http"
        assert host == "10.0.0.1"
        assert port == 80


class TestExtractTagsFromYaml:
    def test_simple_tags(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("id: test\ninfo:\n  name: test\n  tags: body=\"hello world\"\n")
        result = extract_tags_from_yaml(str(f))
        # FOFA 查询引号保持完整，仅剥离 YAML 外层包裹引号
        assert result == 'body="hello world"'

    def test_no_tags(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("id: test\ninfo:\n  name: test\n")
        result = extract_tags_from_yaml(str(f))
        assert result is None

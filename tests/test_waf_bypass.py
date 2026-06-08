"""WAF 绕过模块测试"""

import pytest
from src.stealth.waf_bypass import WAFBypass


@pytest.fixture
def bypass():
    return WAFBypass()


class TestWAFDetection:
    """WAF 检测测试"""

    def test_cloudflare_detected(self, bypass):
        headers = {"cf-ray": "abc123", "server": "cloudflare"}
        waf = bypass.detect_waf(headers, "")
        assert waf == "cloudflare"

    def test_aws_waf_detected(self, bypass):
        headers = {"x-amzn-requestid": "abc123"}
        waf = bypass.detect_waf(headers, "")
        assert waf == "aws_waf"

    def test_incapsula_detected(self, bypass):
        headers = {"x-iinfo": "1"}
        waf = bypass.detect_waf(headers, "")
        assert waf == "incapsula"

    def test_no_waf(self, bypass):
        headers = {"server": "nginx"}
        waf = bypass.detect_waf(headers, "")
        assert waf is None

    def test_generic_waf_in_body(self, bypass):
        headers = {}
        body = "Access Denied - Security Policy Violation"
        waf = bypass.detect_waf(headers, body)
        assert waf == "generic_waf"


class TestStealthHeaders:
    """隐匿头测试"""

    def test_has_user_agent(self, bypass):
        headers = bypass.get_stealth_headers()
        assert "User-Agent" in headers
        assert len(headers["User-Agent"]) > 50

    def test_has_accept(self, bypass):
        headers = bypass.get_stealth_headers()
        assert "Accept" in headers

    def test_has_accept_language(self, bypass):
        headers = bypass.get_stealth_headers()
        assert "Accept-Language" in headers

    def test_has_accept_encoding(self, bypass):
        headers = bypass.get_stealth_headers()
        assert "Accept-Encoding" in headers


class TestFakeReferer:
    """伪造 Referer 测试"""

    def test_google_referer(self, bypass):
        referer = bypass.get_fake_referer()
        # 可能返回搜索引擎或同域
        assert isinstance(referer, str)
        assert len(referer) > 10

    def test_same_domain_referer(self, bypass):
        referer = bypass.get_fake_referer("example.com")
        # 应该返回有效 URL
        assert isinstance(referer, str)
        assert referer.startswith("http")


class TestPayloadEncoding:
    """负载编码测试"""

    def test_url_encode(self, bypass):
        encoded = bypass.encode_payload("<script>alert(1)</script>")
        assert "<" not in encoded
        assert ">" not in encoded

    def test_double_encode(self, bypass):
        encoded = bypass.encode_payload("<script>", level=2)
        assert "%" in encoded

    def test_chunk_payload(self, bypass):
        payload = "A" * 100
        chunks = bypass.chunk_payload(payload)
        assert len(chunks) > 1
        assert "".join(chunks) == payload


class TestRequestInterval:
    """请求间隔测试"""

    def test_base_interval(self, bypass):
        interval = bypass.get_request_interval(base_interval=1.0, jitter=0.0)
        # 应该接近 1.0 (可能有 5% 概率的长暂停)
        assert 0.9 <= interval <= 6.0

    def test_with_jitter(self, bypass):
        intervals = [bypass.get_request_interval(base_interval=1.0, jitter=0.5) for _ in range(100)]
        # 应该有变化
        assert len(set(intervals)) > 1
        # 应该在合理范围内
        assert all(0.1 <= i <= 6.0 for i in intervals)

    def test_should_pause(self, bypass):
        # 每 50 个请求应该暂停
        assert bypass.should_pause(50) > 0
        assert bypass.should_pause(100) > 0
        # 其他请求不应该暂停
        assert bypass.should_pause(1) == 0
        assert bypass.should_pause(49) == 0


class TestUtilityFunctions:
    """工具函数测试"""

    def test_random_case(self, bypass):
        results = [WAFBypass.random_case("hello") for _ in range(10)]
        # 应该有变化
        assert len(set(results)) > 1

    def test_insert_comments(self, bypass):
        result = WAFBypass.insert_comments("SELECT * FROM users")
        assert "/**/" in result

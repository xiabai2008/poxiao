"""技术栈识别单元测试（指纹识别 / 综合检测 / 标签导出）"""

import re

import pytest

from src.dawn.tech_stack import (
    TechStackDetector, TechFingerprint,
    _compile_patterns, _compile_simple,
)


@pytest.fixture
def det():
    return TechStackDetector()


class TestCompileHelpers:
    def test_compile_patterns(self):
        out = _compile_patterns([("nginx", r"nginx", "server")])
        assert out[0][0] == "nginx"
        assert isinstance(out[0][1], re.Pattern)
        assert out[0][2] == "server"

    def test_compile_simple(self):
        out = _compile_simple([("php", r"php")])
        assert out[0][0] == "php"
        assert isinstance(out[0][1], re.Pattern)


class TestDetectServer:
    def test_nginx(self, det):
        assert det.detect_server({"server": "nginx/1.21.0"}) == "nginx"

    def test_apache(self, det):
        assert det.detect_server({"server": "Apache/2.4.41"}) == "apache"

    def test_iis_generic(self, det):
        # "iis" 模式排在版本专属模式之前，故返回通用 "iis"
        assert det.detect_server({"server": "Microsoft-IIS/10.0"}) == "iis"

    def test_cloudflare(self, det):
        assert det.detect_server({"server": "cloudflare"}) == "cloudflare"

    def test_x_powered_by_no_server_match(self, det):
        # X-Powered-By 回退到 server 解析，但 PHP 不在 server 指纹库中
        assert det.detect_server({"x-powered-by": "PHP/7.4"}) == ""

    def test_empty(self, det):
        assert det.detect_server({}) == ""


class TestDetectLanguage:
    def test_php_x_powered_by(self, det):
        assert det.detect_language({"x-powered-by": "PHP/8.1"}, {}) == "php"

    def test_java_cookie(self, det):
        assert det.detect_language({}, {"JSESSIONID": "abc"}, "") == "java"

    def test_java_html(self, det):
        assert det.detect_language({}, {}, "<a href='x.jsp'>") == "java"

    def test_python_header(self, det):
        assert det.detect_language({"x-powered-by": "Python/3.9"}, {}) == "python"

    def test_aspnet(self, det):
        assert det.detect_language({"x-powered-by": "ASP.NET"}, {}) == "asp.net"

    def test_go_server(self, det):
        assert det.detect_language({"server": "Go/1.19"}, {}) == "go"

    def test_node_header(self, det):
        assert det.detect_language({"x-powered-by": "Express"}, {}) == "node.js"

    def test_ruby_html(self, det):
        assert det.detect_language({}, {}, "<script src='/ruby/app'></script>") == "ruby"

    def test_none(self, det):
        assert det.detect_language({}, {}, "") == ""


class TestDetectCms:
    def test_wordpress(self, det):
        assert det.detect_cms("<link href='/wp-content/foo.css'>") == "wordpress"

    def test_dedecms(self, det):
        assert det.detect_cms("powered by 织梦") == "dedecms"

    def test_thinkphp(self, det):
        assert det.detect_cms("thinkphp framework") == "thinkphp"

    def test_shopify_url(self, det):
        assert det.detect_cms(url="https://x.myshopify.com") == "shopify"

    def test_none(self, det):
        assert det.detect_cms("no cms here") == ""


class TestDetectFramework:
    def test_react(self, det):
        assert det.detect_framework("<div data-reactroot></div>") == "react"

    def test_vue(self, det):
        assert det.detect_framework("<div v-cloak></div>") == "vue.js"

    def test_nextjs(self, det):
        assert det.detect_framework(html="", url="", headers={"x-powered-by": "Next.js"}) == "next.js"

    def test_django(self, det):
        assert det.detect_framework("csrfmiddlewaretoken") == "django"

    def test_spring(self, det):
        assert det.detect_framework(html="", headers={"server": "spring"}) == "spring"

    def test_none(self, det):
        assert det.detect_framework("plain") == ""


class TestDetectCdn:
    def test_cloudflare_server(self, det):
        assert det.detect_cdn({"server": "cloudflare"}) == "cloudflare"

    def test_cloudfront_header_name(self, det):
        assert det.detect_cdn({"x-amz-cf-id": "abc"}) == "cloudfront"

    def test_fastly_served_by(self, det):
        assert det.detect_cdn({"x-served-by": "cache-fra"}) == "fastly"

    def test_generic_x_cache(self, det):
        assert det.detect_cdn({"x-cache": "HIT"}) == "detected"

    def test_cdn_value_match(self, det):
        assert det.detect_cdn({"x-cache": "via cloudflare"}) == "cloudflare"

    def test_none(self, det):
        assert det.detect_cdn({}) == ""


class TestDetectWaf:
    def test_sucuri_header_name(self, det):
        assert det.detect_waf({"x-sucuri-id": "xyz"}) == "sucuri-waf"

    def test_aws_header_name(self, det):
        assert det.detect_waf({"x-amzn-waf-id": "abc"}) == "aws-waf"

    def test_cloudflare_server(self, det):
        assert det.detect_waf({"server": "cloudflare cf-ray"}) == "cloudflare-waf"

    def test_explicit_waf_header_generic(self, det):
        assert det.detect_waf({"x-waf": "somevendor"}) == "detected"

    def test_none(self, det):
        assert det.detect_waf({}) == ""


class TestDetectPlatform:
    def test_aws(self, det):
        assert det.detect_platform({"x-amz-requestid": "abc"}) == "aws"

    def test_alibaba(self, det):
        assert det.detect_platform({"server": "aliyun"}) == "alibaba"

    def test_tencent(self, det):
        assert det.detect_platform({"server": "qcloud"}) == "tencent"

    def test_none(self, det):
        assert det.detect_platform({}) == ""


class TestDetectDatabase:
    def test_mysql(self, det):
        assert det.detect_database(html="You have an error in your SQL syntax (MySQL)") == "mysql"

    def test_postgresql(self, det):
        assert det.detect_database(html="pg_query error postgresql") == "postgresql"

    def test_none(self, det):
        assert det.detect_database(html="all good") == ""


class TestDetectAnalytics:
    def test_google(self, det):
        # googletagmanager.com 命中 google-analytics 指纹（排在 gtm 专属之前）
        assert det.detect_analytics("<script src='https://www.googletagmanager.com/gtm.js'></script>") == "google-analytics"

    def test_baidu(self, det):
        assert det.detect_analytics("<script src='https://hm.baidu.com/hm.js'></script>") == "baidu-tongji"

    def test_empty_html(self, det):
        assert det.detect_analytics("") == ""

    def test_none(self, det):
        assert det.detect_analytics("<p>no trackers</p>") == ""


class TestDetect:
    def test_full(self, det):
        fp = det.detect(
            headers={"server": "nginx/1.21", "x-powered-by": "PHP/8.1"},
            cookies={},
            html="<link href='/wp-content/x.css'>",
            url="https://x.com",
        )
        assert isinstance(fp, TechFingerprint)
        assert fp.server == "nginx"
        assert fp.language == "php"
        assert fp.cms == "wordpress"


class TestAsTags:
    def test_filled(self, det):
        fp = TechFingerprint(server="nginx", language="php", cms="wordpress",
                              framework="", cdn="cloudflare", waf="", platform="",
                              database="", analytics="")
        tags = det.as_tags(fp)
        assert "nginx" in tags
        assert "php" in tags
        assert "cdn:cloudflare" in tags

    def test_empty(self, det):
        assert det.as_tags(TechFingerprint()) == []


class TestKnown:
    def test_filters_empty(self):
        fp = TechFingerprint(server="nginx", language="")
        assert fp.known == {"server": "nginx"}

    def test_all_empty(self):
        assert fp_known_all_empty() == {}


def fp_known_all_empty():
    return TechFingerprint().known

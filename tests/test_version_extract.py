"""dawn.version_extract 纯逻辑测试（正则提取，无网络）"""

from src.dawn.version_extract import VersionExtractor, VersionInfo


def test_extract_from_headers_with_version():
    ve = VersionExtractor()
    headers = {
        "server": "nginx/1.24.0",
        "x-powered-by": "PHP/7.4.33",
    }
    res = ve.extract_from_headers(headers)
    comps = {r.component: r.version for r in res}
    assert comps["nginx"] == "1.24.0"
    assert comps["php"] == "7.4.33"


def test_extract_from_headers_no_version():
    ve = VersionExtractor()
    headers = {"server": "cloudflare"}
    res = ve.extract_from_headers(headers)
    assert any(r.component == "cloudflare" and r.version == "detected" for r in res)


def test_extract_from_headers_missing_header():
    ve = VersionExtractor()
    assert ve.extract_from_headers({}) == []


def test_extract_from_meta_specific_cms():
    ve = VersionExtractor()
    html = '<meta name="generator" content="WordPress 6.2.2">'
    res = ve.extract_from_meta(html)
    assert any(r.component == "wordpress" and r.version == "6.2.2" for r in res)


def test_extract_from_meta_generic():
    ve = VersionExtractor()
    html = '<meta name="generator" content="MyApp 2.0.1">'
    res = ve.extract_from_meta(html)
    assert any(r.component == "generator" and r.version == "2.0.1" for r in res)


def test_extract_from_meta_none():
    ve = VersionExtractor()
    assert ve.extract_from_meta("") == []


def test_extract_from_scripts_jquery_path():
    ve = VersionExtractor()
    html = '<script src="/wp-includes/js/jquery/jquery-3.6.0.min.js"></script>'
    res = ve.extract_from_scripts(html)
    assert any(r.component == "jquery" and r.version == "3.6.0" for r in res)


def test_extract_from_scripts_inline_angular():
    ve = VersionExtractor()
    html = '<div ng-version="1.2.3"></div>'
    res = ve.extract_from_scripts(html)
    assert any(r.component == "angular" and r.version == "1.2.3" for r in res)


def test_extract_from_scripts_none():
    ve = VersionExtractor()
    assert ve.extract_from_scripts("no scripts here") == []


def test_extract_from_comments_wordpress():
    ve = VersionExtractor()
    html = "<!-- powered by wordpress 6.2 -->"
    res = ve.extract_from_comments(html)
    assert any(r.component == "wordpress" for r in res)


def test_extract_from_comments_generic():
    ve = VersionExtractor()
    html = "<!-- built with AwesomeFramework v3.1 -->"
    res = ve.extract_from_comments(html)
    assert any("awesomeframework" in r.component for r in res)


def test_extract_from_cookies():
    ve = VersionExtractor()
    res = ve.extract_from_cookies("PHPSESSID=abc; JSESSIONID=xyz; laravel_session=1")
    comps = {r.component for r in res}
    assert "php" in comps
    assert "java-tomcat" in comps
    assert "laravel" in comps


def test_extract_from_cookies_empty():
    ve = VersionExtractor()
    assert ve.extract_from_cookies("") == []


def test_extract_combined_and_dedup():
    ve = VersionExtractor()
    headers = {"server": "nginx/1.24.0"}
    html = '<meta name="generator" content="WordPress 6.2.2">'
    res = ve.extract(headers, html)
    comps = {r.component for r in res}
    assert "nginx" in comps and "wordpress" in comps
    # 去重：同一 component@version 只出现一次
    keys = [f"{r.component}@{r.version}" for r in res]
    assert len(keys) == len(set(keys))


def test_extract_as_dict_and_strings():
    ve = VersionExtractor()
    headers = {"server": "nginx/1.24.0"}
    d = ve.extract_as_dict(headers)
    assert d["nginx"] == "1.24.0"
    s = ve.as_strings(headers)
    assert any("nginx@1.24.0" == x for x in s)


def test_version_info_str():
    v = VersionInfo(component="nginx", version="1.0")
    assert str(v) == "nginx@1.0"

"""dawn.sensitive 纯逻辑测试：路径字典 / is_interesting / 六层降噪（无网络）"""

from src.dawn.sensitive import SensitivePathDetector, PathFind


def test_get_paths_common():
    d = SensitivePathDetector()
    paths = d.get_paths()
    assert any(p[0] == ".env" for p in paths)
    assert any(p[0] == ".git/config" for p in paths)


def test_get_paths_with_tech():
    d = SensitivePathDetector()
    paths = d.get_paths("wordpress")
    assert any(p[0] == "wp-config.php.bak" for p in paths)
    # 通用路径也包含
    assert any(p[0] == ".env" for p in paths)


def test_get_paths_unknown_tech():
    d = SensitivePathDetector()
    paths = d.get_paths("nonexistent_tech_xyz")
    # 不应混入技术栈特定路径
    assert all(p[0] != "wp-config.php.bak" for p in paths)


def test_is_interesting():
    assert PathFind(url="u", status=200, size=500).is_interesting is True
    assert PathFind(url="u", status=403, size=500).is_interesting is True
    assert PathFind(url="u", status=200, size=50).is_interesting is False
    assert PathFind(url="u", status=200, size=500, category="info").is_interesting is False
    assert PathFind(url="u", status=200, size=500, is_catchall=True).is_interesting is False
    assert PathFind(url="u", status=500, size=500).is_interesting is False


def test_reduce_header_analysis_cdn_html():
    d = SensitivePathDetector()
    r = PathFind(
        url="http://x/.env", status=200, size=2000, category="config",
        content_type="text/html", content_preview="<html>generic</html>",
        response_headers={"server": "cloudflare", "content-type": "text/html"},
    )
    d._reduce_noise_header_analysis([r])
    assert r.is_catchall is True


def test_reduce_header_analysis_cdn_but_json_passthrough():
    d = SensitivePathDetector()
    r = PathFind(
        url="http://x/api", status=200, size=200, category="api",
        content_type="application/json", content_preview='{"api":1}',
        response_headers={"server": "cloudflare", "content-type": "application/json"},
    )
    d._reduce_noise_header_analysis([r])
    assert r.is_catchall is False


def test_reduce_content_patterns():
    d = SensitivePathDetector()
    r = PathFind(url="u", status=200, size=500, category="config",
                 content_preview="404 not found")
    d._reduce_noise_content_patterns([r])
    assert r.is_catchall is True


def test_reduce_content_patterns_cloudflare_error():
    d = SensitivePathDetector()
    r = PathFind(url="u", status=200, size=500, category="config",
                 content_preview="error 1020 access denied")
    d._reduce_noise_content_patterns([r])
    assert r.is_catchall is True


def test_reduce_content_patterns_default_page():
    d = SensitivePathDetector()
    r = PathFind(url="u", status=200, size=500, category="config",
                 content_preview="<title>Apache2 Ubuntu Default Page</title> it works")
    d._reduce_noise_content_patterns([r])
    assert r.is_catchall is True


def test_reduce_behavioral_same_hash():
    d = SensitivePathDetector()
    results = [PathFind(url=f"u{i}", status=200, size=100, content_hash="same")
               for i in range(5)]
    d._reduce_noise_behavioral(results)
    assert all(r.is_catchall for r in results)


def test_reduce_behavioral_status_consistency():
    d = SensitivePathDetector()
    results = [PathFind(url=f"u{i}", status=200, size=100) for i in range(5)]
    d._reduce_noise_behavioral(results)
    # 5/5 同一状态码 200 → 全部标记
    assert all(r.is_catchall for r in results)


def test_reduce_behavioral_few_results():
    d = SensitivePathDetector()
    results = [PathFind(url=f"u{i}", status=200, size=100) for i in range(2)]
    d._reduce_noise_behavioral(results)
    # < 3 → 不处理
    assert all(not r.is_catchall for r in results)

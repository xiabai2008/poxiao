"""dawn.sensitive 降噪引擎补充测试：边界场景与混合响应"""

import pytest
from src.dawn.sensitive import SensitivePathDetector, PathFind


class TestHeaderAnalysisBounds:
    def test_no_cdn_headers_passthrough(self):
        d = SensitivePathDetector()
        r = PathFind(url='http://x/config', status=200, size=500, category='config',
                     response_headers={'server': 'Apache/2.4', 'content-type': 'text/html'},
                     content_type='text/html', content_preview='<html>normal</html>')
        d._reduce_noise_header_analysis([r])
        assert r.is_catchall is False

    def test_cdn_but_small_size(self):
        d = SensitivePathDetector()
        r = PathFind(url='http://x/', status=200, size=500, category='config',
                     response_headers={'server': 'cloudflare', 'content-type': 'text/html'},
                     content_type='text/html', content_preview='<html>small</html>')
        d._reduce_noise_header_analysis([r])
        assert r.is_catchall is False

    def test_cdn_but_json_content(self):
        d = SensitivePathDetector()
        r = PathFind(url='http://x/api', status=200, size=2000, category='config',
                     response_headers={'server': 'cloudflare', 'content-type': 'application/json'},
                     content_type='application/json', content_preview='{"data": "test"}')
        d._reduce_noise_header_analysis([r])
        assert r.is_catchall is False

    def test_already_catchall_skip(self):
        d = SensitivePathDetector()
        r = PathFind(url='http://x/', status=200, size=100, is_catchall=True)
        d._reduce_noise_header_analysis([r])
        assert r.is_catchall is True


class TestContentPatternsBounds:
    def test_normal_content_passthrough(self):
        d = SensitivePathDetector()
        r = PathFind(url='http://x/admin', status=200, size=800, category='admin',
                     content_preview='<html><body>Dashboard</body></html>')
        d._reduce_noise_content_patterns([r])
        assert r.is_catchall is False

    def test_info_category_skip(self):
        d = SensitivePathDetector()
        r = PathFind(url='http://x/404', status=404, size=500, category='info',
                     content_preview='404 not found')
        d._reduce_noise_content_patterns([r])
        assert r.is_catchall is False

    def test_large_size_no_pattern(self):
        d = SensitivePathDetector()
        r = PathFind(url='http://x/secret', status=200, size=5000, category='secret',
                     content_preview='Normal content without catchall keywords or error patterns or cloudflare or nginx defaults or apache ubuntu defaults')
        d._reduce_noise_content_patterns([r])
        assert r.is_catchall is False


class TestBehavioralBounds:
    def test_diverse_responses_not_all_catchall(self):
        d = SensitivePathDetector()
        results = [
            PathFind(url='u0', status=200, size=100, content_hash='a'),
            PathFind(url='u1', status=200, size=200, content_hash='b'),
            PathFind(url='u2', status=404, size=100, content_hash='c'),
            PathFind(url='u3', status=200, size=300, content_hash='d'),
            PathFind(url='u4', status=403, size=150, content_hash='e'),
        ]
        d._reduce_noise_behavioral(results)
        assert any(not r.is_catchall for r in results)

    def test_partial_match_not_all_catchall(self):
        d = SensitivePathDetector()
        results = [
            PathFind(url='u0', status=200, size=100, content_hash='same'),
            PathFind(url='u1', status=200, size=100, content_hash='same'),
            PathFind(url='u2', status=200, size=100, content_hash='same'),
            PathFind(url='u3', status=200, size=300, content_hash='diff'),
            PathFind(url='u4', status=404, size=50, content_hash='other'),
        ]
        d._reduce_noise_behavioral(results)
        assert results[3].is_catchall is False
        assert results[4].is_catchall is False

    def test_empty_results(self):
        d = SensitivePathDetector()
        d._reduce_noise_behavioral([])


class TestPathFindBounds:
    def test_default_values(self):
        pf = PathFind(url='http://x/test', status=0, size=0)
        assert pf.is_catchall is False
        assert pf.is_interesting is False

    def test_zero_size_interesting(self):
        assert PathFind(url='u', status=200, size=0).is_interesting is False

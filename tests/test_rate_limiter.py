"""令牌桶限速器测试"""

import pytest
import asyncio
import time
from src.xiazhi.rate_limiter import TokenBucket, RateLimiter


class TestTokenBucket:
    """令牌桶测试"""

    def test_initial_tokens(self):
        bucket = TokenBucket(rate=10, burst=10)
        assert bucket.tokens == 10

    def test_acquire_immediate(self):
        bucket = TokenBucket(rate=10, burst=10)
        # 应该能立即获取令牌
        loop = asyncio.new_event_loop()
        wait = loop.run_until_complete(bucket.acquire())
        assert wait == 0.0
        loop.close()

    def test_acquire_exhaustion(self):
        bucket = TokenBucket(rate=1, burst=1)
        loop = asyncio.new_event_loop()
        # 第一次应该成功
        wait1 = loop.run_until_complete(bucket.acquire())
        assert wait1 == 0.0
        # 第二次应该需要等待
        wait2 = loop.run_until_complete(bucket.acquire())
        assert wait2 > 0.0
        loop.close()

    def test_try_acquire(self):
        bucket = TokenBucket(rate=10, burst=1)
        assert bucket.try_acquire() is True
        assert bucket.try_acquire() is False


class TestRateLimiter:
    """限速器测试"""

    def test_global_limit(self):
        limiter = RateLimiter(qps=10, burst=10)
        # 应该能立即获取
        loop = asyncio.new_event_loop()
        wait = loop.run_until_complete(limiter.acquire())
        assert wait == 0.0
        loop.close()

    def test_domain_limit(self):
        limiter = RateLimiter(qps=10, burst=10, per_domain_qps=1, per_domain_burst=1)
        loop = asyncio.new_event_loop()
        # 第一次应该成功
        wait1 = loop.run_until_complete(limiter.acquire("example.com"))
        assert wait1 == 0.0
        # 第二次同一域名应该需要等待
        wait2 = loop.run_until_complete(limiter.acquire("example.com"))
        assert wait2 > 0.0
        loop.close()

    def test_different_domains(self):
        limiter = RateLimiter(qps=10, burst=10, per_domain_qps=1, per_domain_burst=1)
        loop = asyncio.new_event_loop()
        # 不同域名应该独立限速
        wait1 = loop.run_until_complete(limiter.acquire("example.com"))
        wait2 = loop.run_until_complete(limiter.acquire("test.com"))
        assert wait1 == 0.0
        assert wait2 == 0.0
        loop.close()

    def test_set_domain_qps(self):
        limiter = RateLimiter(qps=10, burst=10)
        limiter.set_domain_qps("example.com", qps=100, burst=100)
        # 应该能快速获取 (允许少量等待时间)
        loop = asyncio.new_event_loop()
        for _ in range(50):
            wait = loop.run_until_complete(limiter.acquire("example.com"))
            assert wait <= 0.2  # 允许少量等待
        loop.close()


class TestDomainBucket:
    """主域名分组测试"""

    def test_two_part_domain(self):
        limiter = RateLimiter()
        b = limiter._get_domain_bucket("example.com")
        assert b is limiter.domain_buckets["example.com"]

    def test_three_part_domain(self):
        limiter = RateLimiter()
        b = limiter._get_domain_bucket("sub.example.com")
        assert b is limiter.domain_buckets["example.com"]

    def test_cn_suffix_grouping(self):
        limiter = RateLimiter()
        b = limiter._get_domain_bucket("a.example.com.cn")
        assert b is limiter.domain_buckets["example.com.cn"]

    def test_other_suffix_grouping(self):
        limiter = RateLimiter()
        b = limiter._get_domain_bucket("a.example.xyz")
        assert b is limiter.domain_buckets["example.xyz"]

    def test_subdomains_share_bucket(self):
        limiter = RateLimiter()
        b1 = limiter._get_domain_bucket("x.example.com")
        b2 = limiter._get_domain_bucket("y.example.com")
        assert b1 is b2


class TestStats:
    """统计信息测试"""

    def test_get_stats_empty(self):
        limiter = RateLimiter()
        assert limiter.get_stats() == {}

    def test_get_stats_after_acquire(self):
        limiter = RateLimiter(qps=100, burst=100)
        loop = asyncio.new_event_loop()
        loop.run_until_complete(limiter.acquire("example.com"))
        loop.close()
        stats = limiter.get_stats()
        assert "example.com" in stats
        assert stats["example.com"]["requests"] == 1

    def test_print_stats(self, capsys):
        limiter = RateLimiter(qps=100, burst=100)
        loop = asyncio.new_event_loop()
        loop.run_until_complete(limiter.acquire("example.com"))
        loop.close()
        limiter.print_stats()
        out = capsys.readouterr().out
        assert "限速统计" in out
        assert "example.com" in out

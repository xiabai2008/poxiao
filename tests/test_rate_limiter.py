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

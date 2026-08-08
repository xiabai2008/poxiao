"""
令牌桶限速器
============
基于域名的请求速率控制

功能:
  - 全局速率限制
  - per-domain 速率限制
  - 自适应速率 (根据响应调整)
  - 突发请求支持

用法:
  limiter = RateLimiter(qps=10, burst=20)
  await limiter.acquire("example.com")  # 等待直到可以发送
  await limiter.acquire()               # 全局限制
"""

import asyncio
import time
from typing import Dict
from collections import defaultdict


class TokenBucket:
    """令牌桶算法"""

    def __init__(self, rate: float, burst: int = 1):
        """
        Args:
            rate: 每秒生成令牌数
            burst: 突发容量
        """
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.last_time = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> float:
        """
        获取令牌，返回等待时间

        Returns:
            实际等待的秒数
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_time
            self.last_time = now

            # 补充令牌
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)

            if self.tokens >= tokens:
                self.tokens -= tokens
                return 0.0
            else:
                # 需要等待
                wait_time = (tokens - self.tokens) / self.rate
                self.tokens = 0
                self.last_time += wait_time
                await asyncio.sleep(wait_time)
                return wait_time

    def try_acquire(self, tokens: int = 1) -> bool:
        """尝试获取令牌，不等待"""
        now = time.monotonic()
        elapsed = now - self.last_time
        self.last_time = now
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


class RateLimiter:
    """多级速率限制器"""

    def __init__(self, qps: float = 10.0, burst: int = 20,
                 per_domain_qps: float = 3.0, per_domain_burst: int = 5):
        """
        Args:
            qps: 全局每秒请求数
            burst: 全局突发容量
            per_domain_qps: 单域名每秒请求数
            per_domain_burst: 单域名突发容量
        """
        self.global_bucket = TokenBucket(rate=qps, burst=burst)
        self.per_domain_qps = per_domain_qps
        self.per_domain_burst = per_domain_burst
        self.domain_buckets: Dict[str, TokenBucket] = {}
        self._stats = defaultdict(lambda: {"requests": 0, "waits": 0, "total_wait": 0.0})

    def _get_domain_bucket(self, domain: str) -> TokenBucket:
        """获取域名桶 (按主域名分组)"""
        # 提取主域名 (e.g., sub.example.com → example.com)
        parts = domain.split(".")
        if len(parts) > 2:
            # 处理 .com.cn 等
            if parts[-2] in ("com", "net", "org", "gov", "edu", "co"):
                main_domain = ".".join(parts[-3:])
            else:
                main_domain = ".".join(parts[-2:])
        else:
            main_domain = domain

        if main_domain not in self.domain_buckets:
            self.domain_buckets[main_domain] = TokenBucket(
                rate=self.per_domain_qps,
                burst=self.per_domain_burst
            )
        return self.domain_buckets[main_domain]

    async def acquire(self, domain: str = "") -> float:
        """
        获取请求许可

        Args:
            domain: 目标域名 (用于 per-domain 限制)

        Returns:
            等待的秒数
        """
        total_wait = 0.0

        # 全局限制
        wait = await self.global_bucket.acquire()
        total_wait += wait

        # 域名限制
        if domain:
            bucket = self._get_domain_bucket(domain)
            wait = await bucket.acquire()
            total_wait += wait

            # 统计
            self._stats[domain]["requests"] += 1
            if total_wait > 0:
                self._stats[domain]["waits"] += 1
                self._stats[domain]["total_wait"] += total_wait

        return total_wait

    def set_domain_qps(self, domain: str, qps: float, burst: int = 5):
        """设置特定域名的速率"""
        self.domain_buckets[domain] = TokenBucket(rate=qps, burst=burst)

    def get_stats(self) -> Dict:
        """获取统计信息"""
        return dict(self._stats)

    def print_stats(self):
        """打印统计"""
        print("  📊 限速统计")
        print(f"  {'─' * 40}")
        for domain, stats in sorted(self._stats.items(), key=lambda x: -x[1]["requests"]):
            if stats["requests"] > 0:
                avg_wait = stats["total_wait"] / stats["requests"] if stats["requests"] > 0 else 0
                print(f"  {domain:30s} 请求:{stats['requests']:5d} 等待:{stats['waits']:4d} 平均:{avg_wait:.3f}s")

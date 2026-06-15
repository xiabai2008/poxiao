"""
代理池管理器
============
加载、验证、轮换代理

代理来源:
  - 本地文件 (每行一个 proxy)
  - 环境变量 (PROXY_LIST)
  - 免费代理 API (可选)
  - 用户自定义代理列表

协议支持:
  - HTTP/HTTPS 代理
  - SOCKS5 代理 (需 httpx[socks])

用法:
  pool = ProxyPool()
  pool.load_from_file("proxies.txt")
  pool.load_from_list(["http://1.2.3.4:8080", "socks5://5.6.7.8:1080"])
  await pool.validate_all()

  proxy = pool.get()      # 随机获取一个可用代理
  proxy = pool.get_rr()   # 轮询获取
"""

import asyncio
import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from collections import defaultdict

import httpx


@dataclass
class ProxyInfo:
    """代理信息"""
    url: str                        # 代理 URL (http://host:port)
    protocol: str = "http"          # http / https / socks5
    host: str = ""
    port: int = 0
    username: str = ""
    password: str = ""
    # 状态
    alive: bool = False
    latency: float = 0.0            # 延迟 (秒)
    success_count: int = 0          # 成功次数
    fail_count: int = 0             # 失败次数
    last_check: float = 0.0         # 最后检查时间
    last_used: float = 0.0          # 最后使用时间
    consecutive_fails: int = 0      # 连续失败次数
    # 地理信息 (可选)
    country: str = ""
    city: str = ""
    isp: str = ""
    # 元数据
    source: str = ""                # 来源
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.host and self.url:
            self._parse_url()

    def _parse_url(self):
        """解析代理 URL"""
        try:
            url = self.url
            if "://" in url:
                self.protocol = url.split("://")[0]
                url = url.split("://")[1]

            if "@" in url:
                auth, addr = url.split("@", 1)
                if ":" in auth:
                    self.username, self.password = auth.split(":", 1)
            else:
                addr = url

            if ":" in addr:
                self.host, port_str = addr.rsplit(":", 1)
                self.port = int(port_str)
            else:
                self.host = addr
                self.port = 8080
        except Exception:
            pass

    @property
    def success_rate(self) -> float:
        """成功率"""
        total = self.success_count + self.fail_count
        if total == 0:
            return 0.0
        return self.success_count / total

    @property
    def score(self) -> float:
        """代理评分 (用于智能选择)"""
        if not self.alive:
            return 0.0
        # 基础分 = 成功率 * 100
        base = self.success_rate * 100
        # 延迟惩罚 (延迟越低越好)
        latency_bonus = max(0, 50 - self.latency * 10)
        # 连续失败惩罚
        fail_penalty = self.consecutive_fails * 20
        # 新鲜度奖励 (最近使用过的代理可能更稳定)
        freshness = 0
        if self.last_used > 0:
            age = time.time() - self.last_used
            if age < 60:
                freshness = 10
        return max(0, base + latency_bonus - fail_penalty + freshness)

    def to_dict(self):
        return {
            "url": self.url,
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "alive": self.alive,
            "latency": round(self.latency, 3),
            "success_rate": round(self.success_rate, 2),
            "score": round(self.score, 1),
            "success": self.success_count,
            "fail": self.fail_count,
            "country": self.country,
            "source": self.source,
        }


class ProxyPool:
    """代理池管理器"""

    # 验证 URL
    VALIDATE_URL = "http://httpbin.org/ip"
    VALIDATE_URL_HTTPS = "https://httpbin.org/ip"

    def __init__(self, max_fails: int = 5, validate_timeout: float = 10.0,
                 min_score: float = 20.0):
        self.proxies: Dict[str, ProxyInfo] = {}   # url → ProxyInfo
        self.max_fails = max_fails                  # 最大连续失败次数
        self.validate_timeout = validate_timeout
        self.min_score = min_score                  # 最低评分阈值
        self._rr_index = 0                          # 轮询索引

    # ── 加载代理 ─────────────────────────────────────

    def load_from_file(self, file_path: str) -> int:
        """从文件加载代理 (每行一个)"""
        path = Path(file_path)
        if not path.exists():
            return 0

        count = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if self._add_proxy(line, source="file"):
                count += 1
        return count

    def load_from_list(self, proxy_list: List[str], source: str = "list") -> int:
        """从列表加载代理"""
        count = 0
        for url in proxy_list:
            if self._add_proxy(url, source=source):
                count += 1
        return count

    def load_from_env(self, env_var: str = "PROXY_LIST") -> int:
        """从环境变量加载 (逗号分隔)"""
        val = os.environ.get(env_var, "")
        if not val:
            return 0
        proxies = [p.strip() for p in val.split(",") if p.strip()]
        return self.load_from_list(proxies, source="env")

    def load_from_api(self, api_url: str) -> int:
        """从 API 加载代理"""
        try:
            resp = httpx.get(api_url, timeout=self.validate_timeout)
            if resp.status_code == 200:
                # 尝试解析为 JSON
                try:
                    data = resp.json()
                    if isinstance(data, list):
                        return self.load_from_list(data, source="api")
                    elif isinstance(data, dict) and "proxies" in data:
                        return self.load_from_list(data["proxies"], source="api")
                except Exception:
                    pass
                # 尝试解析为文本 (每行一个)
                lines = resp.text.strip().splitlines()
                return self.load_from_list(lines, source="api")
        except Exception:
            pass
        return 0

    def _add_proxy(self, url: str, source: str = "") -> bool:
        """添加代理到池"""
        # 标准化 URL
        url = url.strip()
        if not url.startswith("http://") and not url.startswith("https://") and not url.startswith("socks5://"):
            url = f"http://{url}"

        if url in self.proxies:
            return False

        proxy = ProxyInfo(url=url, source=source)
        proxy.alive = True  # 默认标记为可用，后续验证
        self.proxies[url] = proxy
        return True

    # ── 验证代理 ─────────────────────────────────────

    async def validate_all(self, concurrency: int = 20) -> Dict[str, bool]:
        """并发验证所有代理"""
        sem = asyncio.Semaphore(concurrency)
        results = {}

        async def _check(proxy: ProxyInfo):
            async with sem:
                alive, latency = await self._check_one(proxy)
                results[proxy.url] = alive

        tasks = [_check(p) for p in self.proxies.values()]
        await asyncio.gather(*tasks, return_exceptions=True)
        return results

    async def _check_one(self, proxy: ProxyInfo) -> Tuple[bool, float]:
        """验证单个代理"""
        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(
                proxy=proxy.url,
                timeout=self.validate_timeout,
                verify=False,
            ) as client:
                resp = await client.get(self.VALIDATE_URL)
                latency = time.perf_counter() - t0

                if resp.status_code == 200:
                    proxy.alive = True
                    proxy.latency = latency
                    proxy.last_check = time.time()
                    proxy.success_count += 1
                    proxy.consecutive_fails = 0

                    # 尝试提取出口 IP 信息
                    try:
                        data = resp.json()
                        origin = data.get("origin", "")
                        if origin:
                            proxy.tags = [f"ip:{origin}"]
                    except Exception:
                        pass
                    return True, latency
                else:
                    proxy.fail_count += 1
                    proxy.consecutive_fails += 1
                    proxy.alive = proxy.consecutive_fails < self.max_fails
                    return False, latency

        except Exception:
            proxy.fail_count += 1
            proxy.consecutive_fails += 1
            proxy.alive = proxy.consecutive_fails < self.max_fails
            proxy.last_check = time.time()
            return False, time.perf_counter() - t0

    # ── 获取代理 ─────────────────────────────────────

    def get(self) -> Optional[str]:
        """随机获取一个可用代理 (按评分加权)"""
        alive = [p for p in self.proxies.values()
                 if p.alive and p.score >= self.min_score]
        if not alive:
            return None

        # 按评分加权随机选择
        scores = [p.score for p in alive]
        total = sum(scores)
        if total <= 0:
            return random.choice(alive).url

        r = random.uniform(0, total)
        cumulative = 0
        for p in alive:
            cumulative += p.score
            if r <= cumulative:
                p.last_used = time.time()
                return p.url

        alive[-1].last_used = time.time()
        return alive[-1].url

    def get_rr(self) -> Optional[str]:
        """轮询获取可用代理"""
        alive = [p for p in self.proxies.values() if p.alive]
        if not alive:
            return None
        self._rr_index = (self._rr_index + 1) % len(alive)
        proxy = alive[self._rr_index]
        proxy.last_used = time.time()
        return proxy.url

    def get_random(self) -> Optional[str]:
        """随机获取代理 (不考虑评分)"""
        alive = [p for p in self.proxies.values() if p.alive]
        if not alive:
            return None
        proxy = random.choice(alive)
        proxy.last_used = time.time()
        return proxy.url

    # ── 反馈 ─────────────────────────────────────────

    def report_success(self, proxy_url: str):
        """报告代理使用成功"""
        if proxy_url in self.proxies:
            p = self.proxies[proxy_url]
            p.success_count += 1
            p.consecutive_fails = 0
            p.alive = True

    def report_fail(self, proxy_url: str):
        """报告代理使用失败"""
        if proxy_url in self.proxies:
            p = self.proxies[proxy_url]
            p.fail_count += 1
            p.consecutive_fails += 1
            if p.consecutive_fails >= self.max_fails:
                p.alive = False

    # ── 统计 ─────────────────────────────────────────

    def stats(self) -> Dict:
        """代理池统计"""
        alive = [p for p in self.proxies.values() if p.alive]
        return {
            "total": len(self.proxies),
            "alive": len(alive),
            "dead": len(self.proxies) - len(alive),
            "avg_latency": round(sum(p.latency for p in alive) / len(alive), 3) if alive else 0,
            "avg_score": round(sum(p.score for p in alive) / len(alive), 1) if alive else 0,
        }

    def list_proxies(self, only_alive: bool = True) -> List[ProxyInfo]:
        """列出代理"""
        proxies = list(self.proxies.values())
        if only_alive:
            proxies = [p for p in proxies if p.alive]
        return sorted(proxies, key=lambda p: p.score, reverse=True)

    def print_stats(self):
        """打印代理池统计"""
        s = self.stats()
        print(f"  📊 代理池统计")
        print(f"  {'─' * 40}")
        print(f"  总数:   {s['total']}")
        print(f"  可用:   {s['alive']}")
        print(f"  不可用: {s['dead']}")
        print(f"  平均延迟: {s['avg_latency']:.3f}s")
        print(f"  平均评分: {s['avg_score']:.1f}")

        # 显示 Top 5
        top5 = self.list_proxies(only_alive=True)[:5]
        if top5:
            print(f"\n  🏆 Top 5 代理:")
            for p in top5:
                print(f"    {p.url:40s} 延迟:{p.latency:.2f}s 成功率:{p.success_rate:.0%} 评分:{p.score:.0f}")

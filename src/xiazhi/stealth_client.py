"""
隐匿 HTTP 客户端
================
集成代理池、UA轮换、限速、WAF绕过的智能 HTTP 客户端

功能:
  - 自动代理轮换 (加权随机)
  - User-Agent 每次请求随机切换
  - 请求头指纹伪装
  - 令牌桶限速 (全局 + per-domain)
  - 失败自动重试 (换代理/换UA)
  - WAF 检测与绕过
  - Cookie 管理
  - 响应缓存

用法:
  client = StealthClient(
      proxy_file="proxies.txt",
      qps=10,
      per_domain_qps=3,
  )
  resp = await client.get("https://target.com/api")
  await client.close()
"""

import asyncio
import random
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx

from .proxy_pool import ProxyPool
from .user_agents import UserAgentPool
from .rate_limiter import RateLimiter
from .waf_bypass import WAFBypass


class StealthClient:
    """隐匿 HTTP 客户端"""

    def __init__(self,
                 proxy_file: str = "",
                 proxy_list: List[str] = None,
                 proxy_env: str = "PROXY_LIST",
                 qps: float = 10.0,
                 burst: int = 20,
                 per_domain_qps: float = 3.0,
                 per_domain_burst: int = 5,
                 timeout: float = 10.0,
                 max_retries: int = 3,
                 verify_ssl: bool = False,
                 follow_redirects: bool = True,
                 enable_waf_bypass: bool = False):
        """
        Args:
            proxy_file: 代理文件路径
            proxy_list: 代理列表
            proxy_env: 代理环境变量名
            qps: 全局每秒请求数
            burst: 全局突发容量
            per_domain_qps: 单域名每秒请求数
            per_domain_burst: 单域名突发容量
            timeout: HTTP 超时
            max_retries: 最大重试次数
            verify_ssl: 验证 SSL
            follow_redirects: 跟随重定向
            enable_waf_bypass: 启用 WAF 绕过
        """
        # 代理池
        self.proxy_pool = ProxyPool()
        if proxy_file:
            self.proxy_pool.load_from_file(proxy_file)
        if proxy_list:
            self.proxy_pool.load_from_list(proxy_list)
        self.proxy_pool.load_from_env(proxy_env)

        # UA 池
        self.ua_pool = UserAgentPool()

        # 限速器
        self.rate_limiter = RateLimiter(
            qps=qps, burst=burst,
            per_domain_qps=per_domain_qps,
            per_domain_burst=per_domain_burst,
        )

        # WAF 绕过
        self.waf_bypass = WAFBypass()
        self.enable_waf_bypass = enable_waf_bypass

        # 配置
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects

        # 状态
        self._request_count = 0
        self._waf_detected_domains: Dict[str, str] = {}
        self._clients: Dict[str, httpx.AsyncClient] = {}
        self._closed = False

        # 统计
        self.stats = {
            "total_requests": 0,
            "successful": 0,
            "failed": 0,
            "retries": 0,
            "waf_detected": 0,
            "proxy_used": 0,
            "proxy_failed": 0,
            "total_wait_time": 0.0,
        }

    async def get(self, url: str, headers: Dict = None,
                  params: Dict = None, **kwargs) -> httpx.Response:
        """GET 请求"""
        return await self.request("GET", url, headers=headers, params=params, **kwargs)

    async def post(self, url: str, headers: Dict = None,
                   data=None, json_data=None, **kwargs) -> httpx.Response:
        """POST 请求"""
        return await self.request("POST", url, headers=headers,
                                  data=data, json_data=json_data, **kwargs)

    async def request(self, method: str, url: str,
                      headers: Dict = None,
                      params: Dict = None,
                      data=None,
                      json_data=None,
                      proxy: str = "",
                      retry_count: int = 0,
                      **kwargs) -> httpx.Response:
        """
        发送隐匿请求

        自动处理:
          - 限速等待
          - 代理轮换
          - UA 切换
          - 头部伪装
          - 失败重试
        """
        if self._closed:
            raise RuntimeError("Client is closed")

        # 提取域名
        parsed = urlparse(url)
        domain = parsed.hostname or ""

        # 限速等待
        wait_time = await self.rate_limiter.acquire(domain)
        self.stats["total_wait_time"] += wait_time

        # WAF 暂停检查
        if self.enable_waf_bypass:
            pause = self.waf_bypass.should_pause(self._request_count)
            if pause > 0:
                await asyncio.sleep(pause)

        # 构建请求头
        req_headers = self._build_headers(domain, headers)

        # 获取代理
        proxy_url = proxy or self._get_proxy()

        # 发送请求
        self._request_count += 1
        self.stats["total_requests"] += 1

        try:
            client = await self._get_client(proxy_url)
            resp = await client.request(
                method, url,
                headers=req_headers,
                params=params,
                data=data,
                json=json_data,
                **kwargs,
            )

            # 检测 WAF
            if self.enable_waf_bypass:
                waf = self.waf_bypass.detect_waf(dict(resp.headers), resp.text)
                if waf:
                    self._waf_detected_domains[domain] = waf
                    self.stats["waf_detected"] += 1

                    # WAF 命中 → 重试 (换代理 + 换 UA)
                    if retry_count < self.max_retries and resp.status_code in (403, 429, 503):
                        if proxy_url:
                            self.proxy_pool.report_fail(proxy_url)
                        self.stats["retries"] += 1
                        await asyncio.sleep(random.uniform(1.0, 3.0))
                        return await self.request(
                            method, url, headers=headers, params=params,
                            data=data, json_data=json_data,
                            retry_count=retry_count + 1, **kwargs
                        )

            # 成功
            if proxy_url:
                self.proxy_pool.report_success(proxy_url)
                self.stats["proxy_used"] += 1
            self.stats["successful"] += 1

            return resp

        except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError):
            if proxy_url:
                self.proxy_pool.report_fail(proxy_url)
                self.stats["proxy_failed"] += 1

            # 重试
            if retry_count < self.max_retries:
                self.stats["retries"] += 1
                await asyncio.sleep(random.uniform(0.5, 2.0))
                return await self.request(
                    method, url, headers=headers, params=params,
                    data=data, json_data=json_data,
                    retry_count=retry_count + 1, **kwargs
                )

            self.stats["failed"] += 1
            raise

        except Exception:
            self.stats["failed"] += 1
            raise

    def _build_headers(self, domain: str, custom_headers: Dict = None) -> Dict:
        """构建隐匿请求头"""
        # 基础隐匿头
        headers = self.waf_bypass.get_stealth_headers(domain)

        # 随机 Referer (40% 概率)
        if random.random() < 0.4:
            headers["Referer"] = self.waf_bypass.get_fake_referer(domain)

        # 合并自定义头 (自定义头优先)
        if custom_headers:
            headers.update(custom_headers)

        return headers

    def _get_proxy(self) -> str:
        """获取代理"""
        if not self.proxy_pool.proxies:
            return ""
        proxy = self.proxy_pool.get()
        return proxy or ""

    async def _get_client(self, proxy: str = "") -> httpx.AsyncClient:
        """获取或创建 HTTP 客户端"""
        key = proxy or "__direct__"

        if key not in self._clients or self._clients[key].is_closed:
            self._clients[key] = httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_ssl,
                follow_redirects=self.follow_redirects,
                max_redirects=5,
                proxy=proxy if proxy else None,
                limits=httpx.Limits(
                    max_keepalive_connections=20,
                    max_connections=50,
                    keepalive_expiry=30,
                ),
            )

        return self._clients[key]

    # ── 域名级配置 ──────────────────────────────────

    def set_domain_qps(self, domain: str, qps: float, burst: int = 5):
        """设置特定域名的速率限制"""
        self.rate_limiter.set_domain_qps(domain, qps, burst)

    def is_waf_detected(self, domain: str) -> Optional[str]:
        """检查域名是否检测到 WAF"""
        return self._waf_detected_domains.get(domain)

    # ── 统计 ─────────────────────────────────────────

    def print_stats(self):
        """打印统计信息"""
        print("\n  📊 隐匿客户端统计")
        print(f"  {'─' * 50}")
        print(f"  总请求:     {self.stats['total_requests']}")
        print(f"  成功:       {self.stats['successful']}")
        print(f"  失败:       {self.stats['failed']}")
        print(f"  重试:       {self.stats['retries']}")
        print(f"  WAF 命中:   {self.stats['waf_detected']}")
        print(f"  代理使用:   {self.stats['proxy_used']}")
        print(f"  代理失败:   {self.stats['proxy_failed']}")
        print(f"  总等待:     {self.stats['total_wait_time']:.2f}s")

        if self._waf_detected_domains:
            print("\n  🛡️  WAF 检测:")
            for domain, waf in self._waf_detected_domains.items():
                print(f"    {domain}: {waf}")

        # 代理池统计
        if self.proxy_pool.proxies:
            self.proxy_pool.print_stats()

    # ── 生命周期 ─────────────────────────────────────

    async def validate_proxies(self, concurrency: int = 20):
        """验证代理池"""
        if not self.proxy_pool.proxies:
            print("  ℹ️  代理池为空，跳过验证")
            return
        print(f"  🔍 验证 {len(self.proxy_pool.proxies)} 个代理...")
        results = await self.proxy_pool.validate_all(concurrency)
        alive = sum(1 for v in results.values() if v)
        print(f"  ✅ 可用: {alive}/{len(results)}")
        self.proxy_pool.print_stats()

    async def close(self):
        """关闭所有连接"""
        self._closed = True
        for client in self._clients.values():
            if not client.is_closed:
                await client.aclose()
        self._clients.clear()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

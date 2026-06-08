"""
破晓 · 反封禁 & 代理池模块
===========================
隐匿扫描 — 避免 WAF/IDS/速率限制封禁

模块:
  - proxy_pool      代理池管理 (加载/验证/轮换)
  - user_agents     User-Agent 池 (浏览器/移动端/爬虫)
  - headers         请求头随机化 & 指纹伪装
  - rate_limiter    令牌桶限速器 (per-domain)
  - waf_bypass      WAF 绕过技术
  - session         智能会话管理 (代理/重试/Cookie)
  - stealth_client  隐匿 HTTP 客户端 (集成所有模块)

CLI:
  poxiao stealth proxy-test https://httpbin.org/ip
  poxiao stealth check-waf https://target.com
"""

from .stealth_client import StealthClient
from .proxy_pool import ProxyPool
from .rate_limiter import RateLimiter

__all__ = ["StealthClient", "ProxyPool", "RateLimiter"]

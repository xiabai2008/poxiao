"""Hunter（奇安信）被动侦察源集成（P1-F / D8）

密钥按源隔离：仅读取 HUNTER_API_KEY / HUNTER_EMAIL 环境变量（或参数）。
降级：无凭证/请求异常时返回带 error 的 HunterResult，不中断整体 recon。
"""

import asyncio
import os
import time
from dataclasses import dataclass, field

import httpx


@dataclass
class HunterResult:
    """Hunter 查询结果"""
    domain: str = ""
    hosts: list = field(default_factory=list)   # [{host, ip, port, title}]
    raw_data: dict = field(default_factory=dict)
    error: str = ""
    source: str = "hunter"

    def to_dict(self):
        """查询结果序列化（domain/hosts/error/source）"""
        return {
            "domain": self.domain,
            "hosts": self.hosts,
            "error": self.error,
            "source": self.source,
        }


class HunterQuery:
    """Hunter API 适配器（域名 → 资产发现）"""

    API_BASE = "https://hunter.qianxin.com/openApi/search"

    def __init__(self, api_key: str = "", email: str = "",
                 timeout: float = 10.0, min_interval: float = 1.0):
        """初始化 Hunter 查询器（API Key/邮箱/超时/限流）"""
        self.api_key = api_key or os.environ.get("HUNTER_API_KEY", "")
        self.email = email or os.environ.get("HUNTER_EMAIL", "")
        self.timeout = timeout
        self.min_interval = min_interval
        self._last_req = 0.0

    @property
    def has_credentials(self) -> bool:
        """是否已配置 Hunter 凭证"""
        return bool(self.api_key and self.email)

    async def _ratelimit(self):
        """相邻请求最小间隔限流"""
        now = time.monotonic()
        elapsed = now - self._last_req
        if elapsed < self.min_interval:
            await asyncio.sleep(self.min_interval - elapsed)
        self._last_req = time.monotonic()

    async def search(self, domain: str, limit: int = 100) -> HunterResult:
        """查询域名相关资产；无凭证或异常时降级返回 error"""
        result = HunterResult(domain=domain)

        if not self.has_credentials:
            result.error = ("No Hunter credentials (set HUNTER_API_KEY/HUNTER_EMAIL env)")
            return result

        await self._ratelimit()
        try:
            page_size = min(limit, 100)
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    self.API_BASE,
                    params={
                        "api-key": self.api_key,
                        "search": f'domain="{domain}"',
                        "page": 1,
                        "page_size": page_size,
                        "is_web": 3,   # 全部资产（含非 Web）
                        "start_time": "2019-01-01",
                        "end_time": time.strftime("%Y-%m-%d"),
                    },
                )
                data = resp.json()
                # Hunter 业务错误: {"code": 非200, "message": "..."}
                if data.get("code") != 200:
                    result.error = str(data.get("message", f"Hunter error HTTP {resp.status_code}"))
                    return result
                if resp.status_code != 200:
                    result.error = f"HTTP {resp.status_code}"
                    return result

                result.raw_data = data
                arr = (data.get("data") or {}).get("arr", [])
                for item in arr:
                    if not isinstance(item, dict):
                        continue
                    result.hosts.append({
                        "host": item.get("domain", "") or item.get("url", ""),
                        "ip": item.get("ip", ""),
                        "port": item.get("port", ""),
                        "title": item.get("web_title", ""),
                    })
        except Exception as e:
            result.error = str(e)[:200]
        return result

    @staticmethod
    def print_result(r: HunterResult):
        """格式化打印 Hunter 查询结果"""
        print("  Hunter 资产")
        print(f"  {'─' * 50}")
        if r.error:
            print(f"  (跳过/降级) {r.error}")
            return
        if r.hosts:
            print(f"  资产: {len(r.hosts)} 个")
            for h in r.hosts[:10]:
                line = f"    {h.get('ip', '')}:{h.get('port', '')}"
                if h.get("host"):
                    line += f"  {h.get('host')}"
                if h.get("title"):
                    line += f"  [{h.get('title')[:30]}]"
                print(line)
            if len(r.hosts) > 10:
                print(f"    ... 共 {len(r.hosts)} 个")
        else:
            print("  无结果")

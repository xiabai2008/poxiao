"""Quake（360 测绘）被动侦察源集成（P1-F / D8）

密钥按源隔离：仅读取 QUAKE_TOKEN 环境变量（或参数）。
降级：无凭证/请求异常时返回带 error 的 QuakeResult，不中断整体 recon。
"""

import asyncio
import os
import time
from dataclasses import dataclass, field

import httpx


@dataclass
class QuakeResult:
    """Quake 查询结果"""
    domain: str = ""
    hosts: list = field(default_factory=list)   # [{host, ip, port, title}]
    raw_data: dict = field(default_factory=dict)
    error: str = ""
    source: str = "quake"

    def to_dict(self):
        """查询结果序列化（domain/hosts/error/source）"""
        return {
            "domain": self.domain,
            "hosts": self.hosts,
            "error": self.error,
            "source": self.source,
        }


class QuakeQuery:
    """Quake API 适配器（域名 → 资产发现）"""

    API_BASE = "https://quake.360.net/api/v3/search/quake_service"

    def __init__(self, token: str = "", timeout: float = 10.0,
                 min_interval: float = 1.0):
        """初始化 Quake 查询器（Token/超时/限流）"""
        self.token = token or os.environ.get("QUAKE_TOKEN", "")
        self.timeout = timeout
        self.min_interval = min_interval
        self._last_req = 0.0

    @property
    def has_credentials(self) -> bool:
        """是否已配置 Quake Token"""
        return bool(self.token)

    async def _ratelimit(self):
        """相邻请求最小间隔限流"""
        now = time.monotonic()
        elapsed = now - self._last_req
        if elapsed < self.min_interval:
            await asyncio.sleep(self.min_interval - elapsed)
        self._last_req = time.monotonic()

    async def search(self, domain: str, limit: int = 100) -> QuakeResult:
        """查询域名相关资产；无凭证或异常时降级返回 error"""
        result = QuakeResult(domain=domain)

        if not self.has_credentials:
            result.error = ("No Quake credentials (set QUAKE_TOKEN env or pass token)")
            return result

        await self._ratelimit()
        try:
            payload = {
                "query": f'domain: "{domain}"',
                "start": 0,
                "size": min(limit, 100),
                "include": ["hostname", "ip", "port", "title"],
            }
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    self.API_BASE,
                    json=payload,
                    headers={"X-QuakeToken": self.token},
                )
                data = resp.json()
                # Quake 业务错误: {"code": 非0, "message": "..."}
                if data.get("code") != 0:
                    result.error = str(data.get("message", f"Quake error HTTP {resp.status_code}"))
                    return result
                if resp.status_code != 200:
                    result.error = f"HTTP {resp.status_code}"
                    return result

                result.raw_data = data
                for item in data.get("data", []):
                    host = ""
                    if isinstance(item.get("hostname"), list) and item["hostname"]:
                        host = item["hostname"][0]
                    elif isinstance(item.get("hostname"), str):
                        host = item["hostname"]
                    result.hosts.append({
                        "host": host,
                        "ip": item.get("ip", ""),
                        "port": item.get("port", ""),
                        "title": item.get("title", ""),
                    })
        except Exception as e:
            result.error = str(e)[:200]
        return result

    @staticmethod
    def print_result(r: QuakeResult):
        """格式化打印 Quake 查询结果"""
        print("  Quake 资产")
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

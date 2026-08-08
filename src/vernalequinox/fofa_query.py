"""FOFA 被动侦察源集成（P2-1 / D8）

密钥按源隔离：本类仅读取自身的 email/key（参数或环境变量），
不影响 Censys / GitHub / Wayback 等其他被动源。
降级：无凭证或请求异常时返回带 error 的 FofaResult，绝不抛出异常中断整体 recon。
限流：相邻请求至少间隔 min_interval 秒，避免触发 FOFA 配额/限流。
"""

import asyncio
import base64
import os
import time
from dataclasses import dataclass, field

import httpx


@dataclass
class FofaResult:
    """FOFA 查询结果"""
    domain: str = ""
    hosts: list = field(default_factory=list)   # [{host, ip, port, title}]
    raw_data: dict = field(default_factory=dict)
    error: str = ""
    source: str = "fofa"

    def to_dict(self):
        return {
            "domain": self.domain,
            "hosts": self.hosts,
            "error": self.error,
            "source": self.source,
        }


class FofaQuery:
    """FOFA API 适配器（域名 → 子域名/资产发现）"""

    API_BASE = "https://fofa.info/api/v1/search/all"
    # 显式声明返回字段顺序，便于按索引解析
    FIELDS = "host,ip,port,title,domain"

    def __init__(self, email: str = "", key: str = "", timeout: float = 10.0,
                 min_interval: float = 1.0):
        # 密钥仅读取自身环境变量，按源隔离
        self.email = email or os.environ.get("FOFA_EMAIL", "")
        self.key = key or os.environ.get("FOFA_KEY", "")
        self.timeout = timeout
        self.min_interval = min_interval
        self._last_req = 0.0

    @property
    def has_credentials(self) -> bool:
        return bool(self.email and self.key)

    async def _ratelimit(self):
        """相邻请求最小间隔限流（可配置）。

        使用 `elapsed < min_interval` 而非严格大于 0 的判断，
        以兼容 Windows 上 time.monotonic() 低分辨率导致相邻调用
        间隔被量化为 0 的情况，确保限流始终生效。
        """
        now = time.monotonic()
        elapsed = now - self._last_req
        if elapsed < self.min_interval:
            await asyncio.sleep(self.min_interval - elapsed)
        self._last_req = time.monotonic()

    async def search(self, domain: str, limit: int = 100) -> FofaResult:
        """查询域名相关资产；无凭证或异常时降级返回 error，不抛异常"""
        result = FofaResult(domain=domain)

        if not self.has_credentials:
            result.error = ("No FOFA credentials (set --fofa-key/--fofa-email "
                            "or FOFA_KEY/FOFA_EMAIL env)")
            return result

        await self._ratelimit()
        try:
            query = f'domain="{domain}"'
            qbase64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    self.API_BASE,
                    params={
                        "email": self.email,
                        "key": self.key,
                        "qbase64": qbase64,
                        "size": min(limit, 100),
                        "fields": self.FIELDS,
                    },
                )
                data = resp.json()
                # FOFA 业务错误（如密钥失效）返回 {"error": true, "errmsg": "..."}
                if data.get("error"):
                    result.error = str(data.get("errmsg", f"FOFA error HTTP {resp.status_code}"))
                    return result
                if resp.status_code != 200:
                    result.error = f"HTTP {resp.status_code}"
                    return result

                result.raw_data = data
                for row in data.get("results", []):
                    if not isinstance(row, (list, tuple)):
                        continue
                    host = row[0] if len(row) > 0 else ""
                    ip = row[1] if len(row) > 1 else ""
                    port = row[2] if len(row) > 2 else ""
                    title = row[3] if len(row) > 3 else ""
                    result.hosts.append({
                        "host": host,
                        "ip": ip,
                        "port": port,
                        "title": title,
                    })
        except Exception as e:
            # 单源失败仅记录，降级（不中断整体 recon）
            result.error = str(e)[:200]
        return result

    @staticmethod
    def print_result(r: FofaResult):
        print("  FOFA 资产")
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

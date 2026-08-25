"""
IP 情报收集模块
===============
查询 IP 地址的详细情报信息

数据源:
  - ip-api.com (免费，无需 API Key，支持批量)
  - ipinfo.io (免费额度)
  - Shodan (需要 API Key)
  - FOFA (需要 API Key，可选)
  - ipip.net (中国 IP 定位更准)
  - BGP/ASN 信息

功能:
  - IP 地理位置 (国家/城市/ISP)
  - ASN 自治系统号
  - 反向 DNS (PTR)
  - Shodan 端口/服务/漏洞信息
  - 同 IP 站点查询 (反向 IP)
  - IP 信誉评分
"""

import asyncio
import os
from dataclasses import dataclass, field, asdict
from typing import List, Dict


@dataclass
class IPInfo:
    """单个 IP 的情报信息"""
    ip: str
    # 地理位置
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = ""
    # 网络
    isp: str = ""                  # ISP 运营商
    org: str = ""                  # 组织
    asn: str = ""                  # ASN 自治系统号 (AS12345)
    as_org: str = ""               # ASN 所属组织
    # 反向 DNS
    reverse_dns: List[str] = field(default_factory=list)
    # Shodan
    shodan_ports: List[int] = field(default_factory=list)
    shodan_services: Dict[int, str] = field(default_factory=dict)  # port → service
    shodan_vulns: List[str] = field(default_factory=list)
    shodan_os: str = ""
    shodan_hostnames: List[str] = field(default_factory=list)
    # 反向 IP
    same_ip_domains: List[str] = field(default_factory=list)
    # 元数据
    is_private: bool = False
    is_cdn: bool = False
    cdn_provider: str = ""
    source: str = ""
    error: str = ""

    def to_dict(self):
        """IP 情报结果序列化"""
        return asdict(self)




class IPCollector:
    """IP 情报收集器"""

    # ── CDN IP 段关键词 ──
    CDN_KEYWORDS = {
        "cloudflare": ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
                       "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
                       "172.67.", "173.245.", "103.21.", "103.22.", "103.31."],
        "akamai": ["23.0.", "23.1.", "23.2.", "23.3.", "23.4.", "23.5.", "23.6.", "23.7.",
                   "23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.", "23.38.", "23.39.",
                   "23.40.", "23.41.", "23.42.", "23.43.", "23.44.", "23.45.", "23.46.", "23.47."],
        "cloudfront": ["13.32.", "13.33.", "13.35.", "13.224.", "13.225.", "13.226.", "13.227.",
                       "54.230.", "54.239.", "99.84.", "99.86."],
        "阿里云CDN": ["47.88.", "47.89.", "47.90.", "47.91.", "47.252.", "47.253.", "47.254.",
                     "8.130.", "8.131.", "8.132.", "8.133.", "8.134.", "8.135.", "8.136.", "8.137."],
        "腾讯云CDN": ["101.89.", "150.109.", "162.14.", "43.129.", "43.130.", "43.131.",
                     "43.132.", "43.133.", "43.134.", "43.135."],
        "华为云CDN": ["114.116.", "117.78.", "121.36.", "122.112."],
    }

    # ── 私有 IP 段 ──
    PRIVATE_IP_PREFIXES = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                           "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                           "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                           "172.30.", "172.31.", "192.168.", "127."]

    def __init__(self, timeout: float = 10.0,
                 shodan_key: str = "", fofa_key: str = ""):
        """初始化 IP 情报收集器（Shodan/PTR/归属）"""
        self.timeout = timeout
        self.shodan_key = shodan_key or os.environ.get("SHODAN_API_KEY", "")
        self.fofa_key = fofa_key or os.environ.get("FOFA_KEY", "")
        self.fofa_email = os.environ.get("FOFA_EMAIL", "")

    async def collect(self, ip: str) -> IPInfo:
        """收集 IP 情报"""
        info = IPInfo(ip=ip)

        # 私有 IP 检测
        if any(ip.startswith(p) for p in self.PRIVATE_IP_PREFIXES):
            info.is_private = True
            info.source = "local"
            return info

        # CDN 检测
        for provider, prefixes in self.CDN_KEYWORDS.items():
            if any(ip.startswith(p) for p in prefixes):
                info.is_cdn = True
                info.cdn_provider = provider
                break

        # 并发查询多个数据源
        tasks = [
            self._query_ipapi(ip),
            self._query_reverse_dns(ip),
        ]
        if self.shodan_key:
            tasks.append(self._query_shodan(ip))
        if self.fofa_key:
            tasks.append(self._query_fofa(ip))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 合并结果
        for r in results:
            if isinstance(r, IPInfo):
                self._merge(info, r)
            elif isinstance(r, Exception):
                info.error += f" | {str(r)}"

        info.source = "multi"
        return info

    def _merge(self, target: IPInfo, source: IPInfo):
        """合并 IP 信息（source 非空覆盖 target）"""
        for fld in ["country", "country_code", "region", "city", "latitude", "longitude",
                     "timezone", "isp", "org", "asn", "as_org", "shodan_os", "cdn_provider"]:
            val = getattr(source, fld)
            if val:
                setattr(target, fld, val)
        if source.reverse_dns:
            target.reverse_dns = list(set(target.reverse_dns + source.reverse_dns))
        if source.shodan_ports:
            target.shodan_ports = list(set(target.shodan_ports + source.shodan_ports))
        if source.shodan_services:
            target.shodan_services.update(source.shodan_services)
        if source.shodan_vulns:
            target.shodan_vulns = list(set(target.shodan_vulns + source.shodan_vulns))
        if source.shodan_hostnames:
            target.shodan_hostnames = list(set(target.shodan_hostnames + source.shodan_hostnames))
        if source.same_ip_domains:
            target.same_ip_domains = list(set(target.same_ip_domains + source.same_ip_domains))

    async def _query_ipapi(self, ip: str) -> IPInfo:
        """通过 ip-api.com 查询地理位置和 ASN"""
        import httpx

        info = IPInfo(ip=ip, source="ip-api")

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,region,city,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"}
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    info.country = data.get("country", "")
                    info.country_code = data.get("countryCode", "")
                    info.region = data.get("region", "")
                    info.city = data.get("city", "")
                    info.latitude = data.get("lat", 0)
                    info.longitude = data.get("lon", 0)
                    info.timezone = data.get("timezone", "")
                    info.isp = data.get("isp", "")
                    info.org = data.get("org", "")

                    # ASN 解析
                    as_str = data.get("as", "")
                    if as_str:
                        parts = as_str.split(" ", 1)
                        info.asn = parts[0]
                        info.as_org = parts[1] if len(parts) > 1 else ""
                    info.as_org = info.as_org or data.get("asname", "")

                    # PTR
                    ptr = data.get("reverse", "")
                    if ptr:
                        info.reverse_dns = [ptr]

        return info

    async def _query_reverse_dns(self, ip: str) -> IPInfo:
        """反向 DNS 查询 (PTR)"""
        import socket

        info = IPInfo(ip=ip, source="ptr")
        loop = asyncio.get_event_loop()

        def _ptr():
            """查询 IP 反向解析（PTR 记录）"""
            try:
                hostname = socket.gethostbyaddr(ip)
                return [hostname[0]] + list(hostname[1])
            except (socket.herror, socket.gaierror):
                return []

        ptrs = await loop.run_in_executor(None, _ptr)
        if ptrs:
            info.reverse_dns = ptrs

        return info

    async def _query_shodan(self, ip: str) -> IPInfo:
        """通过 Shodan 查询 IP 信息"""
        import httpx

        info = IPInfo(ip=ip, source="shodan")

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": self.shodan_key}
            )
            if resp.status_code == 200:
                data = resp.json()

                info.shodan_os = data.get("os", "") or ""
                info.shodan_hostnames = data.get("hostnames", [])

                # 端口和服务
                for svc in data.get("data", []):
                    port = svc.get("port", 0)
                    if port:
                        info.shodan_ports.append(port)
                        product = svc.get("product", "") or svc.get("transport", "")
                        version = svc.get("version", "")
                        info.shodan_services[port] = f"{product} {version}".strip()

                # 漏洞
                vulns = data.get("vulns", [])
                info.shodan_vulns = vulns[:20]  # 最多20个

        return info

    async def _query_fofa(self, ip: str) -> IPInfo:
        """通过 FOFA 查询同 IP 站点"""
        import httpx
        import base64

        info = IPInfo(ip=ip, source="fofa")

        if not self.fofa_email:
            return info

        query = base64.b64encode(f'ip="{ip}"'.encode()).decode()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                "https://fofa.info/api/v1/search/all",
                params={
                    "email": self.fofa_email,
                    "key": self.fofa_key,
                    "qbase64": query,
                    "size": 20,
                    "fields": "host,domain,title",
                }
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("error") is False:
                    for item in data.get("results", []):
                        if len(item) >= 2:
                            info.same_ip_domains.append(item[1])

        return info

    async def batch_collect(self, ips: List[str], concurrency: int = 5) -> List[IPInfo]:
        """批量收集 IP 情报"""
        sem = asyncio.Semaphore(concurrency)

        async def _collect_one(ip):
            """收集单个 IP 的完整情报"""
            async with sem:
                return await self.collect(ip)

        tasks = [_collect_one(ip) for ip in ips]
        return await asyncio.gather(*tasks)

    @staticmethod
    def print_result(info: IPInfo):
        """格式化打印 IP 情报"""
        if info.is_private:
            print(f"  ℹ️  {info.ip} 是私有 IP")
            return

        cdn_tag = f" 🛡️ CDN ({info.cdn_provider})" if info.is_cdn else ""
        print(f"  🔍 IP 情报: {info.ip}{cdn_tag}")
        print(f"  {'─' * 50}")

        # 地理位置
        location_parts = [p for p in [info.country, info.region, info.city] if p]
        if location_parts:
            print(f"  位置:     {' / '.join(location_parts)}")

        # 运营商
        if info.isp:
            print(f"  运营商:   {info.isp}")
        if info.org and info.org != info.isp:
            print(f"  组织:     {info.org}")

        # ASN
        if info.asn:
            print(f"  ASN:      {info.asn} ({info.as_org})")

        # 反向 DNS
        if info.reverse_dns:
            print(f"  PTR:      {', '.join(info.reverse_dns[:3])}")

        # Shodan
        if info.shodan_os:
            print(f"  OS:       {info.shodan_os}")
        if info.shodan_ports:
            ports_str = ", ".join(str(p) for p in sorted(info.shodan_ports)[:15])
            if len(info.shodan_ports) > 15:
                ports_str += f" ... (共{len(info.shodan_ports)}个)"
            print(f"  开放端口: {ports_str}")
        if info.shodan_services:
            for port, svc in list(info.shodan_services.items())[:8]:
                if svc:
                    print(f"    :{port}  {svc}")
        if info.shodan_vulns:
            print(f"  已知漏洞: {', '.join(info.shodan_vulns[:5])}")
            if len(info.shodan_vulns) > 5:
                print(f"    ... 共 {len(info.shodan_vulns)} 个")

        # 同 IP 站点
        if info.same_ip_domains:
            print(f"  同IP站点: {', '.join(info.same_ip_domains[:5])}")
            if len(info.same_ip_domains) > 5:
                print(f"    ... 共 {len(info.same_ip_domains)} 个")

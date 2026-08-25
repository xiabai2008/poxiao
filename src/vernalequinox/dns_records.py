"""
DNS 记录全量枚举模块
====================
查询域名的所有 DNS 记录类型

数据源:
  - DNS 直接查询 (dnspython)
  - DNS over HTTPS (DoH) — Cloudflare / Google / Quad9
  - DNSSEC 验证状态检测

记录类型: A / AAAA / MX / NS / TXT / SOA / CNAME / SRV / CAA / PTR
"""

import asyncio
from dataclasses import dataclass, field, asdict
from typing import List, Dict
from collections import defaultdict

try:
    import dns.resolver
    import dns.rdatatype
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


@dataclass
class DNSRecord:
    """单条 DNS 记录"""
    rtype: str          # 记录类型 (A/MX/NS/TXT等)
    value: str          # 记录值
    ttl: int = 0        # TTL
    priority: int = 0   # 优先级 (MX/SRV)

    def to_dict(self):
        """DNS 收集结果序列化"""
        return asdict(self)


@dataclass
class DNSResult:
    """DNS 全量查询结果"""
    domain: str
    records: Dict[str, List[DNSRecord]] = field(default_factory=lambda: defaultdict(list))
    nameservers: List[str] = field(default_factory=list)
    doh_records: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))
    dnssec_enabled: bool = False
    cname_chain: List[str] = field(default_factory=list)  # CNAME 链
    mx_domains: List[str] = field(default_factory=list)    # 邮件服务器
    spf_record: str = ""                # SPF 记录
    dmarc_record: str = ""              # DMARC 记录
    txt_records: List[str] = field(default_factory=list)   # 所有 TXT 记录
    source: str = "dns"
    error: str = ""

    def to_dict(self):
        """DNS 收集结果序列化（手动构建，规避 defaultdict asdict 陷阱）
        """
        # 注意：不能直接用 dataclasses.asdict(self)——records/doh_records 是
        # defaultdict，asdict 会用 type(obj)(items) 重建，把 items 误当 default_factory，
        # 导致 `TypeError: first argument must be callable or None`。这里手动构建并转普通 dict。
        return {
            "domain": self.domain,
            "records": {k: [r.to_dict() if hasattr(r, "to_dict") else r for r in v]
                        for k, v in self.records.items()},
            "nameservers": list(self.nameservers),
            "doh_records": dict(self.doh_records),
            "dnssec_enabled": self.dnssec_enabled,
            "cname_chain": list(self.cname_chain),
            "mx_domains": list(self.mx_domains),
            "spf_record": self.spf_record,
            "dmarc_record": self.dmarc_record,
            "txt_records": list(self.txt_records),
            "source": self.source,
            "error": self.error,
        }

    @property
    def all_ips(self) -> List[str]:
        """提取所有 IP 地址"""
        ips = []
        for r in self.records.get("A", []):
            ips.append(r.value)
        for r in self.records.get("AAAA", []):
            ips.append(r.value)
        return ips

    @property
    def has_cdn_cname(self) -> bool:
        """判断是否使用 CDN (通过 CNAME 关键词)"""
        cdn_keywords = [
            "cloudflare", "akamai", "fastly", "cloudfront", "cdn",
            "waf", "security", "incapsula", "sucuri", "edgekey",
            "azurewebsites", "amazonaws", "heroku", "vercel", "netlify",
            "qiniu", "tencent", "alicdn", "yunjiasu", "wangsu",
            "chinacache", "cdnfly", "jsdelivr",
        ]
        for r in self.records.get("CNAME", []):
            if any(kw in r.value.lower() for kw in cdn_keywords):
                return True
        return False


class DNSCollector:
    """DNS 记录全量收集器"""

    # 查询的记录类型
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]

    # DoH 服务器
    DOH_SERVERS = {
        "cloudflare": "https://cloudflare-dns.com/dns-query",
        "google": "https://dns.google/resolve",
        "quad9": "https://dns.quad9.net/dns-query",
    }

    def __init__(self, timeout: float = 5.0, doh: bool = True):
        """初始化 DNS 收集器（超时/解析器）"""
        self.timeout = timeout
        self.use_doh = doh

    async def collect(self, domain: str) -> DNSResult:
        """全量 DNS 记录收集"""
        result = DNSResult(domain=domain)

        if not HAS_DNSPYTHON:
            result.error = "dnspython 未安装 (pip install dnspython)"
            return result

        # 1. 逐类型查询
        for rtype in self.RECORD_TYPES:
            try:
                records = await self._query_type(domain, rtype)
                if records:
                    result.records[rtype] = records
            except Exception:
                pass

        # 2. NS 记录 (直接查)
        try:
            ns_records = await self._query_type(domain, "NS")
            if ns_records:
                result.nameservers = [r.value.rstrip(".") for r in ns_records]
        except Exception:
            pass

        # 3. 解析特殊记录
        self._extract_specials(result)

        # 4. CNAME 链追踪
        try:
            result.cname_chain = await self._trace_cname(domain)
        except Exception:
            pass

        # 5. DoH 查询 (交叉验证)
        if self.use_doh:
            try:
                result.doh_records = await self._query_doh(domain)
            except Exception:
                pass

        # 6. DNSSEC 检测
        try:
            result.dnssec_enabled = await self._check_dnssec(domain)
        except Exception:
            pass

        return result

    async def _query_type(self, domain: str, rtype: str) -> List[DNSRecord]:
        """查询指定类型的 DNS 记录"""
        loop = asyncio.get_event_loop()

        def _resolve():
            """解析域名 A/AAAA/TXT/MX/NS 记录"""
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout

            try:
                answers = resolver.resolve(domain, rtype)
                records = []
                for rdata in answers:
                    rec = DNSRecord(
                        rtype=rtype,
                        value=str(rdata).rstrip("."),
                        ttl=answers.rrset.ttl if hasattr(answers, 'rrset') else 0,
                    )
                    # MX 有优先级
                    if rtype == "MX":
                        rec.priority = rdata.preference
                        rec.value = str(rdata.exchange).rstrip(".")
                    # SRV 有优先级和权重
                    elif rtype == "SRV":
                        rec.priority = rdata.priority
                        rec.value = f"{rdata.target.rstrip('.')}:{rdata.port}"
                    records.append(rec)
                return records
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                return []

        return await loop.run_in_executor(None, _resolve)

    async def _query_doh(self, domain: str) -> Dict[str, List[str]]:
        """通过 DNS over HTTPS 查询 (交叉验证)"""
        import httpx

        results = {}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for name, url in self.DOH_SERVERS.items():
                try:
                    params = {"name": domain, "type": "A"}
                    headers = {"Accept": "application/dns-json"}
                    resp = await client.get(url, params=params, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        answers = data.get("Answer", [])
                        ips = [a["data"] for a in answers if a.get("type") == 1]
                        if ips:
                            results[name] = ips
                except Exception:
                    continue

        return results

    async def _trace_cname(self, domain: str, max_hops: int = 10) -> List[str]:
        """追踪 CNAME 链"""
        chain = []
        current = domain
        loop = asyncio.get_event_loop()

        def _resolve_cname(d):
            """解析 CNAME 链"""
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = self.timeout
                answers = resolver.resolve(d, "CNAME")
                return str(answers[0]).rstrip(".")
            except Exception:
                return None

        for _ in range(max_hops):
            cname = await loop.run_in_executor(None, _resolve_cname, current)
            if cname is None or cname in chain:
                break
            chain.append(cname)
            current = cname

        return chain

    async def _check_dnssec(self, domain: str) -> bool:
        """检测是否启用 DNSSEC"""
        loop = asyncio.get_event_loop()

        def _check():
            """检查单条 DNS 记录有效性"""
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = self.timeout
                answers = resolver.resolve(domain, "DNSKEY")
                return len(answers) > 0
            except Exception:
                return False

        return await loop.run_in_executor(None, _check)

    def _extract_specials(self, result: DNSResult):
        """提取特殊记录"""
        # MX 记录 → 邮件服务器
        for r in result.records.get("MX", []):
            result.mx_domains.append(r.value)

        # TXT 记录 → SPF / DMARC / 验证记录
        for r in result.records.get("TXT", []):
            val = r.value
            result.txt_records.append(val)
            if val.lower().startswith("v=spf1"):
                result.spf_record = val
            if "v=dmarc1" in val.lower():
                result.dmarc_record = val

    @staticmethod
    def print_result(r: DNSResult):
        """格式化打印 DNS 结果"""
        print("  🌐 DNS 记录")
        print(f"  {'─' * 50}")

        # A 记录
        for rec in r.records.get("A", []):
            print(f"  A:       {rec.value}  (TTL: {rec.ttl}s)")

        # AAAA 记录
        for rec in r.records.get("AAAA", []):
            print(f"  AAAA:    {rec.value}")

        # CNAME 记录
        for rec in r.records.get("CNAME", []):
            print(f"  CNAME:   {rec.value}")
        if r.cname_chain:
            print(f"  CNAME链: {' → '.join([r.domain] + r.cname_chain)}")

        # MX 记录
        for rec in r.records.get("MX", []):
            print(f"  MX:      {rec.priority} {rec.value}")

        # NS 记录
        ns = r.nameservers or [rec.value for rec in r.records.get("NS", [])]
        if ns:
            print(f"  NS:      {', '.join(ns[:4])}")

        # TXT 记录
        if r.spf_record:
            print(f"  SPF:     {r.spf_record[:80]}")
        if r.dmarc_record:
            print(f"  DMARC:   {r.dmarc_record[:80]}")

        # SOA 记录
        for rec in r.records.get("SOA", []):
            print(f"  SOA:     {rec.value[:80]}")

        # CAA 记录
        for rec in r.records.get("CAA", []):
            print(f"  CAA:     {rec.value}")

        # DNSSEC
        dnssec_icon = "✅" if r.dnssec_enabled else "❌"
        print(f"  DNSSEC:  {dnssec_icon} {'已启用' if r.dnssec_enabled else '未启用'}")

        # CDN 检测
        cdn_icon = "🛡️" if r.has_cdn_cname else "  "
        if r.has_cdn_cname:
            print(f"  {cdn_icon} 检测到 CDN/WAF")

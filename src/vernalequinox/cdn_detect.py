"""
CDN / WAF 检测 & 真实 IP 推断模块
==================================
检测目标是否使用 CDN/WAF，并尝试推断真实 IP

检测方法:
  - CNAME 记录关键词匹配
  - HTTP 响应头指纹
  - 多地 Ping 对比 (多个解析源)
  - 历史 DNS 记录查询
  - 邮件服务器 IP (MX → 真实 IP)
  - 子域名绕过 (非 CDN 子域名)
  - SSL 证书指纹关联
"""

import asyncio
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Tuple

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


@dataclass
class CDNResult:
    """CDN/WAF 检测结果"""
    domain: str
    has_cdn: bool = False
    cdn_provider: str = ""          # CDN 提供商
    waf_detected: bool = False
    waf_name: str = ""              # WAF 名称
    # 真实 IP 推断
    real_ips: List[str] = field(default_factory=list)          # 推断的真实 IP
    real_ip_source: Dict[str, str] = field(default_factory=dict)  # IP → 来源
    # 候选 IP
    mx_ips: List[str] = field(default_factory=list)            # MX 服务器 IP
    sibling_ips: List[str] = field(default_factory=list)       # 兄弟子域名 IP
    historical_ips: List[str] = field(default_factory=list)    # 历史解析 IP
    # 详情
    cname_records: List[str] = field(default_factory=list)
    http_headers: Dict[str, str] = field(default_factory=dict)
    details: List[str] = field(default_factory=list)           # 检测详情
    source: str = ""
    error: str = ""

    def to_dict(self):
        """CDN 检测结果序列化"""
        return asdict(self)

    @property
    def is_behind_cdn(self) -> bool:
        """判断是否处于 CDN/WAF 之后"""
        return self.has_cdn and not self.real_ips


class CDNDetector:
    """CDN / WAF 检测器"""

    # ── CDN CNAME 关键词 ──
    CDN_CNAME_KEYWORDS = {
        "Cloudflare": ["cloudflare", "cf-"],
        "Akamai": ["akamai", "edgekey", "edgesuite"],
        "CloudFront": ["cloudfront"],
        "Fastly": ["fastly", "fastly.net"],
        "Azure CDN": ["azureedge", "azurefd", "trafficmanager"],
        "阿里云CDN": ["alikunlun", "alicdn", "kunlun"],
        "腾讯云CDN": ["cdn-dragon", "tdnsv5", "wsdvs", "tencent-cdn"],
        "华为云CDN": ["cdnhwc", "huaweicloud"],
        "网宿CDN": ["wscdn", "wangsu", "chinacache"],
        "百度云CDN": ["bdydns", "bcecdn"],
        "七牛CDN": ["qiniucdn", "qnssl", "clouddn"],
        "又拍云CDN": ["upaiyun", "upyun"],
        "Cloudflare (WAF)": ["yunjiasu"],
        "Imperva/Incapsula": ["incapdns", "impervadns"],
        "Sucuri": ["sucuri"],
        "StackPath": ["stackpathdns", "highwinds"],
    }

    # ── WAF HTTP Header 指纹 ──
    WAF_HEADER_FINGERPRINTS = {
        "Cloudflare": {"server": "cloudflare", "cf-ray": ""},
        "Akamai": {"x-akamai": "", "akamai": ""},
        "AWS WAF": {"x-amzn-requestid": "", "x-amz-cf-id": ""},
        "Incapsula": {"x-iinfo": "", "incap_ses": ""},
        "Sucuri": {"x-sucuri-id": "", "server": "sucuri"},
        "ModSecurity": {"server": "mod_security", "x-mod-security": ""},
        "F5 BIG-IP": {"server": "BIG-IP", "x-cnection": ""},
        "华为云WAF": {"x-hw-waf": ""},
        "腾讯云WAF": {"x-tw-waf": ""},
        "阿里云WAF": {"eagleid": "", "x-hs": ""},
    }

    # ── 常见非 CDN 子域名 (可用于获取真实 IP) ──
    SIBLING_PREFIXES = [
        "mail", "smtp", "pop", "imap", "ftp", "vpn", "oa", "crm", "erp",
        "git", "svn", "jenkins", "jira", "confluence", "dev", "test",
        "staging", "beta", "pre", "uat", "admin", "manage", "internal",
        "db", "mysql", "redis", "mongo", "api-internal", "gateway",
    ]

    def __init__(self, timeout: float = 8.0):
        """初始化 CDN 检测器（超时）"""
        self.timeout = timeout

    async def detect(self, domain: str, ip: str = "") -> CDNResult:
        """检测域名的 CDN/WAF 使用情况"""
        result = CDNResult(domain=domain)

        # 并发检测
        tasks = [
            self._check_cname(domain),
            self._check_http_headers(domain),
            self._check_mx_ips(domain),
            self._check_sibling_subdomains(domain),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # CNAME 检测
        if isinstance(results[0], dict):
            for provider, cnames in results[0].items():
                result.has_cdn = True
                result.cdn_provider = provider
                result.cname_records = cnames
                result.details.append(f"CNAME 命中 {provider}: {', '.join(cnames[:2])}")

        # HTTP Header 检测
        if isinstance(results[1], dict):
            headers, waf = results[1]
            result.http_headers = headers
            if waf:
                result.waf_detected = True
                result.waf_name = waf
                if not result.cdn_provider:
                    result.cdn_provider = waf
                result.has_cdn = True
                result.details.append(f"HTTP Header 命中 WAF: {waf}")

        # MX IP 检测
        if isinstance(results[2], list):
            result.mx_ips = results[2]
            if results[2]:
                result.details.append(f"MX 服务器 IP: {', '.join(results[2][:3])}")
                # MX 服务器 IP 通常是真实 IP
                for mx_ip in results[2]:
                    if not self._is_cdn_ip(mx_ip):
                        result.real_ips.append(mx_ip)
                        result.real_ip_source[mx_ip] = "MX服务器"

        # 兄弟子域名检测
        if isinstance(results[3], list):
            result.sibling_ips = results[3]
            if results[3]:
                result.details.append(f"兄弟子域名 IP: {', '.join(results[3][:3])}")
                for sib_ip in results[3]:
                    if sib_ip not in result.real_ips and not self._is_cdn_ip(sib_ip):
                        result.real_ips.append(sib_ip)
                        result.real_ip_source[sib_ip] = "兄弟子域名"

        result.source = "multi"
        return result

    async def _check_cname(self, domain: str) -> Dict[str, List[str]]:
        """检查 CNAME 记录是否指向 CDN"""
        if not HAS_DNSPYTHON:
            return {}

        loop = asyncio.get_event_loop()
        cdn_hits = {}

        def _resolve():
            """DNS 解析变体（A/CNAME/NS 记录）"""
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = self.timeout
                answers = resolver.resolve(domain, "CNAME")
                cnames = [str(r).rstrip(".") for r in answers]
                return cnames
            except Exception:
                return []

        cnames = await loop.run_in_executor(None, _resolve)

        for cname in cnames:
            for provider, keywords in self.CDN_CNAME_KEYWORDS.items():
                if any(kw in cname.lower() for kw in keywords):
                    cdn_hits.setdefault(provider, []).append(cname)

        return cdn_hits

    async def _check_http_headers(self, domain: str) -> Tuple[Dict[str, str], str]:
        """检查 HTTP 响应头中的 WAF 指纹"""
        import httpx

        headers = {}
        waf = ""

        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
                resp = await client.get(f"https://{domain}", headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                })
                headers = dict(resp.headers)

                # 检测 WAF 指纹
                for waf_name, fingerprints in self.WAF_HEADER_FINGERPRINTS.items():
                    for key, value in fingerprints.items():
                        # 检查 header 是否存在
                        for h_key, h_val in headers.items():
                            if key.lower() in h_key.lower():
                                if not value or value.lower() in h_val.lower():
                                    waf = waf_name
                                    return headers, waf
        except Exception:
            pass

        return headers, waf

    async def _check_mx_ips(self, domain: str) -> List[str]:
        """获取 MX 服务器的 IP 地址"""
        if not HAS_DNSPYTHON:
            return []

        loop = asyncio.get_event_loop()

        def _resolve():
            """线程池执行：解析 MX 服务器 A 记录"""
            ips = []
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = self.timeout
                mx_records = resolver.resolve(domain, "MX")
                for mx in mx_records:
                    mx_host = str(mx.exchange).rstrip(".")
                    try:
                        a_records = resolver.resolve(mx_host, "A")
                        for a in a_records:
                            ips.append(str(a))
                    except Exception:
                        pass
            except Exception:
                pass
            return ips

        return await loop.run_in_executor(None, _resolve)

    async def _check_sibling_subdomains(self, domain: str) -> List[str]:
        """检查常见非 CDN 子域名的 IP"""
        if not HAS_DNSPYTHON:
            return []

        loop = asyncio.get_event_loop()
        # 处理多段 TLD（如 .co.uk, .com.cn, .github.io）
        parts = domain.split(".")
        if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org", "gov", "edu", "ac", "me", "io"):
            base_domain = ".".join(parts[-3:])
        else:
            base_domain = ".".join(parts[-2:])

        def _resolve():
            """线程池执行：解析常见非 CDN 子域名的 A 记录"""
            ips = []
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.0

            for prefix in self.SIBLING_PREFIXES[:15]:  # 限制数量
                subdomain = f"{prefix}.{base_domain}"
                try:
                    answers = resolver.resolve(subdomain, "A")
                    for a in answers:
                        ip = str(a)
                        if ip not in ips:
                            ips.append(ip)
                except Exception:
                    pass
            return ips

        return await loop.run_in_executor(None, _resolve)

    def _is_cdn_ip(self, ip: str) -> bool:
        """判断 IP 是否属于已知 CDN"""
        cdn_prefixes = [
            "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
            "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
            "172.67.", "173.245.", "103.21.", "103.22.", "103.31.",
            "23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.",
            "13.32.", "13.33.", "13.35.", "13.224.", "13.225.",
            "99.84.", "99.86.",
        ]
        return any(ip.startswith(p) for p in cdn_prefixes)

    @staticmethod
    def print_result(r: CDNResult):
        """格式化打印 CDN 检测结果"""
        print("  🛡️ CDN / WAF 检测")
        print(f"  {'─' * 50}")

        if r.has_cdn:
            print(f"  CDN:      ✅ {r.cdn_provider}")
        else:
            print("  CDN:      ❌ 未检测到")

        if r.waf_detected:
            print(f"  WAF:      ✅ {r.waf_name}")

        if r.cname_records:
            print(f"  CNAME:    {', '.join(r.cname_records[:3])}")

        if r.real_ips:
            print("\n  🎯 推断真实 IP:")
            for ip in r.real_ips[:5]:
                source = r.real_ip_source.get(ip, "unknown")
                print(f"    {ip}  ({source})")
        elif r.has_cdn:
            print("\n  ⚠️  检测到 CDN，未能推断真实 IP")
            print("  建议: 尝试 MX / 子域名 / 历史 DNS / SSL 证书指纹关联")

        if r.mx_ips:
            print(f"\n  📧 MX IP: {', '.join(r.mx_ips[:3])}")

        if r.sibling_ips:
            print(f"  🔗 兄弟子域名 IP: {', '.join(r.sibling_ips[:5])}")

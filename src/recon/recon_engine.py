"""
破晓 · 被动信息收集编排引擎
============================
一键全量被动情报收集 — 不主动触碰目标

用法:
  recon = ReconEngine()
  report = await recon.full_recon("example.com")
  recon.print_report(report)

CLI:
  poxiao recon example.com
  poxiao recon example.com --shodan-key YOUR_KEY
  poxiao recon example.com -o report.json
"""

import asyncio
import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from pathlib import Path

from .whois_lookup import WhoisLookup, WhoisResult
from .icp_query import ICPQuery, ICPResult
from .dns_records import DNSCollector, DNSResult
from .ip_info import IPCollector, IPInfo
from .cdn_detect import CDNDetector, CDNResult
from .cert_info import CertAnalyzer, CertInfo


@dataclass
class ReconReport:
    """被动信息收集汇总报告"""
    domain: str
    scan_time: float = 0.0              # 耗时 (秒)
    timestamp: str = ""                 # 扫描时间

    # 各模块结果
    whois: Optional[WhoisResult] = None
    icp: Optional[ICPResult] = None
    dns: Optional[DNSResult] = None
    cdn: Optional[CDNResult] = None
    cert: Optional[CertInfo] = None
    ip_details: List[IPInfo] = field(default_factory=list)

    # 汇总信息
    all_ips: List[str] = field(default_factory=list)
    all_domains: List[str] = field(default_factory=list)
    all_emails: List[str] = field(default_factory=list)
    open_ports_summary: Dict[str, List[int]] = field(default_factory=dict)  # ip → ports
    vulns_summary: Dict[str, List[str]] = field(default_factory=dict)       # ip → vulns
    risk_indicators: List[str] = field(default_factory=list)  # 风险指标

    source: str = ""
    error: str = ""

    def to_dict(self):
        d = {
            "domain": self.domain,
            "scan_time": round(self.scan_time, 2),
            "timestamp": self.timestamp,
            "all_ips": self.all_ips,
            "all_domains": self.all_domains,
            "all_emails": self.all_emails,
            "open_ports_summary": self.open_ports_summary,
            "vulns_summary": self.vulns_summary,
            "risk_indicators": self.risk_indicators,
        }
        if self.whois:
            d["whois"] = self.whois.to_dict()
        if self.icp:
            d["icp"] = self.icp.to_dict()
        if self.dns:
            d["dns"] = self.dns.to_dict()
        if self.cdn:
            d["cdn"] = self.cdn.to_dict()
        if self.cert:
            d["cert"] = self.cert.to_dict()
        if self.ip_details:
            d["ip_details"] = [ip.to_dict() for ip in self.ip_details]
        return d


class ReconEngine:
    """被动信息收集编排引擎"""

    def __init__(self, timeout: float = 10.0,
                 shodan_key: str = "", fofa_key: str = "",
                 skip_shodan: bool = False, skip_fofa: bool = False):
        self.timeout = timeout
        self.whois = WhoisLookup(timeout=timeout)
        self.icp = ICPQuery(timeout=timeout)
        self.dns = DNSCollector(timeout=timeout)
        self.cdn = CDNDetector(timeout=timeout)
        self.cert = CertAnalyzer(timeout=timeout)
        self.ip = IPCollector(
            timeout=timeout,
            shodan_key="" if skip_shodan else shodan_key,
            fofa_key="" if skip_fofa else fofa_key,
        )

    async def full_recon(self, domain: str) -> ReconReport:
        """全量被动信息收集"""
        report = ReconReport(domain=domain)
        t0 = time.perf_counter()

        from datetime import datetime
        report.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ═══ 阶段 1: 并发查询 DNS + Whois + ICP + 证书 ═══
        print(f"  [1/4] 并发收集基础情报...")
        phase1 = await asyncio.gather(
            self.dns.collect(domain),
            self.whois.query(domain),
            self.icp.query(domain),
            self.cert.analyze(domain),
            return_exceptions=True,
        )

        # DNS
        if isinstance(phase1[0], DNSResult):
            report.dns = phase1[0]
            report.all_ips = phase1[0].all_ips

        # Whois
        if isinstance(phase1[1], WhoisResult):
            report.whois = phase1[1]

        # ICP
        if isinstance(phase1[2], ICPResult):
            report.icp = phase1[2]

        # Certificate
        if isinstance(phase1[3], CertInfo):
            report.cert = phase1[3]
            # 证书中的子域名
            if phase1[3].san_domains:
                report.all_domains.extend(phase1[3].san_domains)
            if phase1[3].crt_sh_all_domains:
                report.all_domains.extend(phase1[3].crt_sh_all_domains)
            # 证书中的 IP
            if phase1[3].san_ips:
                report.all_ips.extend(phase1[3].san_ips)

        # ═══ 阶段 2: CDN/WAF 检测 ═══
        print(f"  [2/4] CDN/WAF 检测...")
        report.cdn = await self.cdn.detect(domain, report.all_ips[0] if report.all_ips else "")

        # 合并真实 IP
        if report.cdn.real_ips:
            for ip in report.cdn.real_ips:
                if ip not in report.all_ips:
                    report.all_ips.append(ip)

        # ═══ 阶段 3: IP 情报 ═══
        unique_ips = list(set(report.all_ips))
        if unique_ips:
            print(f"  [3/4] IP 情报收集 ({len(unique_ips)} 个 IP)...")
            report.ip_details = await self.ip.batch_collect(unique_ips, concurrency=3)

            # 汇总端口和漏洞
            for ip_info in report.ip_details:
                if ip_info.shodan_ports:
                    report.open_ports_summary[ip_info.ip] = ip_info.shodan_ports
                if ip_info.shodan_vulns:
                    report.vulns_summary[ip_info.ip] = ip_info.shodan_vulns

        # ═══ 阶段 4: 汇总分析 ═══
        print(f"  [4/4] 汇总分析...")
        self._analyze_risks(report)
        self._extract_emails(report)

        # 去重
        report.all_ips = sorted(set(report.all_ips))
        report.all_domains = sorted(set(d for d in report.all_domains
                                       if d and "*" not in d))

        report.scan_time = time.perf_counter() - t0
        report.source = "recon_engine"

        return report

    def _analyze_risks(self, report: ReconReport):
        """分析风险指标"""
        risks = report.risk_indicators

        # 1. 证书过期
        if report.cert and report.cert.is_expired:
            risks.append("🔴 SSL 证书已过期")

        # 2. 证书即将过期
        if report.cert and 0 < report.cert.days_until_expiry < 30:
            risks.append(f"🟡 SSL 证书将在 {report.cert.days_until_expiry} 天后过期")

        # 3. 自签名证书
        if report.cert and report.cert.is_self_signed:
            risks.append("🟡 使用自签名证书")

        # 4. DNSSEC 未启用
        if report.dns and not report.dns.dnssec_enabled:
            risks.append("ℹ️  DNSSEC 未启用")

        # 5. SPF/DMARC 缺失
        if report.dns:
            if not report.dns.spf_record:
                risks.append("ℹ️  SPF 记录缺失 (邮件欺骗风险)")
            if not report.dns.dmarc_record:
                risks.append("ℹ️  DMARC 记录缺失 (邮件欺骗风险)")

        # 6. Shodan 漏洞
        for ip, vulns in report.vulns_summary.items():
            if vulns:
                risks.append(f"🔴 {ip} 存在 {len(vulns)} 个已知漏洞: {', '.join(vulns[:3])}")

        # 7. 敏感端口
        sensitive_ports = {21: "FTP", 23: "Telnet", 3389: "RDP", 6379: "Redis",
                          27017: "MongoDB", 3306: "MySQL", 5432: "PostgreSQL",
                          9200: "Elasticsearch", 11211: "Memcached", 2375: "Docker"}
        for ip, ports in report.open_ports_summary.items():
            for port in ports:
                if port in sensitive_ports:
                    risks.append(f"🟡 {ip}:{port} ({sensitive_ports[port]}) 开放 — 可能存在未授权访问")

        # 8. 境外服务器
        if report.icp and report.icp.has_record:
            for ip_info in report.ip_details:
                if ip_info.country_code and ip_info.country_code not in ("CN", ""):
                    risks.append(f"ℹ️  备案域名使用境外 IP: {ip_info.ip} ({ip_info.country})")

    def _extract_emails(self, report: ReconReport):
        """从各模块提取邮箱"""
        emails = set()

        # Whois 注册邮箱
        if report.whois and report.whois.registrant_email:
            emails.add(report.whois.registrant_email)

        # Whois 原始文本中的邮箱
        if report.whois and report.whois.raw_text:
            import re
            found = re.findall(r'[\w.-]+@[\w.-]+\.\w+', report.whois.raw_text)
            emails.update(found)

        report.all_emails = sorted(emails)

    async def quick_recon(self, domain: str) -> ReconReport:
        """快速被动收集 (仅 DNS + Whois + 证书，跳过 IP 深度)"""
        report = ReconReport(domain=domain)
        t0 = time.perf_counter()

        from datetime import datetime
        report.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        results = await asyncio.gather(
            self.dns.collect(domain),
            self.whois.query(domain),
            self.cert.analyze(domain),
            return_exceptions=True,
        )

        if isinstance(results[0], DNSResult):
            report.dns = results[0]
            report.all_ips = results[0].all_ips
        if isinstance(results[1], WhoisResult):
            report.whois = results[1]
        if isinstance(results[2], CertInfo):
            report.cert = results[2]
            report.all_domains = results[2].san_domains + results[2].crt_sh_all_domains

        report.scan_time = time.perf_counter() - t0
        report.source = "quick_recon"
        return report

    def save_report(self, report: ReconReport, output_path: str = "") -> str:
        """保存报告为 JSON"""
        if not output_path:
            safe_name = report.domain.replace(".", "_").replace(":", "_")
            output_path = f"scan_results/recon_{safe_name}.json"

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str),
            encoding="utf-8"
        )
        return str(path)

    @staticmethod
    def print_report(report: ReconReport):
        """格式化打印完整报告"""
        print()
        print(f"{'═' * 60}")
        print(f"  🔍 破晓 · 被动信息收集报告")
        print(f"  目标: {report.domain}")
        print(f"  时间: {report.timestamp}  |  耗时: {report.scan_time:.1f}s")
        print(f"{'═' * 60}")

        # Whois
        print()
        if report.whois:
            WhoisLookup.print_result(report.whois)

        # ICP
        print()
        if report.icp:
            ICPQuery.print_result(report.icp)

        # DNS
        print()
        if report.dns:
            DNSCollector.print_result(report.dns)

        # CDN
        print()
        if report.cdn:
            CDNDetector.print_result(report.cdn)

        # Certificate
        print()
        if report.cert:
            CertAnalyzer.print_result(report.cert)

        # IP 情报
        if report.ip_details:
            print()
            for ip_info in report.ip_details:
                IPCollector.print_result(ip_info)
                print()

        # 风险指标
        if report.risk_indicators:
            print(f"  ⚡ 风险指标")
            print(f"  {'─' * 50}")
            for risk in report.risk_indicators:
                print(f"  {risk}")
            print()

        # 汇总
        print(f"  📊 汇总")
        print(f"  {'─' * 50}")
        print(f"  IP 地址:   {len(report.all_ips)} 个")
        if report.all_ips:
            for ip in report.all_ips[:5]:
                print(f"    {ip}")
            if len(report.all_ips) > 5:
                print(f"    ... 共 {len(report.all_ips)} 个")

        print(f"  子域名:   {len(report.all_domains)} 个 (来自证书透明度)")
        if report.all_domains:
            for d in report.all_domains[:8]:
                print(f"    {d}")
            if len(report.all_domains) > 8:
                print(f"    ... 共 {len(report.all_domains)} 个")

        if report.all_emails:
            print(f"  邮箱:     {', '.join(report.all_emails[:5])}")

        if report.open_ports_summary:
            total_ports = sum(len(v) for v in report.open_ports_summary.values())
            print(f"  开放端口: {total_ports} 个 (跨 {len(report.open_ports_summary)} 个 IP)")

        if report.vulns_summary:
            total_vulns = sum(len(v) for v in report.vulns_summary.values())
            print(f"  已知漏洞: {total_vulns} 个")

        print(f"\n{'═' * 60}")

"""被动侦察模块单元测试（DNS / 证书 / IP / CDN 结果对象、解析、编排引擎）"""

import asyncio
from collections import defaultdict
from unittest.mock import AsyncMock, MagicMock, patch

from src.vernalequinox.dns_records import DNSCollector, DNSResult, DNSRecord
from src.vernalequinox.cert_info import CertAnalyzer, CertInfo
from src.vernalequinox.ip_info import IPCollector, IPInfo
from src.vernalequinox.cdn_detect import CDNDetector, CDNResult
from src.vernalequinox.engine import ReconEngine
from src.vernalequinox.whois_lookup import WhoisResult
from src.vernalequinox.icp_query import ICPResult
from src.vernalequinox.wayback import WaybackResult


def _make_client(json_data, status=200):
    fake_resp = MagicMock()
    fake_resp.status_code = status
    fake_resp.json.return_value = json_data
    fake_client = MagicMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(return_value=fake_resp)
    return fake_client


# ── DNS ──────────────────────────────────────────────

class TestDNSResult:
    def test_all_ips(self):
        r = DNSResult(domain="x.com")
        r.records["A"] = [DNSRecord("A", "1.2.3.4")]
        r.records["AAAA"] = [DNSRecord("AAAA", "::1")]
        assert "1.2.3.4" in r.all_ips and "::1" in r.all_ips

    def test_has_cdn_cname(self):
        r = DNSResult(domain="x.com")
        r.records["CNAME"] = [DNSRecord("CNAME", "xxx.cloudflare.net")]
        assert r.has_cdn_cname is True

    def test_no_cdn_cname(self):
        r = DNSResult(domain="x.com")
        r.records["CNAME"] = [DNSRecord("CNAME", "host.example.com")]
        assert r.has_cdn_cname is False

    def test_to_dict(self):
        r = DNSResult(domain="x.com")
        r.records["A"] = [DNSRecord("A", "1.2.3.4")]
        d = r.to_dict()
        assert d["domain"] == "x.com"
        assert d["records"]["A"][0]["value"] == "1.2.3.4"


class TestDNSCollector:
    def test_extract_specials(self):
        r = DNSResult(domain="x.com")
        r.records["MX"] = [DNSRecord("MX", "mail.x.com", priority=10)]
        r.records["TXT"] = [
            DNSRecord("TXT", "v=spf1 include:_spf.x.com ~all"),
            DNSRecord("TXT", "v=DMARC1; p=reject"),
        ]
        DNSCollector()._extract_specials(r)
        assert r.mx_domains == ["mail.x.com"]
        assert r.spf_record.startswith("v=spf1")
        assert r.dmarc_record.startswith("v=DMARC1")

    def test_collect_no_dnspython(self, monkeypatch):
        monkeypatch.setattr("src.vernalequinox.dns_records.HAS_DNSPYTHON", False)
        r = asyncio.run(DNSCollector().collect("x.com"))
        assert r.error

    def test_print_result(self, capsys):
        r = DNSResult(domain="x.com")
        r.records["A"] = [DNSRecord("A", "1.2.3.4", ttl=300)]
        r.cname_chain = ["cd.x.com"]
        r.dnssec_enabled = True
        r.records["CNAME"] = [DNSRecord("CNAME", "x.cloudflare.net")]
        DNSCollector.print_result(r)
        out = capsys.readouterr().out
        assert "1.2.3.4" in out
        assert "DNSSEC" in out


# ── 证书 ──────────────────────────────────────────────

class TestCertInfo:
    def test_days_until_expiry_future(self):
        c = CertInfo(domain="x", not_after="2030-01-01T00:00:00")
        assert c.days_until_expiry > 0

    def test_days_until_expiry_past(self):
        c = CertInfo(domain="x", not_after="2000-01-01T00:00:00")
        assert c.days_until_expiry < 0

    def test_days_until_expiry_empty(self):
        assert CertInfo(domain="x").days_until_expiry == -1

    def test_to_dict(self):
        c = CertInfo(domain="x", subject_cn="x")
        assert c.to_dict()["subject_cn"] == "x"


class TestCertAnalyzer:
    def test_parse_cert_text(self):
        a = CertAnalyzer()
        info = CertInfo(domain="x.com")
        cert_text = {
            "subject": ((("commonName", "example.com"),),
                       (("organizationName", "Example Org"),)),
            "issuer": ((("organizationName", "Example Org"),),),
            "subjectAltName": (("DNS", "www.example.com"),
                               ("DNS", "*.example.com"),
                               ("IP", "1.2.3.4")),
            "notBefore": "2020-01-01T00:00:00",
            "notAfter": "2030-01-01T00:00:00",
            "serialNumber": "ABC",
        }
        a._parse_cert_text(cert_text, info)
        assert info.subject_cn == "example.com"
        assert "www.example.com" in info.san_domains
        assert info.is_wildcard is True
        assert info.san_ips == ["1.2.3.4"]
        assert info.is_self_signed is True
        assert info.not_after == "2030-01-01T00:00:00"
        assert info.days_until_expiry > 0

    def test_analyze(self):
        a = CertAnalyzer()
        live = CertInfo(domain="x", subject_cn="x", san_domains=["a.com"], is_expired=False)
        crt = {"count": 2, "certs": [{"id": 1}], "all_domains": ["b.com", "c.com"]}
        a._get_live_cert = AsyncMock(return_value=live)
        a._query_crtsh = AsyncMock(return_value=crt)
        info = asyncio.run(a.analyze("x.com"))
        assert info.subject_cn == "x"
        assert info.crt_sh_count == 2
        assert "b.com" in info.crt_sh_all_domains

    def test_find_related(self):
        a = CertAnalyzer()
        live = CertInfo(domain="x", san_domains=["sub.x.com"])
        crt = {"count": 1, "certs": [{"issuer_ca_id": 1}], "all_domains": ["other.com"]}
        a._get_live_cert = AsyncMock(return_value=live)
        a._query_crtsh = AsyncMock(return_value=crt)
        related = asyncio.run(a.find_related_domains("x.com"))
        assert "sub.x.com" in related and "other.com" in related

    def test_print_result_error(self, capsys):
        CertAnalyzer.print_result(CertInfo(domain="x", error="boom"))
        assert "失败" in capsys.readouterr().out

    def test_print_result_ok(self, capsys):
        c = CertInfo(domain="x", subject_cn="x", san_domains=["a.com"])
        CertAnalyzer.print_result(c)
        assert "SAN" in capsys.readouterr().out


# ── IP 情报 ───────────────────────────────────────────

class TestIPInfo:
    def test_to_dict(self):
        assert IPInfo(ip="1.2.3.4").to_dict()["ip"] == "1.2.3.4"

    def test_collect_private(self):
        info = asyncio.run(IPCollector().collect("10.0.0.1"))
        assert info.is_private is True

    def test_collect_cdn(self):
        info = asyncio.run(IPCollector().collect("104.16.0.1"))
        assert info.is_cdn is True
        assert info.cdn_provider == "cloudflare"


class TestIPCollector:
    def test_merge(self):
        t = IPInfo(ip="1.2.3.4")
        s = IPInfo(ip="1.2.3.4", country="US", shodan_ports=[80],
                   shodan_services={80: "http"}, shodan_vulns=["CVE-1"])
        IPCollector()._merge(t, s)
        assert t.country == "US"
        assert t.shodan_ports == [80]
        assert t.shodan_services[80] == "http"
        assert t.shodan_vulns == ["CVE-1"]

    def test_query_ipapi(self):
        data = {
            "status": "success", "country": "US", "countryCode": "US",
            "region": "CA", "city": "LA", "lat": 1.0, "lon": 2.0,
            "timezone": "UTC", "isp": "ISP", "org": "Org",
            "as": "AS123 ISP", "asname": "ISPNAME", "reverse": "host.x.com",
        }
        c = IPCollector()
        with patch("httpx.AsyncClient", return_value=_make_client(data)):
            info = asyncio.run(c._query_ipapi("1.2.3.4"))
        assert info.country == "US"
        assert info.asn == "AS123"
        assert info.reverse_dns == ["host.x.com"]

    def test_batch_collect(self, monkeypatch):
        c = IPCollector()
        c.collect = AsyncMock(return_value=IPInfo(ip="1.2.3.4", country="US"))
        res = asyncio.run(c.batch_collect(["1.2.3.4"]))
        assert res[0].country == "US"

    def test_print_result_private(self, capsys):
        IPCollector.print_result(IPInfo(ip="10.0.0.1", is_private=True))
        assert "私有" in capsys.readouterr().out

    def test_print_result_full(self, capsys):
        info = IPInfo(ip="1.2.3.4", country="US", isp="ISP", asn="AS1",
                      shodan_ports=[80], shodan_vulns=["CVE-1"])
        IPCollector.print_result(info)
        out = capsys.readouterr().out
        assert "1.2.3.4" in out and "AS1" in out


# ── CDN / WAF ────────────────────────────────────────

class TestCDNResult:
    def test_is_behind_cdn(self):
        assert CDNResult(domain="x", has_cdn=True).is_behind_cdn is True
        assert CDNResult(domain="x", has_cdn=True, real_ips=["1.2.3.4"]).is_behind_cdn is False

    def test_to_dict(self):
        assert CDNResult(domain="x").to_dict()["domain"] == "x"


class TestCDNDetector:
    def test_is_cdn_ip(self):
        assert CDNDetector()._is_cdn_ip("104.16.0.1") is True
        assert CDNDetector()._is_cdn_ip("8.8.8.8") is False

    def test_check_http_headers_waf(self):
        d = CDNDetector()
        client = _make_client({})
        client.get = AsyncMock(return_value=MagicMock(
            status_code=200, headers={"server": "cloudflare"}
        ))
        with patch("httpx.AsyncClient", return_value=client):
            headers, waf = asyncio.run(d._check_http_headers("x.com"))
        assert waf == "Cloudflare"
        assert "server" in headers

    def test_detect_orchestration(self):
        d = CDNDetector()
        d._check_cname = AsyncMock(return_value={"Cloudflare": ["x.cloudflare.net"]})
        d._check_http_headers = AsyncMock(return_value=({}, ""))
        d._check_mx_ips = AsyncMock(return_value=["9.9.9.9"])
        d._check_sibling_subdomains = AsyncMock(return_value=["8.8.8.8"])
        r = asyncio.run(d.detect("x.com"))
        assert r.has_cdn is True
        assert r.cdn_provider == "Cloudflare"
        assert "9.9.9.9" in r.real_ips
        assert "8.8.8.8" in r.real_ips

    def test_print_result(self, capsys):
        r = CDNResult(domain="x", has_cdn=True, cdn_provider="Cloudflare",
                      real_ips=["1.2.3.4"])
        CDNDetector.print_result(r)
        assert "Cloudflare" in capsys.readouterr().out


# ── 编排引擎 ──────────────────────────────────────────

class TestReconEngine:
    def _mocked_engine(self, monkeypatch):
        eng = ReconEngine()
        dns = DNSResult(domain="x.com")
        dns.records["A"] = [DNSRecord("A", "1.2.3.4")]
        eng.dns.collect = AsyncMock(return_value=dns)
        eng.whois.query = AsyncMock(return_value=WhoisResult(
            domain="x.com", registrant_email="a@b.com",
            raw_text="contact admin@x.com"))
        eng.cert.analyze = AsyncMock(return_value=CertInfo(
            domain="x.com", is_expired=True, not_after="2000-01-01T00:00:00"))
        eng.icp.query = AsyncMock(return_value=ICPResult(domain="x.com", has_record=True))
        eng.cdn.detect = AsyncMock(return_value=CDNResult(domain="x.com", has_cdn=False))
        eng.ip.batch_collect = AsyncMock(return_value=[IPInfo(
            ip="1.2.3.4", country_code="US", shodan_ports=[3306],
            shodan_vulns=["CVE-2021-1"])])
        eng.wayback.search = AsyncMock(return_value=WaybackResult(
            domain="x.com",
            unique_urls=[{"url": "https://x.com/admin"}, {"url": "https://x.com/about"}]))
        return eng

    def test_full_recon(self, monkeypatch):
        eng = self._mocked_engine(monkeypatch)
        report = asyncio.run(eng.full_recon("x.com"))
        assert report.domain == "x.com"
        assert "1.2.3.4" in report.all_ips
        assert report.all_emails  # 从 whois 提取
        assert report.wayback_interesting_urls  # /admin 命中关键词
        # 风险指标：过期证书 + DNSSEC + SPF/DMARC + Shodan 漏洞 + 敏感端口 + 境外
        risks = " ".join(report.risk_indicators)
        assert "过期" in risks
        assert "3306" in risks
        assert "CVE-2021-1" in risks

    def test_quick_recon(self, monkeypatch):
        eng = self._mocked_engine(monkeypatch)
        report = asyncio.run(eng.quick_recon("x.com"))
        assert report.dns is not None
        assert report.cert is not None

    def test_save_report(self, monkeypatch, tmp_path):
        eng = self._mocked_engine(monkeypatch)
        report = asyncio.run(eng.full_recon("x.com"))
        out = str(tmp_path / "recon.json")
        saved = eng.save_report(report, out)
        assert saved == out
        import json
        data = json.loads(open(out, encoding="utf-8").read())
        assert data["domain"] == "x.com"

    def test_print_report(self, monkeypatch, capsys):
        eng = self._mocked_engine(monkeypatch)
        report = asyncio.run(eng.full_recon("x.com"))
        ReconEngine.print_report(report)
        assert "被动信息收集报告" in capsys.readouterr().out

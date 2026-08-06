"""Whois 查询单元测试（vernalequinox/whois_lookup.py）— mock，覆盖解析与编排

低 ROI 模块（基线 36%）覆盖率提升：WhoisResult 属性、raw whois 文本解析、
query 编排（lib → raw 降级）、打印。
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from src.vernalequinox.whois_lookup import WhoisLookup, WhoisResult


# ── WhoisResult ────────────────────────────────────────────

class TestWhoisResult:
    def test_has_info_true(self):
        assert WhoisResult(domain="x", registrar="GoDaddy").has_info is True

    def test_has_info_false(self):
        assert WhoisResult(domain="x").has_info is False

    def test_to_dict(self):
        d = WhoisResult(domain="x", registrar="GoDaddy").to_dict()
        assert d["domain"] == "x"
        assert d["registrar"] == "GoDaddy"


# ── raw whois 解析 ─────────────────────────────────────────

def _fake_loop(raw_text):
    loop = MagicMock()
    loop.run_in_executor = AsyncMock(return_value=raw_text)
    return loop


class TestRawWhoisParse:
    def test_parse_fields(self):
        raw = (
            "Registrar: Example Registrar Inc\n"
            "Creation Date: 2020-01-01\n"
            "Expiry Date: 2030-01-01\n"
            "Registrant Organization: Example Org\n"
            "Registrant Country: US\n"
            "Name Server: ns1.example.com\n"
            "Name Server: ns2.example.com\n"
            "Domain Status: clientTransferProhibited\n"
            "DNSSEC: signed\n"
        )
        with patch("src.vernalequinox.whois_lookup.asyncio.get_event_loop",
                   return_value=_fake_loop(raw)):
            r = asyncio.run(WhoisLookup()._query_raw_whois("example.com"))
        assert r.registrar == "Example Registrar Inc"
        assert r.creation_date == "2020-01-01"
        assert r.registrant_org == "Example Org"
        assert r.registrant_country == "US"
        assert "ns1.example.com" in r.name_servers
        assert "clientTransferProhibited" in r.status
        assert r.dnssec == "signed"
        assert r.source == "raw-whois"

    def test_parse_cn_registrar(self):
        raw = "注册商: 阿里云\n注册时间: 2019-05-05\n"
        with patch("src.vernalequinox.whois_lookup.asyncio.get_event_loop",
                   return_value=_fake_loop(raw)):
            r = asyncio.run(WhoisLookup()._query_raw_whois("example.com"))
        assert r.registrar == "阿里云"


# ── query 编排 ─────────────────────────────────────────────

class TestQueryOrchestration:
    def test_query_uses_lib(self):
        lib_result = WhoisResult(domain="x", registrar="LibReg", source="python-whois")
        q = WhoisLookup()
        q._query_whois_lib = AsyncMock(return_value=lib_result)
        r = asyncio.run(q.query("example.com"))
        assert r.registrar == "LibReg"

    def test_query_lib_fails_then_raw(self):
        q = WhoisLookup()
        q._query_whois_lib = AsyncMock(side_effect=Exception("no lib"))
        raw = "Registrar: RawReg\n"
        with patch("src.vernalequinox.whois_lookup.asyncio.get_event_loop",
                   return_value=_fake_loop(raw)):
            r = asyncio.run(q.query("example.com"))
        assert r.registrar == "RawReg"


# ── 打印 ───────────────────────────────────────────────────

class TestPrint:
    def test_print_error(self, capsys):
        WhoisLookup.print_result(WhoisResult(domain="x", error="boom"))
        assert "失败" in capsys.readouterr().out

    def test_print_ok(self, capsys):
        r = WhoisResult(domain="x", registrar="R", creation_date="2020",
                        registrant_org="Org", name_servers=["ns1.x.com"])
        WhoisLookup.print_result(r)
        out = capsys.readouterr().out
        assert "R" in out
        assert "ns1.x.com" in out

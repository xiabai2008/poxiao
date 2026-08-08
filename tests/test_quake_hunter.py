"""Quake / Hunter 测绘引擎集成测试（P1-F：mock HTTP，无真实网络）"""

import asyncio
import json

import pytest

from src.vernalequinox.quake_query import QuakeQuery, QuakeResult
from src.vernalequinox.hunter_query import HunterQuery, HunterResult


def _fake_resp(data: dict, status: int = 200):
    class _Resp:
        status_code = status

        def json(self):
            return data

    return _Resp()


class TestQuakeQuery:
    def test_no_credentials_degraded(self, monkeypatch):
        monkeypatch.delenv("QUAKE_TOKEN", raising=False)
        q = QuakeQuery(token="")
        r = asyncio.run(q.search("example.com"))
        assert isinstance(r, QuakeResult)
        assert r.error and "credentials" in r.error

    def test_parses_hosts(self, monkeypatch):
        async def fake_post(url, json=None, headers=None):
            return _fake_resp({
                "code": 0,
                "data": [
                    {"hostname": ["sub.example.com"], "ip": "1.2.3.4",
                     "port": 443, "title": "Admin"},
                    {"hostname": "www.example.com", "ip": "5.6.7.8",
                     "port": 80, "title": ""},
                ],
            })

        monkeypatch.setattr("httpx.AsyncClient", _FakeClient)
        _FakeClient.handler = fake_post
        q = QuakeQuery(token="tok")
        r = asyncio.run(q.search("example.com"))
        assert r.error == ""
        assert len(r.hosts) == 2
        assert r.hosts[0]["host"] == "sub.example.com"
        assert r.hosts[1]["port"] == 80

    def test_business_error(self, monkeypatch):
        async def fake_post(url, json=None, headers=None):
            return _fake_resp({"code": 40001, "message": "invalid token"})

        monkeypatch.setattr("httpx.AsyncClient", _FakeClient)
        _FakeClient.handler = fake_post
        q = QuakeQuery(token="bad")
        r = asyncio.run(q.search("example.com"))
        assert "invalid token" in r.error


class TestHunterQuery:
    def test_no_credentials_degraded(self, monkeypatch):
        monkeypatch.delenv("HUNTER_API_KEY", raising=False)
        monkeypatch.delenv("HUNTER_EMAIL", raising=False)
        h = HunterQuery(api_key="", email="")
        r = asyncio.run(h.search("example.com"))
        assert isinstance(r, HunterResult)
        assert r.error and "credentials" in r.error

    def test_parses_hosts(self, monkeypatch):
        async def fake_get(url, params=None):
            return _fake_resp({
                "code": 200,
                "data": {"arr": [
                    {"domain": "sub.example.com", "ip": "1.1.1.1",
                     "port": 443, "web_title": "Portal"},
                ]},
            })

        monkeypatch.setattr("httpx.AsyncClient", _FakeClient)
        _FakeClient.handler = fake_get
        h = HunterQuery(api_key="k", email="e@x.com")
        r = asyncio.run(h.search("example.com"))
        assert r.error == ""
        assert len(r.hosts) == 1
        assert r.hosts[0]["host"] == "sub.example.com"
        assert r.hosts[0]["title"] == "Portal"

    def test_business_error(self, monkeypatch):
        async def fake_get(url, params=None):
            return _fake_resp({"code": 401, "message": "api-key error"})

        monkeypatch.setattr("httpx.AsyncClient", _FakeClient)
        _FakeClient.handler = fake_get
        h = HunterQuery(api_key="bad", email="e@x.com")
        r = asyncio.run(h.search("example.com"))
        assert "api-key error" in r.error


class TestReconEngineIntegration:
    def test_engine_initializes_sources(self):
        from src.vernalequinox import ReconEngine
        e = ReconEngine(timeout=2, quake_token="q", hunter_key="h", hunter_email="e@x.com")
        assert e.quake.has_credentials is True
        assert e.hunter.has_credentials is True
        assert e.fofa.has_credentials is False

    def test_full_recon_merges_engine_hosts(self, monkeypatch):
        from src.vernalequinox import ReconEngine
        import asyncio

        e = ReconEngine(timeout=2, quake_token="q")

        async def fake_quake_search(domain, limit=100):
            r = QuakeResult(domain=domain)
            r.hosts.append({"host": "q.example.com", "ip": "9.9.9.9", "port": 443, "title": ""})
            return r

        # 只 mock quake；其余源用 stub 返回空结果
        async def empty(*a, **k):
            return None

        async def empty_cdn(*a, **k):
            from src.vernalequinox.cdn_detect import CDNResult
            return CDNResult(domain="example.com")  # real_ips 默认空列表

        for name in ("dns", "whois", "icp", "cert", "ip", "wayback", "github", "censys", "fofa", "hunter"):
            setattr(e, name, type("Stub", (), {
                "has_credentials": False,
                "has_token": False,
                "search": empty,
                "collect": empty,
                "query": empty,
                "analyze": empty,
                "batch_collect": empty,
            })())
        e.cdn = type("StubCdn", (), {"detect": empty_cdn})()
        e.quake = type("Q", (), {"has_credentials": True, "search": fake_quake_search})()

        report = asyncio.run(e.full_recon("example.com"))
        assert report.quake is not None
        assert "q.example.com" in report.all_domains
        assert "9.9.9.9" in report.all_ips


class _FakeClient:
    """替换 httpx.AsyncClient 的简单假客户端类（monkeypatch 类本身）"""

    handler = None

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, params=None):
        return await type(self).handler(url, params=params)

    async def post(self, url, json=None, headers=None):
        return await type(self).handler(url, json=json, headers=headers)

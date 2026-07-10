"""P2-1 / D8：FOFA 被动侦察源 — 密钥隔离 / 限流 / 降级"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

from src.vernalequinox.fofa_query import FofaQuery, FofaResult
from src.vernalequinox.engine import ReconEngine


def _make_client(json_data, status=200):
    """构造可被 `async with httpx.AsyncClient(...) as c` 使用的 mock 客户端"""
    fake_resp = MagicMock()
    fake_resp.status_code = status
    fake_resp.json.return_value = json_data
    fake_client = MagicMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(return_value=fake_resp)
    return fake_client


def test_fofa_no_credentials_downgrades_without_raise():
    f = FofaQuery()
    assert f.has_credentials is False
    r = asyncio.run(f.search("example.com"))
    assert r.error
    assert r.hosts == []


def test_fofa_search_parses_results():
    f = FofaQuery(email="a@b.com", key="k")
    data = {"error": False, "results": [
        ["host1.example.com", "1.2.3.4", "80", "Site A", "example.com"],
        ["host2.example.com", "5.6.7.8", "443", "Site B", "example.com"],
    ]}
    with patch("httpx.AsyncClient", return_value=_make_client(data)):
        r = asyncio.run(f.search("example.com"))
    assert r.error == ""
    assert len(r.hosts) == 2
    assert r.hosts[0]["ip"] == "1.2.3.4"
    assert r.hosts[0]["port"] == "80"
    assert r.hosts[1]["title"] == "Site B"


def test_fofa_api_business_error_downgrades():
    f = FofaQuery(email="a@b.com", key="k")
    data = {"error": True, "errmsg": "API key invalid"}
    with patch("httpx.AsyncClient", return_value=_make_client(data)):
        r = asyncio.run(f.search("example.com"))
    assert "API key invalid" in r.error
    assert r.hosts == []


def test_fofa_request_exception_downgrades():
    f = FofaQuery(email="a@b.com", key="k")
    fake_client = MagicMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(side_effect=Exception("network boom"))
    with patch("httpx.AsyncClient", return_value=fake_client):
        r = asyncio.run(f.search("example.com"))
    assert "network boom" in r.error


def test_fofa_ratelimit_enforced():
    # 直接验证 _ratelimit：相邻两次调用应触发一次真实限流等待
    f = FofaQuery(min_interval=0.05)
    t0 = time.monotonic()
    asyncio.run(f._ratelimit())
    asyncio.run(f._ratelimit())
    elapsed = time.monotonic() - t0
    # 第二次请求应触发约 0.05s 的限流等待（首次因 _last_req=0 不等待）
    assert elapsed >= 0.03


def test_recon_engine_wires_fofa():
    eng = ReconEngine()
    assert hasattr(eng, "fofa")
    assert eng.fofa.has_credentials is False  # 无凭证时默认降级，不阻断

"""Wayback Machine 历史 URL 发现单元测试"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from src.vernalequinox.wayback import WaybackQuery, WaybackResult


def _make_client(json_data, status=200):
    fake_resp = MagicMock()
    fake_resp.status_code = status
    fake_resp.json.return_value = json_data
    fake_client = MagicMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(return_value=fake_resp)
    return fake_client


class TestSearch:
    def test_parse_and_dedup(self):
        data = [
            ["original", "mimetype", "statuscode", "timestamp"],
            ["https://x.com/a?x=1", "text/html", "200", "20200101"],
            ["https://x.com/a", "text/html", "200", "20200102"],  # 同路径去重
            ["https://x.com/b", "text/html", "200", "20200103"],
        ]
        q = WaybackQuery()
        with patch("httpx.AsyncClient", return_value=_make_client(data)):
            r = asyncio.run(q.search("x.com"))
        assert len(r.urls) == 3
        assert len(r.unique_urls) == 2
        assert r.error == ""

    def test_error_status(self):
        q = WaybackQuery()
        with patch("httpx.AsyncClient", return_value=_make_client({}, status=500)):
            r = asyncio.run(q.search("x.com"))
        assert r.error

    def test_empty_data(self):
        q = WaybackQuery()
        with patch("httpx.AsyncClient", return_value=_make_client([["header"]])):
            r = asyncio.run(q.search("x.com"))
        assert r.urls == []


class TestInteresting:
    def test_find_interesting(self):
        q = WaybackQuery()
        q.search = AsyncMock(return_value=WaybackResult(
            domain="x", unique_urls=[
                {"url": "https://x.com/admin"},
                {"url": "https://x.com/home"},
            ]))
        interesting = asyncio.run(q.find_interesting_urls("x.com"))
        assert len(interesting) == 1
        assert interesting[0]["url"] == "https://x.com/admin"


class TestResult:
    def test_to_dict(self):
        r = WaybackResult(domain="x", urls=[1, 2], unique_urls=[1, 2, 3])
        d = r.to_dict()
        assert d["total_urls"] == 2
        assert d["unique_urls"] == 3

    def test_print_result(self, capsys):
        r = WaybackResult(domain="x", unique_urls=[{"url": "https://x.com/a"}])
        WaybackQuery.print_result(r)
        assert "Wayback" in capsys.readouterr().out

    def test_print_result_error(self, capsys):
        WaybackQuery.print_result(WaybackResult(domain="x", error="boom"))
        assert "Error: boom" in capsys.readouterr().out

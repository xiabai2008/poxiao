"""target.manager 测试：Target dataclass + 纯逻辑 + 存活检测(monkeypatch AsyncClient)"""

import asyncio

import httpx
import pytest

from src.target.manager import Target, TargetManager


def test_target_post_init_and_properties():
    t = Target(url="https://www.Example.com/path")
    assert t.host == "www.Example.com"
    assert t.normalized == "https://www.Example.com/path"
    assert t.domain_key == "example.com"
    assert len(t.fingerprint) == 12


def test_target_no_host_passed():
    t = Target(url="http://example.com")
    assert t.host == "example.com"


def test_load_from_file(tmp_path):
    p = tmp_path / "targets.txt"
    p.write_text(
        "# comment\nhttps://a.com\nhttp://b.com # inline comment\nc.com\n\n",
        encoding="utf-8",
    )
    mgr = TargetManager()
    targets = mgr.load_from_file(str(p))
    urls = {t.url for t in targets}
    assert "https://a.com" in urls
    assert "http://b.com" in urls
    assert "https://c.com" in urls  # 自动补全协议


def test_load_from_file_missing():
    mgr = TargetManager()
    with pytest.raises(FileNotFoundError):
        mgr.load_from_file("__no_such_targets__.txt")


def test_load_from_list():
    mgr = TargetManager()
    targets = mgr.load_from_list(["https://a.com", "  ", "https://b.com"])
    assert len(targets) == 2


def test_deduplicate():
    mgr = TargetManager()
    targets = [
        Target(url="https://a.com"),
        Target(url="https://A.com/x"),  # 同 domain_key
        Target(url="https://b.com"),
    ]
    uniq = mgr.deduplicate(targets)
    assert len(uniq) == 2


def test_classify():
    mgr = TargetManager()
    targets = [
        Target(url="https://www.gov.cn/x"),
        Target(url="https://x.edu.cn"),
        Target(url="https://icbc.com"),
        Target(url="https://shop.example.com"),
        Target(url="https://example.com"),
    ]
    mgr.classify(targets)
    cats = {t.host: t.category for t in targets}
    assert cats["www.gov.cn"] == "gov"
    assert cats["x.edu.cn"] == "edu"
    assert cats["icbc.com"] == "bank"
    assert cats["shop.example.com"] == "ecommerce"
    assert cats["example.com"] == "enterprise"


def test_summary():
    mgr = TargetManager()
    targets = [
        Target(url="https://a.com", is_alive=True, status_code=200, category="gov"),
        Target(url="https://b.com", is_alive=False, status_code=0, category="gov"),
    ]
    s = mgr.summary(targets)
    assert s["total"] == 2
    assert s["alive"] == 1
    assert s["dead"] == 1
    assert s["categories"]["gov"] == 2
    assert len(s["targets"]) == 2


# ── 存活检测（monkeypatch httpx.AsyncClient）────────────

class _FakeResp:
    def __init__(self, status_code=200, history=None, url="http://x"):
        self.status_code = status_code
        self.history = history or []
        self.url = url


class _FakeAsyncClient:
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def head(self, url, **k):
        if url.startswith("dead"):
            raise httpx.ConnectError("nope")
        if url.startswith("err"):
            raise ValueError("boom")
        if url.startswith("redir"):
            return _FakeResp(301, history=["h"], url="http://redirected")
        return _FakeResp(200)


def test_check_alive_sync(monkeypatch):
    monkeypatch.setattr("src.target.manager.httpx.AsyncClient", _FakeAsyncClient)
    mgr = TargetManager()
    targets = [
        Target(url="https://ok.com"),
        Target(url="dead://x"),
        Target(url="err://x"),
        Target(url="redir://x"),
        Target(url="https://x.com/500"),  # 需要 status>=500 → dead
    ]
    # 让 500 的目标返回 500
    orig_head = _FakeAsyncClient.head

    async def _head(self, url, **k):
        if url.endswith("/500"):
            return _FakeResp(500)
        return await orig_head(self, url, **k)

    _FakeAsyncClient.head = _head
    results = mgr.check_alive_sync(targets)
    by_url = {t.url: t for t in results}
    assert by_url["https://ok.com"].is_alive is True
    assert by_url["dead://x"].is_alive is False
    assert by_url["err://x"].is_alive is False
    assert by_url["redir://x"].redirect_url == "http://redirected"
    assert by_url["https://x.com/500"].is_alive is False

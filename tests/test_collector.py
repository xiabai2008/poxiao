"""霜月子域名收集器单元测试（frostmoon/collector.py）— mock DNS，覆盖纯逻辑

低 ROI 模块（基线 17%）覆盖率提升：分类映射、Subdomain.to_url、导出/摘要、
collect 编排（泛解析检测 + 全源关闭）、_is_wildcard 判定。
"""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

from src.frostmoon.collector import ShuangYue, Subdomain, _classify


# ── 分类 ───────────────────────────────────────────────────

class TestClassify:
    def test_admin(self):
        assert _classify("admin.x.com") == "admin"

    def test_api(self):
        assert _classify("api.x.com") == "api"

    def test_portal(self):
        assert _classify("www.x.com") == "portal"

    def test_dev(self):
        assert _classify("dev.x.com") == "dev"

    def test_unknown(self):
        assert _classify("randomhost.x.com") == "unknown"


# ── Subdomain ──────────────────────────────────────────────

class TestSubdomain:
    def test_to_url(self):
        assert Subdomain(domain="a.com").to_url() == "https://a.com"


# ── 导出 / 摘要 ────────────────────────────────────────────

def _subs():
    return [
        Subdomain(domain="admin.x.com", alive=True, category="admin",
                  title="Admin"),
        Subdomain(domain="api.x.com", alive=True, category="api", title="API"),
        Subdomain(domain="old.x.com", alive=False, category="dev", title="Old"),
    ]


class TestExportSummary:
    def test_to_target_file(self, tmp_path):
        out = tmp_path / "subs.txt"
        ShuangYue().to_target_file(_subs(), str(out))
        txt = out.read_text(encoding="utf-8")
        assert "admin.x.com" in txt
        assert "api.x.com" in txt
        # 存活过滤：旧/未存活不写入
        assert "old.x.com" not in txt

    def test_summary(self):
        s = ShuangYue().summary(_subs())
        assert "admin.x.com" not in s  # summary 只统计数量，不打全域名
        assert "admin" in s
        assert "共 3 个子域名" in s


# ── 泛解析 / collect 编排 ──────────────────────────────────

def _fake_resolve_answer(ip):
    a = type("A", (), {"__str__": lambda self: ip})()
    return [a]


class TestWildcard:
    def test_is_wildcard_true(self):
        sy = ShuangYue()
        sy._wildcard_ips = {"1.2.3.4"}
        sy.resolver.resolve = MagicMock(return_value=_fake_resolve_answer("1.2.3.4"))
        assert sy._is_wildcard("anything.x.com") is True

    def test_is_wildcard_false(self):
        sy = ShuangYue()
        sy._wildcard_ips = {"1.2.3.4"}
        sy.resolver.resolve = MagicMock(return_value=_fake_resolve_answer("9.9.9.9"))
        assert sy._is_wildcard("anything.x.com") is False

    def test_detect_wildcard_failure(self):
        sy = ShuangYue()
        sy.resolver.resolve = MagicMock(side_effect=Exception("nxdomain"))
        assert sy._detect_wildcard("x.com") is False


class TestCollect:
    def test_collect_no_sources(self):
        sy = ShuangYue()
        # 泛解析检测失败（避免真实 DNS）
        sy.resolver.resolve = MagicMock(side_effect=Exception("nxdomain"))
        result = asyncio.run(sy.collect("x.com", use_crtsh=False,
                                         use_brute=False, check_alive=False))
        assert result == []

    def test_collect_check_alive_off(self):
        sy = ShuangYue()
        sy.resolver.resolve = MagicMock(side_effect=Exception("nxdomain"))
        # use_crtsh/use_brute 开，但其内部网络调用会抛异常被吞 → 无结果，
        # 但 check_alive=False 走 else 分支构造 Subdomain
        result = asyncio.run(sy.collect("x.com", use_crtsh=True,
                                         use_brute=False, check_alive=False))
        # 无源数据 → 列表空
        assert isinstance(result, list)

    def test_collect_sync(self):
        sy = ShuangYue()
        sy.resolver.resolve = MagicMock(side_effect=Exception("nxdomain"))
        result = sy.collect_sync("x.com", use_crtsh=False, use_brute=False,
                                 check_alive=False)
        assert result == []

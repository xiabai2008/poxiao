"""ICP 备案查询单元测试（vernalequinox/icp_query.py）— mock HTTP，覆盖解析与编排

低 ROI 模块（基线 40%）覆盖率提升：ICPResult 属性、API 解析、TLD 启发式、
批量查询、打印。
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from src.vernalequinox.icp_query import ICPQuery, ICPResult


# ── 异步客户端 mock ────────────────────────────────────────

class _FakeResp:
    def __init__(self, status=200, json_data=None):
        self.status_code = status
        self._json = json_data or {}

    def json(self):
        return self._json


class _FakeClient:
    def __init__(self, json_data=None):
        self._json = json_data or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, headers=None):
        return _FakeResp(200, self._json)


def _patch_client(json_data):
    return patch("httpx.AsyncClient", return_value=_FakeClient(json_data))


# ── ICPResult ──────────────────────────────────────────────

class TestICPResult:
    def test_is_enterprise_by_type(self):
        r = ICPResult(domain="x", company_type="企业")
        assert r.is_enterprise is True

    def test_is_enterprise_by_name(self):
        r = ICPResult(domain="x", company_name="某某科技有限公司")
        assert r.is_enterprise is True

    def test_not_enterprise(self):
        r = ICPResult(domain="x", company_type="个人")
        assert r.is_enterprise is False

    def test_province_code(self):
        r = ICPResult(domain="x", icp_number="京ICP备12345678号")
        assert r.icp_province_code == "京"

    def test_province_code_missing(self):
        r = ICPResult(domain="x", icp_number="")
        assert r.icp_province_code == ""


# ── API 解析 ───────────────────────────────────────────────

class TestParseApiResponse:
    def test_icpapi_format(self):
        data = {"icp": {"icp": "京ICP备12345678号", "unitName": "测试公司",
                        "unitNature": "企业", "auditDate": "2020-01-01"}}
        r = ICPQuery()._parse_api_response(data, "x.com")
        assert r is not None
        assert r.has_record is True
        assert r.icp_number == "京ICP备12345678号"
        assert r.company_name == "测试公司"
        assert r.province == "北京"

    def test_vvhan_format(self):
        data = {"info": {"icp": "沪ICP备888号", "name": "沪上公司"}}
        r = ICPQuery()._parse_api_response(data, "x.com")
        assert r is not None and r.has_record is True
        assert r.icp_number == "沪ICP备888号"

    def test_no_record(self):
        data = {"info": {"name": "example"}}
        assert ICPQuery()._parse_api_response(data, "x.com") is None

    def test_empty_data(self):
        assert ICPQuery()._parse_api_response({}, "x.com") is None


# ── 启发式 fallback ────────────────────────────────────────

class TestFallback:
    def test_cn_domain(self):
        r = asyncio.run(ICPQuery()._query_fallback("example.cn"))
        assert r.has_record is True
        assert r.source == "tld-heuristic"

    def test_com_cn_domain(self):
        r = asyncio.run(ICPQuery()._query_fallback("example.com.cn"))
        assert r.has_record is True

    def test_non_cn_domain(self):
        r = asyncio.run(ICPQuery()._query_fallback("example.com"))
        assert r.has_record is False


# ── query 编排 ─────────────────────────────────────────────

class TestQuery:
    def test_query_uses_api(self):
        data = {"icp": {"icp": "京ICP备12345678号", "unitName": "测试公司"}}
        q = ICPQuery()
        with _patch_client(data):
            r = asyncio.run(q.query("example.com"))
        assert r.has_record is True
        assert r.icp_number == "京ICP备12345678号"

    def test_query_falls_back_to_tld(self):
        # API 返回无备案 → fallback 通过 .cn 启发式给出结果
        q = ICPQuery()
        with _patch_client({}):
            r = asyncio.run(q.query("example.cn"))
        assert r.has_record is True

    def test_query_api_error_uses_fallback(self):
        q = ICPQuery()
        with patch("httpx.AsyncClient", side_effect=Exception("net")):
            r = asyncio.run(q.query("example.cn"))
        # fallback 命中 .cn
        assert r.has_record is True


# ── 批量 / 打印 ────────────────────────────────────────────

class TestBatchAndPrint:
    def test_batch(self):
        q = ICPQuery()
        q.query = AsyncMock(return_value=ICPResult(domain="x", has_record=True))
        res = asyncio.run(q.batch_query(["a.cn", "b.cn"]))
        assert len(res) == 2

    def test_print_result_error(self, capsys):
        ICPQuery.print_result(ICPResult(domain="x", error="boom"))
        assert "失败" in capsys.readouterr().out

    def test_print_result_no_record(self, capsys):
        ICPQuery.print_result(ICPResult(domain="x", has_record=False))
        assert "无 ICP 备案" in capsys.readouterr().out

    def test_print_result_record(self, capsys):
        ICPQuery.print_result(ICPResult(domain="x", has_record=True,
                                         icp_number="京ICP备1号",
                                         company_name="公司"))
        out = capsys.readouterr().out
        assert "京ICP备1号" in out

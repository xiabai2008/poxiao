"""Phase 0 修复回归测试 — Windows 文件名 / 历史对比 / 标签归一化 /
二进制匹配 / MCP SSE 鉴权 / 运行时变量一致性 / 死 CVE 数据"""

import http.client
import json
import threading
from pathlib import Path

from src.dawn.src_reporter import SRCReporter
from src.dawn.engine import normalize_tech_tag
from src.dawn.cve_match import CVEMatcher
from src.xiazhi.matcher import MatcherEngine, Matcher
from src.xiazhi.poc_engine import POCEngine
from src.guanxing.poc_store import save_scan_results, compare_with_last
from src.guanxing import db as guanxing_db
from src.mcp.sse_server import SSEServer, _REQUIRED_TOKEN


# ── 0-1 Windows 文件名清洗 ──────────────────────────
class TestSanitizeFilename:
    def test_colon_and_slash_cleaned(self):
        assert ":" not in SRCReporter._sanitize_filename("[x.com] 疑似 CVE-1: desc")

    def test_windows_invalid_chars_all_cleaned(self):
        name = SRCReporter._sanitize_filename('a<>:"/\\|?*b')
        assert name == "a_________b"

    def test_trailing_dot_space_trimmed(self):
        name = SRCReporter._sanitize_filename("title. ")
        assert not name.endswith(". ") and not name.endswith(".")

    def test_truncated_to_40_and_nonempty(self):
        name = SRCReporter._sanitize_filename("x" * 100)
        assert len(name) == 40
        assert SRCReporter._sanitize_filename(":::") == "report"


# ── 0-2 历史对比取上一批扫描 ────────────────────────
class TestHistoryCompare:
    def _setup(self, tmp_path, monkeypatch):
        db_path = tmp_path / "test.db"
        monkeypatch.setattr(guanxing_db, "DB_PATH", Path(db_path))

    def test_compare_uses_previous_scan(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch)
        target = "https://example.com"
        # 第一批: 2 个发现
        save_scan_results(target, [
            {"template_id": "t1", "url": target, "matched": True, "template_name": "A"},
            {"template_id": "t2", "url": target, "matched": True, "template_name": "B"},
        ])
        # 第二批: 只有 t1 保留, t2 消失, t3 新增（先保存再对比，与 poc.py 调用顺序一致）
        save_scan_results(target, [
            {"template_id": "t1", "url": target, "matched": True, "template_name": "A"},
            {"template_id": "t3", "url": target, "matched": True, "template_name": "C"},
        ])
        diff = compare_with_last(target, [
            {"template_id": "t1", "url": target, "matched": True, "template_name": "A"},
            {"template_id": "t3", "url": target, "matched": True, "template_name": "C"},
        ])
        new_ids = {f.get("template_id") for f in diff.new_findings}
        assert "t3" in new_ids, "新增应包含 t3"
        assert "t1" not in new_ids, "已存在不应判为新增"
        assert {d.get("template_id") for d in diff.disappeared} == {"t2"}, "消失应包含 t2"

    def test_first_scan_all_new(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch)
        target = "https://first.com"
        save_scan_results(target, [{"template_id": "t1", "url": target, "matched": True}])
        diff = compare_with_last(target, [
            {"template_id": "t1", "url": target, "matched": True},
            {"template_id": "t2", "url": target, "matched": True},
        ])
        assert len(diff.new_findings) == 2, "首次扫描全部为新增"


# ── 0-3 技术栈标签归一化 ────────────────────────────
class TestNormalizeTechTag:
    def test_version_suffix(self):
        assert normalize_tech_tag("iis/10.0") == ("iis", "10.0")
        assert normalize_tech_tag("nginx/1.18.0") == ("nginx", "1.18.0")

    def test_category_prefix(self):
        assert normalize_tech_tag("db:mysql") == ("mysql", "")
        assert normalize_tech_tag("cdn:cloudflare") == ("cloudflare", "")
        assert normalize_tech_tag("waf:modsec") == ("modsec", "")

    def test_plain_tag(self):
        assert normalize_tech_tag("asp.net") == ("asp.net", "")
        assert normalize_tech_tag("") == ("", "")

    def test_normalized_tag_matches_cve_db(self):
        matcher = CVEMatcher()
        comp, ver = normalize_tech_tag("iis/6.0")
        assert any(v.cve_id == "CVE-2017-7269" for v in matcher.match(comp, ver))
        comp, ver = normalize_tech_tag("db:mysql/5.5")
        assert comp == "mysql" and ver == "5.5"


# ── 0-4 二进制匹配使用原始字节 ──────────────────────
class TestBinaryMatcherBytes:
    def test_binary_matches_raw_bytes(self):
        engine = MatcherEngine()
        m = Matcher(type="binary", binary=["504b0304"])
        # zip 头字节, 若先解码为 text 再 encode 会损坏 (0x04 控制字符)
        raw = bytes.fromhex("504b0304140000000800")
        assert raw.decode("latin-1") != ""  # 纯 latin-1 可解码
        matched, desc = engine.match(m, 200, {}, raw.decode("latin-1"), body_bytes=raw)
        assert matched is True
        assert "binary" in desc

    def test_binary_no_match(self):
        engine = MatcherEngine()
        m = Matcher(type="binary", binary=["ffffffff"])
        matched, _ = engine.match(m, 200, {}, "xxxx", body_bytes=b"xxxx")
        assert matched is False


# ── 0-5 MCP SSE token 鉴权 ──────────────────────────
class TestSseAuth:
    def _start_server(self, token):
        srv = SSEServer(host="127.0.0.1", port=0, token=token)
        srv._make()
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        return srv, t

    def test_no_token_allowed_by_default(self):
        srv, t = self._start_server("")
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
            c.request("GET", "/sse")
            assert c.getresponse().status == 200
            c.close()
        finally:
            srv.shutdown()

    def test_unauthorized_without_token(self):
        srv, t = self._start_server("secret123")
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
            c.request("GET", "/sse")
            r = c.getresponse()
            assert r.status == 401
            assert "Bearer" in r.getheader("WWW-Authenticate", "")
            r.read()
            c.close()
        finally:
            srv.shutdown()

    def test_authorized_with_bearer_token(self):
        srv, t = self._start_server("secret123")
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
            c.request("GET", "/sse", headers={"Authorization": "Bearer secret123"})
            assert c.getresponse().status == 200
            c.close()
        finally:
            srv.shutdown()

    def test_authorized_with_query_token(self):
        srv, t = self._start_server("secret123")
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
            c.request("GET", "/sse?token=secret123")
            assert c.getresponse().status == 200
            c.close()
        finally:
            srv.shutdown()

    def test_wrong_token_rejected_on_post(self):
        srv, t = self._start_server("secret123")
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
            c.request("POST", "/messages?sessionId=x&token=wrong", body="{}",
                      headers={"Content-Type": "application/json"})
            r = c.getresponse()
            assert r.status == 401
            r.read()
            c.close()
        finally:
            srv.shutdown()


# ── 0-7 运行时变量每请求一致 + matcher 变量展开 ──────
class TestRuntimeVars:
    def test_gen_runtime_vars_same_within_request(self):
        engine = POCEngine(timeout=5)
        rv = engine._gen_runtime_vars()
        assert rv["randstr"] and rv["randbase64"] and rv["timestamp"]
        # 同一请求内重复展开得到相同值
        a = engine._expand_variables("tok={{randstr}}", {}, rv)
        b = engine._expand_variables("tok={{randstr}}", {}, rv)
        assert a == b

    def test_runtime_vars_differ_across_requests(self):
        engine = POCEngine(timeout=5)
        rv1 = engine._gen_runtime_vars()
        rv2 = engine._gen_runtime_vars()
        assert rv1["randstr"] != rv2["randstr"]

    def test_matcher_word_expands_variables(self):
        engine = MatcherEngine()
        m = Matcher(type="word", words=["tok={{randstr}}"])
        # 响应体包含请求内生成的实际随机值
        rv = POCEngine(timeout=5)._gen_runtime_vars()
        matched, _ = engine.match(m, 200, {}, f"tok={rv['randstr']}",
                                  variables={"randstr": rv["randstr"]})
        assert matched is True

    def test_legacy_runtime_resolution_kept(self):
        engine = POCEngine(timeout=5)
        out = engine._expand_variables("tok={{randstr}}", {})
        assert out.startswith("tok=") and out != "tok={{randstr}}"


# ── 0-8 CVE 数据修复回归 ────────────────────────────
class TestCveDataFixes:
    def test_cve_2025_24813_tomcat_range_matches(self):
        m = CVEMatcher()
        ids = {v.cve_id for v in m.match("tomcat", "9.0.98")}
        assert "CVE-2025-24813" in ids
        ids = {v.cve_id for v in m.match("tomcat", "10.1.34")}
        assert "CVE-2025-24813" in ids

    def test_cve_2025_24813_fixed_version_excluded(self):
        m = CVEMatcher()
        ids = {v.cve_id for v in m.match("tomcat", "9.0.99")}
        assert "CVE-2025-24813" not in ids

    def test_iis_entries_parse(self):
        m = CVEMatcher()
        assert "CVE-2017-7269" in {v.cve_id for v in m.match("iis", "6.0")}
        assert "CVE-2022-21907" in {v.cve_id for v in m.match("iis", "10.0")}
        assert "CVE-2015-1635" in {v.cve_id for v in m.match("iis", "8.5")}

    def test_discuz_entries_parse(self):
        m = CVEMatcher()
        ids = {v.cve_id for v in m.match("discuz", "3.4")}
        assert {"CVE-2019-13956", "CVE-2023-35943"} <= ids

    def test_njs_cve_not_attached_to_nginx(self):
        m = CVEMatcher()
        ids = {v.cve_id for v in m.match("nginx", "1.18.0")}
        assert "CVE-2022-26945" not in ids

    def test_no_unparseable_affected_left(self):
        import re
        from src.dawn.cve_match import BUILTIN_VULNS
        bad = []
        for e in BUILTIN_VULNS:
            aff = e.get("affected", "")
            if aff and not re.match(r"[\d]+(?:\.[\d]+)*",
                                    aff.replace("=", "").replace("<", "").replace(">", "").strip()):
                bad.append(e["cve"])
        assert bad == [], f"仍有不可解析 affected: {bad}"

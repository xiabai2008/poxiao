"""OAST 本地回调基础设施测试（P1-D：盲注/XXE/SSRF 带外验证）"""

import http.client
import os
import threading

import pytest

from src.oast.server import (
    OastServer, query_calls, flush_calls, gen_oast_domain, gen_oast_url,
    _log_path,
)
from src.xiazhi.poc_engine import POCEngine


@pytest.fixture(autouse=True)
def isolated_log(tmp_path, monkeypatch):
    log = tmp_path / "oast.log"
    monkeypatch.setenv("POXIAO_OAST_LOG", str(log))
    monkeypatch.setattr("src.oast.server._log_path", lambda: log)
    yield log


class TestDomainGen:
    def test_random_label(self):
        a = gen_oast_domain()
        b = gen_oast_domain()
        assert a != b
        assert a.endswith("oast.local")

    def test_env_base(self, monkeypatch):
        monkeypatch.setenv("POXIAO_OAST_BASE", "oast.example.com")
        assert gen_oast_domain().endswith("oast.example.com")
        assert gen_oast_url().startswith("http://")


class TestOastServer:
    def _start(self, tmp_path):
        srv = OastServer(host="127.0.0.1", port=0)
        srv._make()
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        return srv, t

    def test_records_get_and_post(self, tmp_path):
        srv, t = self._start(tmp_path)
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
            c.request("GET", "/ping?x=1")
            r = c.getresponse()
            assert r.status == 200
            r.read()
            c.request("POST", "/submit", body='{"a":1}',
                      headers={"Content-Type": "application/json"})
            r = c.getresponse()
            assert r.status == 200
            r.read()
            c.close()
        finally:
            srv.shutdown()

        calls = query_calls()
        assert len(calls) == 2
        assert calls[0]["method"] == "GET"
        assert calls[0]["path"] == "/ping"
        assert calls[0]["query"] == "x=1"
        assert calls[1]["method"] == "POST"
        assert calls[1]["body"] == '{"a":1}'

    def test_query_by_domain_filter(self, tmp_path):
        srv, t = self._start(tmp_path)
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
            c.request("GET", "/abc123.oast.local/x")
            c.getresponse().read()
            c.request("GET", "/other/x")
            c.getresponse().read()
            c.close()
        finally:
            srv.shutdown()

        hits = query_calls(domain="abc123.oast.local")
        assert len(hits) == 1
        assert "abc123.oast.local" in hits[0]["path"]

    def test_flush(self, tmp_path):
        srv, t = self._start(tmp_path)
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
            c.request("GET", "/x")
            c.getresponse().read()
            c.close()
        finally:
            srv.shutdown()
        assert flush_calls() == 1
        assert query_calls() == []

    def test_empty_query(self):
        assert query_calls() == []


class TestPocEngineIntegration:
    def test_oast_vars_generated_and_tracked(self, monkeypatch, tmp_path):
        monkeypatch.setenv("POXIAO_OAST_BASE", "oast.t.com")
        engine = POCEngine(timeout=5, track_oast=True)
        rv = engine._gen_runtime_vars()
        assert rv["oast-domain"].endswith("oast.t.com")
        assert rv["oast-url"] == f"http://{rv['oast-domain']}/"
        assert engine._oast_domains == [rv["oast-domain"]]

    def test_oast_var_consistency_within_request(self, tmp_path):
        engine = POCEngine(timeout=5, track_oast=True)
        rv = engine._gen_runtime_vars()
        a = engine._expand_variables("url={{oast-url}}", {}, rv)
        b = engine._expand_variables("url={{oast-url}}", {}, rv)
        assert a == b

    def test_no_track_no_record(self, tmp_path):
        engine = POCEngine(timeout=5, track_oast=False)
        engine._gen_runtime_vars()
        assert engine._oast_domains == []

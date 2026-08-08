"""raw HTTP 报文模板测试（P2-1：nuclei raw 格式支持）"""

import asyncio
import threading

import pytest

from src.xiazhi.loader import TemplateLoader, Template
from src.xiazhi.poc_engine import POCEngine


def _write_raw_template(d, name="raw-test.yaml", raw="GET /info HTTP/1.1\nHost: {{Hostname}}"):
    f = d / name
    f.write_text(
        "id: raw-test\n"
        'info:\n  name: "Raw Test"\n  severity: info\n'
        "http:\n"
        "  raw:\n"
        f"    - |\n      {raw.replace(chr(10), chr(10) + '      ')}\n"
        "  matchers:\n"
        '    - type: word\n      words:\n        - "raw-ok"\n',
        encoding="utf-8",
    )
    return f


class TestRawParse:
    def test_parse_raw_simple(self):
        from src.xiazhi.loader import TemplateLoader
        l = TemplateLoader()
        parsed = l._parse_raw_http("GET /path?x=1 HTTP/1.1\nHost: {{Hostname}}\n\nbody-here")
        assert parsed["method"] == "GET"
        assert parsed["path"] == "/path?x=1"
        assert parsed["headers"] == {"Host": "{{Hostname}}"}
        assert parsed["body"] == "body-here"

    def test_parse_raw_no_body(self):
        from src.xiazhi.loader import TemplateLoader
        l = TemplateLoader()
        parsed = l._parse_raw_http("POST /x HTTP/1.1\nContent-Type: application/json")
        assert parsed["method"] == "POST"
        assert parsed["body"] == ""

    def test_parse_raw_crlf_and_blank_lines(self):
        from src.xiazhi.loader import TemplateLoader
        l = TemplateLoader()
        parsed = l._parse_raw_http("\r\n\r\nPUT /y HTTP/1.1\r\nA: 1\r\n\r\n")
        assert parsed["method"] == "PUT"
        assert parsed["headers"] == {"A": "1"}

    def test_parse_raw_invalid(self):
        from src.xiazhi.loader import TemplateLoader
        l = TemplateLoader()
        assert l._parse_raw_http("") is None
        assert l._parse_raw_http("no-space-here") is None

    def test_loader_creates_request_with_raw(self, tmp_path):
        f = _write_raw_template(tmp_path)
        l = TemplateLoader(str(tmp_path))
        templates = l.load_all()
        assert len(templates) == 1
        req = templates[0].requests[0]
        assert req.method == "GET"
        assert req.path == ["/info"]
        assert req.headers.get("Host") == "{{Hostname}}"
        assert req.raw  # 原文保留
        # 顶层 matchers 附加到请求
        assert len(req.matchers) == 1

    def test_loader_multiple_raw_requests(self, tmp_path):
        f = tmp_path / "multi.yaml"
        f.write_text(
            "id: multi\n"
            'info:\n  name: "M"\n  severity: info\n'
            "http:\n"
            "  raw:\n"
            "    - |\n      GET /a HTTP/1.1\n      Host: {{Hostname}}\n"
            "    - |\n      GET /b HTTP/1.1\n      Host: {{Hostname}}\n"
            "  matchers:\n"
            '    - type: word\n      words:\n        - "ok"\n',
            encoding="utf-8",
        )
        l = TemplateLoader(str(tmp_path))
        templates = l.load_all()
        assert len(templates[0].requests) == 2
        assert [r.path[0] for r in templates[0].requests] == ["/a", "/b"]
        # 每个请求都带顶层 matchers
        assert all(len(r.matchers) == 1 for r in templates[0].requests)


class TestRawExecution:
    @pytest.fixture
    def target(self):
        """本地 mock 目标：/info 返回 raw-ok"""
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # noqa: A003
                pass

            def do_GET(self):  # noqa: N802
                if self.path == "/info":
                    body = b"hello raw-ok marker"
                    self.send_response(200)
                else:
                    body = b"not found"
                    self.send_response(404)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        yield f"http://127.0.0.1:{srv.server_address[1]}"
        srv.shutdown()

    def test_raw_request_end_to_end(self, tmp_path, target):
        f = _write_raw_template(tmp_path)
        loader = TemplateLoader(str(tmp_path))
        templates = loader.load_all()
        engine = POCEngine(timeout=5)
        results = asyncio.run(engine.scan_target(target, templates))
        assert len(results) == 1
        assert results[0].matched is True
        assert results[0].request_url.endswith("/info")

    def test_raw_host_variable_expanded(self, tmp_path, target):
        """Host 头中的 {{Hostname}} 应展开为目标主机"""
        f = _write_raw_template(tmp_path)
        loader = TemplateLoader(str(tmp_path))
        templates = loader.load_all()
        engine = POCEngine(timeout=5)

        captured = {}

        async def run():
            # 直接执行单个请求，检查展开后的 headers
            req = templates[0].requests[0]
            variables = {
                "BaseURL": target.rstrip("/"),
                "Hostname": target.split("//")[-1].split(":")[0],
                "Host": target.split("//")[-1],
                "Scheme": "http",
                "Port": "80",
            }
            rv = engine._gen_runtime_vars()
            headers = {k: engine._expand_variables(v, variables, rv)
                       for k, v in req.headers.items()}
            captured["host"] = headers.get("Host", "")
            return headers

        asyncio.run(run())
        assert captured["host"] == target.split("//")[-1].split(":")[0]

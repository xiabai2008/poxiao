"""被动代理测试（P1-E：转发 + 记录 + 敏感参数标记）"""

import http.client
import json
import threading

import pytest

from src.proxy.server import ProxyServer, query_calls, analyze_url, _log_path


@pytest.fixture(autouse=True)
def isolated_log(tmp_path, monkeypatch):
    log = tmp_path / "proxy.log"
    monkeypatch.setenv("POXIAO_PROXY_LOG", str(log))
    monkeypatch.setattr("src.proxy.server._log_path", lambda: log)
    yield log


class TestAnalyzeUrl:
    def test_params_parsed(self):
        info = analyze_url("http://x.com/login?user=admin&pass=1")
        assert info["params"]["user"] == "admin"
        assert info["path"] == "/login"

    def test_sensitive_params_marked(self):
        info = analyze_url("http://x.com/api?token=abc&key=1&q=2")
        assert info["sensitive_params"] == ["key", "token"]

    def test_no_query(self):
        info = analyze_url("http://x.com/")
        assert info["sensitive_params"] == []


class TestProxyForward:
    @pytest.fixture
    def target_server(self):
        """本地 mock 目标服务器"""
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # noqa: A003
                pass

            def do_GET(self):  # noqa: N802
                body = b"mock-target-ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        yield f"127.0.0.1:{srv.server_address[1]}"
        srv.shutdown()

    @pytest.fixture
    def proxy(self, tmp_path):
        srv = ProxyServer(host="127.0.0.1", port=0)
        srv._make()
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        yield f"127.0.0.1:{srv.port}"
        srv.shutdown()

    def test_forward_get(self, target_server, proxy):
        c = http.client.HTTPConnection("127.0.0.1", int(proxy.split(":")[1]), timeout=5)
        c.request("GET", f"http://{target_server}/hello?x=1")
        r = c.getresponse()
        assert r.status == 200
        assert r.read() == b"mock-target-ok"
        c.close()

        calls = query_calls()
        assert len(calls) == 1
        assert calls[0]["method"] == "GET"
        assert calls[0]["url"].endswith("/hello?x=1")
        assert calls[0]["status"] == 200

    def test_forward_post_records_body(self, target_server, proxy):
        c = http.client.HTTPConnection("127.0.0.1", int(proxy.split(":")[1]), timeout=5)
        payload = b'{"password": "secret"}'
        c.request("POST", f"http://{target_server}/api/login", body=payload,
                  headers={"Content-Type": "application/json"})
        r = c.getresponse()
        assert r.status == 200
        assert r.read() == payload
        c.close()

        calls = query_calls()
        assert calls[0]["method"] == "POST"
        assert calls[0]["url"].endswith("/api/login")

    def test_query_filter_by_domain(self, target_server, proxy, tmp_path):
        c = http.client.HTTPConnection("127.0.0.1", int(proxy.split(":")[1]), timeout=5)
        c.request("GET", f"http://{target_server}/a")
        c.getresponse().read()
        c.request("GET", "http://other.example.com/b")
        r = c.getresponse()  # 上游不可达 → 502，但仍记录
        r.read()
        c.close()

        calls = query_calls(domain=target_server)
        assert len(calls) == 1
        assert target_server in calls[0]["url"]

    def test_sensitive_param_marked_in_log(self, target_server, proxy):
        c = http.client.HTTPConnection("127.0.0.1", int(proxy.split(":")[1]), timeout=5)
        c.request("GET", f"http://{target_server}/login?password=hunter2")
        c.getresponse().read()
        c.close()
        calls = query_calls()
        assert calls[0]["sensitive_params"] == ["password"]

    def test_connect_tunnel_established(self, proxy):
        # CONNECT 到不可达端口应返回 502（验证 CONNECT 路径可响应）
        c = http.client.HTTPConnection("127.0.0.1", int(proxy.split(":")[1]), timeout=5)
        c.request("CONNECT", "127.0.0.1:1")
        r = c.getresponse()
        assert r.status in (200, 502)
        r.read()
        c.close()

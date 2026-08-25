"""被动代理服务器（P1-E：xray 式浏览器代理被动扫描入口）

- HTTP 请求：解析后经 httpx 转发，记录 method/URL/参数/头到 JSONL。
- HTTPS：CONNECT 隧道（纯 socket 透传，不解密）。
- 用途：浏览器/工具挂 `poxiao proxy` 后，正常访问目标站点即被记录，
  供后续联动扫描/人工研判（xray 同款工作流）。
"""

from __future__ import annotations

import json
import os
import socket
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

import httpx

# 敏感参数名（记录时标记，供人工关注）
SENSITIVE_PARAMS = {
    "password", "passwd", "pwd", "token", "secret", "api_key", "apikey",
    "access_token", "auth", "session", "key", "credential", "cookie",
}


def _log_path() -> Path:
    """代理日志路径（支持 POXIAO_PROXY_LOG 覆盖）"""
    return Path(os.environ.get("POXIAO_PROXY_LOG", "scan_results/proxy_calls.log"))


def _record(entry: dict) -> None:
    """记录代理流量条目到 JSONL"""
    try:
        log = _log_path()
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def analyze_url(url: str) -> dict:
    """解析 URL 并标记敏感参数（供测试与后续联动）"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    sensitive = sorted(k for k in params if k.lower() in SENSITIVE_PARAMS)
    return {
        "url": url,
        "path": parsed.path,
        "query": parsed.query,
        "params": {k: v[0] for k, v in params.items()},
        "sensitive_params": sensitive,
    }


class _ProxyHandler(BaseHTTPRequestHandler):
    """被动代理请求处理器：HTTP 转发 + CONNECT 隧道 + 流量记录"""

    server_version = "poxiao-proxy/1.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        """静默请求日志（流量已记录）"""
        return  # 静默

    # ── HTTP 转发 ────────────────────────────────
    def _forward(self) -> None:
        """转发 HTTP 请求并记录流量"""
        length = 0
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            length = 0
        body = self.rfile.read(length) if length else None

        entry = {
            "timestamp": datetime.now().isoformat(),
            "method": self.command,
            "url": self.path,
            "source_ip": self.client_address[0] if self.client_address else "",
        }
        entry.update(analyze_url(self.path))

        try:
            with httpx.Client(
                timeout=15.0, verify=False,
                follow_redirects=False,
                headers={k: v for k, v in self.headers.items()
                         if k.lower() not in ("proxy-connection", "connection", "host")},
            ) as client:
                resp = client.request(self.command, self.path, content=body)
            entry["status"] = resp.status_code
            entry["resp_size"] = len(resp.content)
            _record(entry)

            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp.content)))
            self.end_headers()
            self.wfile.write(resp.content)
        except Exception as e:
            entry["error"] = str(e)[:200]
            _record(entry)
            try:
                self.send_error(502, "poxiao-proxy upstream error")
            except OSError:
                pass

    # ── CONNECT 隧道（HTTPS 透传）─────────────────
    def do_CONNECT(self) -> None:  # noqa: N802
        """处理 HTTPS 隧道（CONNECT 透传）"""
        try:
            host, _, port = self.path.partition(":")
            port = int(port or 443)
        except ValueError:
            self.send_error(400)
            return

        try:
            upstream = socket.create_connection((host, port), timeout=15.0)
        except OSError:
            self.send_error(502)
            return

        self.send_response(200, "Connection established")
        self.end_headers()
        self.connection.settimeout(60.0)
        upstream.settimeout(60.0)

        def _pipe(src: socket.socket, dst: socket.socket) -> None:
            """双向 TCP 数据透传（隧道用）"""
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t1 = threading.Thread(target=_pipe, args=(self.connection, upstream), daemon=True)
        t2 = threading.Thread(target=_pipe, args=(upstream, self.connection), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        upstream.close()

    def do_GET(self) -> None:  # noqa: N802
        """转发并记录 GET 请求"""
        self._forward()

    def do_POST(self) -> None:  # noqa: N802
        """转发并记录 POST 请求"""
        self._forward()

    def do_PUT(self) -> None:  # noqa: N802
        """转发并记录 PUT 请求"""
        self._forward()

    def do_DELETE(self) -> None:  # noqa: N802
        """转发并记录 DELETE 请求"""
        self._forward()

    def do_PATCH(self) -> None:  # noqa: N802
        """转发并记录 PATCH 请求"""
        self._forward()

    def do_OPTIONS(self) -> None:  # noqa: N802
        """转发并记录 OPTIONS 请求"""
        self._forward()


class ProxyServer:
    """被动代理服务器封装"""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        """初始化被动代理服务器（地址/端口）"""
        self.host = host
        self.port = port
        self._httpd: Optional[ThreadingHTTPServer] = None

    def _make(self) -> ThreadingHTTPServer:
        """创建底层 HTTP 服务并回填实际端口"""
        self._httpd = ThreadingHTTPServer((self.host, self.port), _ProxyHandler)
        self.port = self._httpd.server_address[1]
        return self._httpd

    def serve_forever(self) -> None:
        """启动代理服务器（阻塞运行）"""
        httpd = self._httpd or self._make()
        try:
            httpd.serve_forever()
        finally:
            httpd.server_close()

    def shutdown(self) -> None:
        """停止代理服务器"""
        if self._httpd is not None:
            self._httpd.shutdown()


def query_calls(domain: str = "", limit: int = 100) -> list:
    """查询代理记录；domain 为 URL 包含匹配，空则全部"""
    log = _log_path()
    if not log.exists():
        return []
    calls = []
    for line in log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if domain and domain not in entry.get("url", ""):
            continue
        calls.append(entry)
        if len(calls) >= limit:
            break
    return calls

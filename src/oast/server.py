"""OAST 本地回调服务器（P1-D：盲注/XXE/SSRF 的带外检测基础设施）

设计：
- 纯 stdlib（http.server + threading + JSONL 持久化），无外部服务（守 X3）。
- 服务器记录所有到达的 HTTP 请求（method/path/query/headers/body/来源 IP）。
- 使用方式：公网可达的机器/内网穿透后配置 `POXIAO_OAST_BASE=http://<域名>`
  与回调端口；POC 模板经 `{{oast-url}}`/`{{oast-domain}}` 变量生成随机子域，
  扫描后 `poxiao oast query --domain <子域>` 查询命中，即确认带外漏洞。
- 数据文件：JSONL（默认 scan_results/oast_calls.log），可配置
  `POXIAO_OAST_LOG`。
"""

from __future__ import annotations

import json
import os
import random
import string
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse


def _log_path() -> Path:
    return Path(os.environ.get("POXIAO_OAST_LOG", "scan_results/oast_calls.log"))


def _random_label(length: int = 8) -> str:
    """生成随机子域标签（字母数字，避免域名通配干扰）"""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def gen_oast_domain() -> str:
    """生成随机 OAST 子域：<label>.<base>

    base 取自环境变量 POXIAO_OAST_BASE（默认 oast.local，提示未配置）。
    """
    base = os.environ.get("POXIAO_OAST_BASE", "oast.local")
    return f"{_random_label()}.{base}"


def gen_oast_url() -> str:
    """生成随机 OAST URL：http://<label>.<base>/"""
    return f"http://{gen_oast_domain()}/"


# ── 回调记录服务器 ──────────────────────────────────

class _OastHandler(BaseHTTPRequestHandler):
    server_version = "poxiao-oast/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return  # 静默（回调日志已落盘）

    def _record(self) -> None:
        length = 0
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            length = 0
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        parsed = urlparse(self.path)
        entry = {
            "timestamp": datetime.now().isoformat(),
            "method": self.command,
            "scheme": "http",
            "path": parsed.path,
            "query": parsed.query,
            "query_params": parse_qs(parsed.query),
            "headers": dict(self.headers),
            "body": body[:4096],
            "source_ip": self.client_address[0] if self.client_address else "",
        }
        try:
            log = _log_path()
            log.parent.mkdir(parents=True, exist_ok=True)
            with log.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass

        # 统一 200，尽量不暴露回调服务器特征
        resp = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def do_GET(self) -> None:  # noqa: N802
        self._record()

    def do_POST(self) -> None:  # noqa: N802
        self._record()

    def do_PUT(self) -> None:  # noqa: N802
        self._record()

    def do_DELETE(self) -> None:  # noqa: N802
        self._record()

    def do_HEAD(self) -> None:  # noqa: N802
        self._record()


class OastServer:
    """OAST 回调服务器封装"""

    def __init__(self, host: str = "0.0.0.0", port: int = 8899):
        self.host = host
        self.port = port
        self._httpd: Optional[ThreadingHTTPServer] = None

    def _make(self) -> ThreadingHTTPServer:
        self._httpd = ThreadingHTTPServer((self.host, self.port), _OastHandler)
        self.port = self._httpd.server_address[1]
        return self._httpd

    def serve_forever(self) -> None:
        httpd = self._httpd or self._make()
        try:
            httpd.serve_forever()
        finally:
            httpd.server_close()

    def shutdown(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()


# ── 查询 ────────────────────────────────────────────

def query_calls(domain: str = "", limit: int = 100) -> List[Dict]:
    """查询回调记录；domain 为前缀匹配（如子域标签），空则返回全部"""
    log = _log_path()
    if not log.exists():
        return []
    calls: List[Dict] = []
    for line in log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if domain and f"{domain}" not in entry.get("path", "") + entry.get("query", ""):
            continue
        calls.append(entry)
        if len(calls) >= limit:
            break
    return calls


def flush_calls() -> int:
    """清空回调记录，返回清除条数"""
    log = _log_path()
    if not log.exists():
        return 0
    count = len(log.read_text(encoding="utf-8").splitlines())
    log.unlink()
    return count

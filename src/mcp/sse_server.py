"""破晓 PoXiao — MCP 服务端，SSE (HTTP) 传输

实现 MCP 旧版 HTTP+SSE 传输（protocolVersion 2024-11-05），兼容支持 SSE 的
MCP 客户端（Cursor / 部分网关 / n8n 等）：

  - GET  /sse                       建立 SSE 长连接；首帧下发 endpoint 事件（含 sessionId）
  - POST /messages?sessionId=<id>   客户端提交 JSON-RPC 请求；服务端 202 应答，
                                    实际响应经该会话的 SSE 流以 message 事件回推

设计约束:
  - 纯 stdlib（http.server + threading + queue），不引入 Flask 等外部依赖（守 X3 / Q5）
  - 复用 protocol.process_message 协议核心，行为与 stdio 完全一致
  - 默认仅监听回环地址 127.0.0.1（私有化定位，避免误暴露）
"""
from __future__ import annotations

import json
import logging
import queue
import secrets
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse

from .protocol import process_message

logger = logging.getLogger("poxiao.mcp")

# 心跳间隔（秒）：SSE 空闲时发送注释行保活，避免中间代理断连
_HEARTBEAT_SECS = 15

# 会话表: sessionId -> 该连接的消息队列（放入 None 表示关闭）
_SESSIONS: Dict[str, "queue.Queue"] = {}
_LOCK = threading.Lock()

# 访问令牌：设置后 GET /sse 与 POST /messages 均须携带
# Authorization: Bearer <token> 或 ?token=<token> 参数（secrets.compare_digest 恒时比较）
_REQUIRED_TOKEN: str = ""


class _Handler(BaseHTTPRequestHandler):
    """MCP HTTP+SSE 请求处理器"""

    server_version = "poxiao-mcp/3.1.0"
    protocol_version = "HTTP/1.1"

    # 日志走 logger（stderr），不污染 stdout
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        """请求日志写入 logger（stderr），不污染协议流"""
        logger.info("%s - %s", self.address_string(), fmt % args)

    # ── 鉴权 ─────────────────────────────────────
    def _check_auth(self) -> bool:
        """校验 Bearer 令牌或 ?token= 参数；未启用令牌时恒通过"""
        if not _REQUIRED_TOKEN:
            return True
        provided = ""
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            provided = auth[7:].strip()
        if not provided:
            qs = parse_qs(urlparse(self.path).query)
            provided = (qs.get("token") or [""])[0]
        return secrets.compare_digest(provided, _REQUIRED_TOKEN)

    def _send_unauthorized(self) -> None:
        """返回 401 + WWW-Authenticate 头"""
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Bearer realm="poxiao-mcp"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ── GET /sse：建立 SSE 长连接 ──────────────────────
    def do_GET(self) -> None:  # noqa: N802
        """处理 GET /sse（鉴权 → 建立 SSE 长连接 → 心跳保活）"""
        parsed = urlparse(self.path)
        if parsed.path != "/sse":
            self.send_error(404, "Not Found")
            return

        if not self._check_auth():
            self._send_unauthorized()
            return

        session_id = uuid.uuid4().hex
        q: "queue.Queue" = queue.Queue()
        with _LOCK:
            _SESSIONS[session_id] = q

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        try:
            # 首帧：告知客户端用于回传 JSON-RPC 的 POST 端点
            self._write_event("endpoint", f"/messages?sessionId={session_id}")
            while True:
                try:
                    payload: Optional[str] = q.get(timeout=_HEARTBEAT_SECS)
                except queue.Empty:
                    # 心跳注释行（以 : 开头，客户端忽略）
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    continue
                if payload is None:  # 主动关闭信号
                    break
                self._write_event("message", payload)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass  # 客户端断开，正常退出
        finally:
            with _LOCK:
                _SESSIONS.pop(session_id, None)

    # ── POST /messages：接收 JSON-RPC 请求 ─────────────
    def do_POST(self) -> None:  # noqa: N802
        """处理 POST /messages（鉴权 → 解析 JSON-RPC → 202 应答 → SSE 回推）"""
        parsed = urlparse(self.path)
        if parsed.path != "/messages":
            self.send_error(404, "Not Found")
            return

        if not self._check_auth():
            self._send_unauthorized()
            return

        qs = parse_qs(parsed.query)
        session_id = (qs.get("sessionId") or [""])[0]
        with _LOCK:
            q = _SESSIONS.get(session_id)
        if q is None:
            self.send_error(404, "Unknown or expired sessionId")
            return

        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            self.send_error(400, "Invalid Content-Length")
            return
        raw = self.rfile.read(length) if length else b""
        try:
            msg = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self.send_error(400, "Invalid JSON")
            return

        # 立即 202 Accepted：真正的响应经 SSE 流回推
        body = b"Accepted"
        self.send_response(202)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

        if isinstance(msg, dict):
            resp = process_message(msg)
            if resp is not None:
                q.put(json.dumps(resp, ensure_ascii=False, default=str))

    # ── 辅助：写一个 SSE 事件帧 ────────────────────────
    def _write_event(self, event: str, data: str) -> None:
        """写入一个 SSE 事件帧（event + data）"""
        chunk = f"event: {event}\ndata: {data}\n\n".encode("utf-8")
        self.wfile.write(chunk)
        self.wfile.flush()


class SSEServer:
    """MCP SSE 服务端封装（基于 ThreadingHTTPServer）"""

    def __init__(self, host: str = "127.0.0.1", port: int = 8765, token: str = ""):
        """初始化 SSE 服务器（地址/端口/token 鉴权）"""
        self.host = host
        self.port = port
        global _REQUIRED_TOKEN
        _REQUIRED_TOKEN = token
        self._httpd: Optional[ThreadingHTTPServer] = None

    def _make(self) -> ThreadingHTTPServer:
        """创建底层 HTTP 服务并回填实际端口（支持 port=0 自动分配）"""
        self._httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
        self.port = self._httpd.server_address[1]
        return self._httpd

    def serve_forever(self) -> None:
        """启动 HTTP 服务（阻塞运行）"""
        httpd = self._httpd or self._make()
        try:
            httpd.serve_forever()
        finally:
            httpd.server_close()

    def shutdown(self) -> None:
        """停止服务（供另一线程调用）并唤醒所有 SSE 连接"""
        with _LOCK:
            for q in list(_SESSIONS.values()):
                q.put(None)
        if self._httpd is not None:
            self._httpd.shutdown()

"""破晓 PoXiao — MCP (Model Context Protocol) 服务端，stdio 传输

实现 JSON-RPC 2.0 over stdio（逐行换行分隔的 JSON 消息），兼容 Claude Desktop /
CodeBuddy / Cursor 等 MCP 客户端的 stdio 接入。

协议要点:
  - 客户端 → 服务端: 逐行 JSON-RPC 请求/通知
  - 服务端 → 客户端: 逐行 JSON-RPC 响应（仅 stdout，保证协议流纯净）
  - 方法: initialize / ping / tools/list / tools/call
  - 通知（无 id）: notifications/initialized 等，忽略即可

设计约束:
  - 纯 stdlib，无外部依赖（守 X3 / Q5）
  - 工具执行期间重定向 stdout，避免引擎 print 污染 JSON-RPC 流（日志走 stderr）
  - 结果以 text content（JSON 字符串）返回，便于 AI 消费
"""
from __future__ import annotations

import json
import logging
import sys
from typing import Any, Dict, Optional, TextIO

from .protocol import PROTOCOL_VERSION, SERVER_INFO, process_message

logger = logging.getLogger("poxiao.mcp")

__all__ = ["MCPServer", "PROTOCOL_VERSION", "SERVER_INFO"]


class MCPServer:
    """stdio 传输的 MCP 服务端"""

    def __init__(self, instream: Optional[TextIO] = None, outstream: Optional[TextIO] = None):
        # 捕获原始 stdout 引用：即使工具执行时 redirect_stdout，
        # 我们仍向真实 stdout 写出 JSON-RPC 响应。
        self.instream = instream if instream is not None else sys.stdin
        self.outstream = outstream if outstream is not None else sys.stdout

    # ── 底层 IO ──────────────────────────────────────
    def _send(self, obj: Dict[str, Any]) -> None:
        line = json.dumps(obj, ensure_ascii=False, default=str)
        self.outstream.write(line + "\n")
        self.outstream.flush()

    def _send_error(self, msg_id: Any, code: int, message: str, data: Any = None) -> None:
        err: Dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        self._send({"jsonrpc": "2.0", "id": msg_id, "error": err})

    # ── 方法处理 ────────────────────────────────────
    def _handle(self, msg: Dict[str, Any]) -> None:
        """委托给共用协议核心，得到响应后写回 stdout"""
        resp = process_message(msg)
        if resp is not None:
            self._send(resp)

    # ── 主循环 ──────────────────────────────────────
    def run(self) -> None:
        """从 stdin 逐行读取 JSON-RPC 请求并分发。Ctrl-C / EOF 退出。"""
        for line in self.instream:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(msg, dict):
                continue
            try:
                self._handle(msg)
            except Exception as e:  # 单条消息出错不影响后续
                logger.exception("handle error")
                if isinstance(msg, dict) and msg.get("id") is not None:
                    self._send_error(msg["id"], -32603, f"Internal error: {e}")

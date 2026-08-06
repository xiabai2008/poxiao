"""破晓 PoXiao — MCP JSON-RPC 2.0 消息处理核心（stdio / SSE 传输共用）

把「一条 JSON-RPC 消息 → 一条响应」的纯处理逻辑抽离出来，供两种传输复用：
  - stdio: src/mcp/server.py（逐行 JSON）
  - SSE  : src/mcp/sse_server.py（HTTP + text/event-stream）

设计约束:
  - 纯 stdlib，无外部依赖（守 X3 / Q5）
  - 工具执行期间重定向 stdout，避免引擎 print 污染协议流（日志走 stderr）
  - 通知（无 id）不产生响应，返回 None
"""
from __future__ import annotations

import contextlib
import io
import logging
from typing import Any, Dict, Optional

from .tools import TOOL_DEFINITIONS, dispatch_tool

logger = logging.getLogger("poxiao.mcp")

# 与主流 MCP 客户端兼容的协议版本号
PROTOCOL_VERSION = "2024-11-05"

SERVER_INFO = {"name": "poxiao", "version": "3.0.0"}


def make_error(msg_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    """构造 JSON-RPC 错误响应对象"""
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": msg_id, "error": err}


def process_message(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """处理单条 JSON-RPC 消息。

    返回值:
      - dict: 需要回送给客户端的响应
      - None: 通知（无 id）不回复
    """
    method = msg.get("method")
    msg_id = msg.get("id")
    params: Dict[str, Any] = msg.get("params") or {}

    # 通知（无 id）不回复
    if msg_id is None:
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOL_DEFINITIONS}}

    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        try:
            # 重定向 stdout：引擎进度/print 不应污染协议流
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                result = dispatch_tool(name, arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": result.get("content", []),
                    "isError": result.get("isError", False),
                },
            }
        except Exception as e:  # 防御性：任何异常都回错误，不崩服务端
            logger.exception("tool %s failed", name)
            return make_error(msg_id, -32000, f"tool error: {e}")

    return make_error(msg_id, -32601, f"Method not found: {method}")

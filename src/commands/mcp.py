"""MCP 服务端命令 — 启动破晓 Model Context Protocol 服务端 (stdio / SSE)"""

import logging
import sys

from src.mcp.server import MCPServer

logger = logging.getLogger("poxiao.mcp")


def cmd_mcp(args):
    """启动破晓 MCP 服务端（stdio 或 SSE 传输，供 AI 助手调用）"""
    # 注意：stdio 模式下 stdout 必须专用于 JSON-RPC 协议流，任何状态信息都写到 stderr。
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [mcp] %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    transport = getattr(args, "transport", "stdio")

    if transport == "sse":
        from src.mcp.sse_server import SSEServer

        host = getattr(args, "host", "127.0.0.1")
        port = int(getattr(args, "port", 8765))
        server = SSEServer(host=host, port=port)
        server._make()  # 提前绑定端口，便于打印真实地址
        sys.stderr.write(
            f"破晓 MCP 服务端已启动 (SSE): http://{host}:{server.port}/sse  按 Ctrl-C 退出。\n"
        )
        sys.stderr.flush()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
            sys.stderr.write("\n破晓 MCP 服务端已停止。\n")
            sys.stderr.flush()
        return

    # 默认 stdio
    sys.stderr.write("破晓 MCP 服务端已启动 (stdio)。按 Ctrl-C 退出。\n")
    sys.stderr.flush()

    server = MCPServer()
    try:
        server.run()
    except KeyboardInterrupt:
        sys.stderr.write("\n破晓 MCP 服务端已停止。\n")
        sys.stderr.flush()

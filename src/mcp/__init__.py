"""破晓 PoXiao — MCP (Model Context Protocol) 服务端包

提供 stdio 与 SSE(HTTP) 两种传输的 JSON-RPC 2.0 服务，让 AI 助手
（Claude / CodeBuddy / Cursor 等）直接调用破晓的扫描能力，返回结构化 JSON 结果。

入口:      src/commands/mcp.py (poxiao mcp [--transport stdio|sse])
协议核心:  src/mcp/protocol.py  (process_message，两种传输共用)
stdio 传输: src/mcp/server.py
SSE   传输: src/mcp/sse_server.py
工具定义:  src/mcp/tools.py
"""

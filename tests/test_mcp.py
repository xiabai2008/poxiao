"""MCP 服务端测试（协议层 + 工具分发 + SSE 传输，无外部网络）"""

import http.client
import io
import json
import threading

from src.mcp.protocol import process_message
from src.mcp.server import MCPServer
from src.mcp.sse_server import SSEServer
from src.mcp.tools import TOOL_DEFINITIONS, dispatch_tool


def _send_recv(server, messages):
    """把多条请求写入 stdin StringIO，跑一轮 run()，返回响应列表"""
    instream = io.StringIO("\n".join(json.dumps(m) for m in messages) + "\n")
    outstream = io.StringIO()
    srv = MCPServer(instream=instream, outstream=outstream)
    srv.run()
    out = outstream.getvalue().strip()
    if not out:
        return []
    return [json.loads(line) for line in out.splitlines() if line.strip()]


# ── 协议层 ──────────────────────────────────────────
def test_initialize():
    resp = _send_recv(MCPServer, [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05"}},
    ])
    assert len(resp) == 1
    assert resp[0]["id"] == 1
    assert resp[0]["result"]["protocolVersion"] == "2024-11-05"
    assert "tools" in resp[0]["result"]["capabilities"]
    assert resp[0]["result"]["serverInfo"]["name"] == "poxiao"


def test_ping():
    resp = _send_recv(MCPServer, [
        {"jsonrpc": "2.0", "id": 2, "method": "ping"},
    ])
    assert resp[0]["id"] == 2
    assert resp[0]["result"] == {}


def test_tools_list_has_seven_tools():
    resp = _send_recv(MCPServer, [
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
    ])
    tools = resp[0]["result"]["tools"]
    names = {t["name"] for t in tools}
    assert {
        "scan_targets", "check_alive", "subdomain_enum", "passive_recon",
        "verify_target", "poc_scan", "util_codec",
    } <= names
    # 每个工具都有 inputSchema
    assert all("inputSchema" in t for t in tools)


def test_notification_ignored():
    # 通知无 id，不应产生任何响应
    resp = _send_recv(MCPServer, [
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ])
    assert resp == []


def test_method_not_found():
    resp = _send_recv(MCPServer, [
        {"jsonrpc": "2.0", "id": 9, "method": "bogus/method"},
    ])
    assert resp[0]["error"]["code"] == -32601


# ── 工具分发（离线）────────────────────────────────
def test_dispatch_unknown_tool():
    r = dispatch_tool("nope", {})
    assert r["isError"] is True
    assert "error" in json.loads(r["content"][0]["text"])


def test_tools_call_util_codec_roundtrip():
    # 通过协议层调用 util_codec（完全离线）
    resp = _send_recv(MCPServer, [
        {"jsonrpc": "2.0", "id": 10, "method": "tools/call",
         "params": {"name": "util_codec",
                    "arguments": {"action": "encode", "type": "base64", "text": "hello"}}},
    ])
    assert resp[0]["id"] == 10
    data = json.loads(resp[0]["result"]["content"][0]["text"])
    assert data["result"] == "aGVsbG8="  # base64("hello")
    assert resp[0]["result"]["isError"] is False


def test_util_codec_decode_and_hash():
    enc = dispatch_tool("util_codec",
                        {"action": "decode", "type": "base64", "text": "aGVsbG8="})
    assert json.loads(enc["content"][0]["text"])["result"] == "hello"

    h = dispatch_tool("util_codec", {"action": "hash", "type": "md5", "text": "admin"})
    assert json.loads(h["content"][0]["text"])["result"] == "21232f297a57a5a743894a0e4a801fc3"


def test_util_codec_auto():
    r = dispatch_tool("util_codec", {"action": "auto", "text": "aGVsbG8="})
    data = json.loads(r["content"][0]["text"])
    types = {x["type"] for x in data["results"]}
    assert "base64" in types


def test_scan_targets_missing_args_returns_error():
    # 无网络：缺 target / target_file 应返回结构化错误
    r = dispatch_tool("scan_targets", {})
    assert r["isError"] is True


def test_tool_count_matches_definitions():
    # TOOL_DEFINITIONS 与分发表保持一致（7 个）
    assert len(TOOL_DEFINITIONS) == 7


# ── 协议核心 process_message（stdio/SSE 共用）──────────
def test_process_message_notification_returns_none():
    assert process_message({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_process_message_initialize():
    resp = process_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert resp["result"]["serverInfo"]["name"] == "poxiao"
    assert resp["result"]["protocolVersion"] == "2024-11-05"


def test_process_message_method_not_found():
    resp = process_message({"jsonrpc": "2.0", "id": 7, "method": "nope"})
    assert resp["error"]["code"] == -32601


# ── SSE 传输集成测试（本机回环，纯 stdlib）────────────
def _read_sse_event(fp, max_lines=200):
    """从 SSE 流读取一个事件帧，跳过心跳注释行；返回 (event, data)"""
    event = None
    data = None
    for _ in range(max_lines):
        raw = fp.readline()
        if not raw:
            break
        line = raw.decode("utf-8").rstrip("\r\n")
        if line.startswith(":"):  # 心跳注释
            continue
        if line == "":
            if event is not None or data is not None:
                return event, data
            continue
        if line.startswith("event:"):
            event = line[len("event:"):].strip()
        elif line.startswith("data:"):
            data = line[len("data:"):].strip()
    return event, data


def test_sse_endpoint_and_tools_call():
    srv = SSEServer(host="127.0.0.1", port=0)
    srv._make()  # 绑定随机端口
    port = srv.port
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        # 1) 建立 SSE 连接，读取首帧 endpoint 事件
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/sse")
        resp = conn.getresponse()
        assert resp.status == 200
        assert "text/event-stream" in resp.getheader("Content-Type", "")

        event, data = _read_sse_event(resp.fp)
        assert event == "endpoint"
        assert data.startswith("/messages?sessionId=")
        endpoint = data

        # 2) POST 一个离线可完成的 tools/call（util_codec base64 编码）
        c2 = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        payload = json.dumps({
            "jsonrpc": "2.0", "id": 42, "method": "tools/call",
            "params": {"name": "util_codec",
                       "arguments": {"action": "encode", "type": "base64", "text": "hello"}},
        })
        c2.request("POST", endpoint, body=payload,
                   headers={"Content-Type": "application/json"})
        r2 = c2.getresponse()
        assert r2.status == 202
        r2.read()

        # 3) 响应经 SSE 流以 message 事件回推
        event, data = _read_sse_event(resp.fp)
        assert event == "message"
        obj = json.loads(data)
        assert obj["id"] == 42
        inner = json.loads(obj["result"]["content"][0]["text"])
        assert inner["result"] == "aGVsbG8="  # base64("hello")

        conn.close()
        c2.close()
    finally:
        srv.shutdown()


def test_sse_unknown_session_404():
    srv = SSEServer(host="127.0.0.1", port=0)
    srv._make()
    port = srv.port
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", "/messages?sessionId=deadbeef",
                  body="{}", headers={"Content-Type": "application/json"})
        r = c.getresponse()
        assert r.status == 404
        r.read()
        c.close()
    finally:
        srv.shutdown()

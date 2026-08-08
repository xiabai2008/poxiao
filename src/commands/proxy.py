"""被动代理命令（P1-E：xray 式浏览器代理）"""

from src.utils.output import Out


def cmd_proxy(args):
    """被动代理服务器"""
    if args.proxy_action == "serve":
        from src.proxy.server import ProxyServer
        host = getattr(args, "host", "127.0.0.1")
        port = getattr(args, "port", 8080)
        server = ProxyServer(host=host, port=port)
        server._make()
        Out.success(f"被动代理已启动: http://{host}:{server.port}   (Ctrl+C 停止)")
        Out.info("浏览器/工具设置代理后正常访问目标即可被动记录")
        Out.info("记录: scan_results/proxy_calls.log")
        Out.info("提示: HTTPS 流量经 CONNECT 隧道透传（不解密），仅记录 HTTP 明文请求")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
            Out.warning("\n被动代理已停止")
        return

    if args.proxy_action == "query":
        from src.proxy.server import query_calls
        domain = getattr(args, "domain", "") or ""
        calls = query_calls(domain=domain, limit=getattr(args, "limit", 100))
        if not calls:
            Out.info(f"无代理记录{(' (URL 包含: ' + domain + ')') if domain else ''}")
            return
        Out.section(f"代理流量记录 ({len(calls)})", "🌐")
        for c in calls:
            sens = f"  [敏感参数: {','.join(c['sensitive_params'])}]" \
                if c.get("sensitive_params") else ""
            Out._print(
                f"  {c.get('status', '?')} {c['method']} {c.get('url', '')[:90]}{sens}"
            )
        return

    Out.info("用法: poxiao proxy {serve|query}")
    Out._print("    poxiao proxy serve --port 8080")
    Out._print("    poxiao proxy query --domain example.com")

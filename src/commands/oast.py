"""OAST 带外回调命令（P1-D）"""


from src.utils.output import Out, C


def cmd_oast(args):
    """OAST 带外回调基础设施"""
    if args.oast_action == "serve":
        from src.oast.server import OastServer
        host = getattr(args, "host", "0.0.0.0")
        port = getattr(args, "port", 8899)
        server = OastServer(host=host, port=port)
        server._make()
        Out.success(f"OAST 回调服务器已启动: http://{host}:{server.port}   (Ctrl+C 停止)")
        Out.info("配置 POXIAO_OAST_BASE=http://<公网域名> 后，模板 {{oast-url}} 将使用该域名")
        Out.info("日志: scan_results/oast_calls.log")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
            Out.warning("\nOAST 服务器已停止")
        return

    if args.oast_action == "query":
        from src.oast.server import query_calls
        domain = getattr(args, "domain", "") or ""
        calls = query_calls(domain=domain, limit=getattr(args, "limit", 100))
        if not calls:
            Out.info(f"无回调记录{(' (包含: ' + domain + ')') if domain else ''}")
            return
        Out.section(f"OAST 回调记录 ({len(calls)})", "📡")
        for c in calls:
            Out._print(
                f"  {C.CYAN}{c['timestamp'][:19]}{C.RESET} "
                f"{c['method']} {c.get('path', '')}"
                + (f"?{c['query']}" if c.get("query") else "")
                + f"  {C.DIM}src={c.get('source_ip', '?')}{C.RESET}"
            )
            if c.get("body"):
                Out.dim(f"      body: {c['body'][:200]}")
        return

    if args.oast_action == "flush":
        from src.oast.server import flush_calls
        n = flush_calls()
        Out.success(f"已清空 {n} 条回调记录")
        return

    Out.info("用法: poxiao oast {serve|query|flush}")
    Out._print("    poxiao oast serve --port 8899")
    Out._print("    poxiao oast query --domain <子域>")
    Out._print("    poxiao oast flush")

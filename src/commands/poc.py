"""POC 模板扫描命令"""

import asyncio
import time
from pathlib import Path

from src.xiazhi import POCEngine, TemplateLoader
from src.guanxing.poc_store import save_scan_results, compare_with_last, print_history, get_target_stats, print_findings
from src.utils.output import Out, C


def cmd_poc(args):
    """POC 模板扫描"""
    if not args.poc_action:
        Out.info("用法: poxiao poc {scan|list|history}")
        Out._print("    poxiao poc scan example.com -t templates/")
        Out._print("    poxiao poc scan example.com --history")
        Out._print("    poxiao poc scan example.com --loop --interval 3600")
        Out._print("    poxiao poc history example.com --findings")
        Out._print("    poxiao poc list -t templates/")
        return

    template_dir = getattr(args, 'templates', '') or ""
    extra_dirs = []
    if hasattr(args, 'template_dir') and args.template_dir:
        extra_dirs.append(args.template_dir)

    if args.poc_action == "list":
        loader = TemplateLoader(template_dir, extra_dirs=extra_dirs)
        tags = [t.strip() for t in args.tags.split(",") if t.strip()] if args.tags else None
        severity_filter = [s.strip() for s in args.severity.split(",") if s.strip()] if args.severity else None
        templates = loader.load_all(tags=tags, severity=severity_filter)
        loader.list_templates(templates)
        return

    if args.poc_action == "history":
        target = args.target
        if not target.startswith("http"):
            target = f"https://{target}"
        stats = get_target_stats(target)
        Out.section(f"目标统计: {target}", "📊")
        Out.kv_row("扫描次数", str(stats['scan_count']))
        Out.kv_row("总漏洞数", str(stats['total_findings']))
        if stats['severity_counts']:
            for sev, cnt in stats['severity_counts'].items():
                Out.kv_row(sev, str(cnt), indent=6)
        print_history(target)
        if args.findings:
            print_findings(target, only_new=getattr(args, 'only_new', False))
        return

    if args.poc_action == "scan":
        _run_poc_scan(args, template_dir)
        return


def _run_poc_scan(args, template_dir):
    """执行 POC 扫描 (支持历史对比 + 持续性扫描)"""
    extra_dirs = []
    if hasattr(args, 'template_dir') and args.template_dir:
        extra_dirs.append(args.template_dir)

    # P2-5: 社区模板库（默认 templates-community/，POXIAO_COMMUNITY_PATH 覆盖）
    if getattr(args, "include_community", False):
        import os
        community = os.environ.get(
            "POXIAO_COMMUNITY_PATH",
            str(Path(__file__).parent.parent.parent / "templates-community"),
        )
        if Path(community).exists():
            extra_dirs.append(community)
            Out.info(f"社区模板库: {community}（实验性，未签名模板可能产生噪音）")
        else:
            Out.warning(f"社区模板库不存在（{community}），已跳过；"
                        "可用 template_sync.py sync 拉取")

    # 加载模板（P1-C: 可选签名校验）
    verify_sigs = bool(getattr(args, "verify_signatures", False))
    public_key = getattr(args, "public_key", "") or ""
    if verify_sigs:
        if not public_key:
            Out.error("--verify-signatures 需要 --public-key <公钥 PEM 路径>")
            return
        Out.info(f"模板签名校验: 已启用（公钥 {public_key}）")
    loader = TemplateLoader(template_dir, extra_dirs=extra_dirs)
    tags = [t.strip() for t in args.tags.split(",") if t.strip()] if args.tags else None
    severity_filter = [s.strip() for s in args.severity.split(",") if s.strip()] if args.severity else None
    templates = loader.load_all(
        tags=tags, severity=severity_filter,
        verify_signatures=verify_sigs, public_key_path=public_key,
    )

    if not templates:
        Out.error("未找到模板。请确认 templates/ 目录存在且包含 YAML 文件")
        return

    sev_counts = loader.count_by_severity(templates)

    # 配置信息框
    config_lines = [
        f"模板: {len(templates)} 个",
        f"并发: {args.concurrency}",
    ]
    for sev, cnt in sev_counts.items():
        if cnt > 0:
            config_lines.append(f"  {sev}: {cnt}")

    # 加载目标
    targets = []
    if Path(args.target).exists():
        raw = Path(args.target).read_text(encoding="utf-8").splitlines()
        targets = [ln.strip() for ln in raw if ln.strip() and not ln.strip().startswith("#")]
    else:
        targets = [args.target]

    # 自动补全 URL scheme
    fixed_targets = []
    for t in targets:
        if not t.startswith("http://") and not t.startswith("https://"):
            t = f"https://{t}"
        fixed_targets.append(t)
    targets = fixed_targets

    config_lines.append(f"目标: {len(targets)} 个")

    # 显示配置框
    Out.box("POC 模板扫描", config_lines, C.CYAN)

    # 显示目标列表
    if len(targets) <= 5:
        for t in targets:
            Out.info(t)
    else:
        for t in targets[:3]:
            Out.info(t)
        Out.dim(f"... 共 {len(targets)} 个")

    # 隐匿模式
    if args.stealth:
        Out.blank()
        Out.info("隐匿模式: 已启用")
        if args.proxies:
            Out.info(f"代理文件: {args.proxies}")
        Out.info(f"限速: 全局 {args.qps} QPS, 单域名 {args.domain_qps} QPS")

    # WAF 绕过（P2-3 / X2：默认关，需显式 --waf-bypass 启用）
    if getattr(args, "waf_bypass", False):
        Out.blank()
        Out.info("WAF 绕过: 已启用（可选能力，建议仅在内网/授权测试中使用）")

    # 持续性扫描
    if args.loop:
        Out.blank()
        Out.info(f"持续性扫描: 间隔 {args.interval}s (Ctrl+C 停止)")

    Out.blank()

    # 创建引擎
    engine = POCEngine(
        timeout=args.timeout,
        concurrency=args.concurrency,
        stealth=args.stealth,
        enable_waf_bypass=getattr(args, "waf_bypass", False),
        proxy_file=args.proxies,
        qps=args.qps,
        per_domain_qps=args.domain_qps,
        track_oast=bool(getattr(args, "oast", False)),
    )

    # 验证代理
    if args.stealth and engine._stealth_client and engine._stealth_client.proxy_pool.proxies:
        asyncio.run(engine._stealth_client.validate_proxies())

    # 扫描函数
    def run_single_scan():
        t0 = time.perf_counter()
        if len(targets) == 1:
            results = asyncio.run(engine.scan_target(targets[0], templates))
            elapsed = time.perf_counter() - t0

            # 保存到数据库
            result_dicts = [r.to_dict() for r in results if r.matched]
            save_scan_results(
                targets[0], result_dicts,
                template_count=len(templates), elapsed=elapsed
            )

            # 打印结果摘要
            matched = [r for r in results if r.matched]
            if matched:
                Out.blank()
                Out.section("扫描结果", "🔥")
                Out.success(f"发现 {len(matched)} 个漏洞  {C.DIM}({Out.elapsed(elapsed)}){C.RESET}")

                # 按严重级别分组
                by_severity = {}
                for r in matched:
                    by_severity.setdefault(r.severity, []).append(r)

                for sev in ["critical", "high", "medium", "low", "info"]:
                    vulns = by_severity.get(sev, [])
                    if not vulns:
                        continue
                    icon = Out.severity_icon(sev)
                    Out.blank()
                    Out._print(f"    {icon} {C.BOLD}{sev.upper()}{C.RESET} ({len(vulns)})")
                    for r in vulns:
                        Out._print(f"      {r.template_name}")
                        Out._print(f"        {C.DIM}{r.request_url}{C.RESET}")
                        if r.extracted:
                            for k, v in r.extracted.items():
                                Out._print(f"        {C.GREEN}{k}: {v[:60]}{C.RESET}")
            else:
                Out.blank()
                Out.success(f"扫描完成  {C.DIM}({Out.elapsed(elapsed)}){C.RESET}")
                Out.info("未发现漏洞")

            # 历史对比
            if args.history:
                diff = compare_with_last(targets[0], result_dicts)
                Out.blank()
                Out.section("历史对比", "📊")
                if diff.new_findings:
                    Out.success(f"新增 {len(diff.new_findings)} 个漏洞")
                    for f in diff.new_findings:
                        Out._print(f"      + {f.get('template_name', '')} [{f.get('severity', '')}]")
                if diff.existing_findings:
                    Out.info(f"已知 {len(diff.existing_findings)} 个漏洞")
                if diff.disappeared:
                    Out.warning(f"消失 {len(diff.disappeared)} 个漏洞")
                    for f in diff.disappeared:
                        Out._print(f"      - {f.get('template_id', '')}")

            return results
        else:
            all_results = asyncio.run(engine.scan_targets(targets, templates, concurrency=args.concurrency))
            elapsed = time.perf_counter() - t0
            Out.success(f"耗时: {Out.elapsed(elapsed)}")
            total_findings = sum(len(v) for v in all_results.values())
            Out.blank()
            Out.section("扫描结果", "🔥")
            Out.success(f"发现 {total_findings} 个漏洞 (跨 {len(all_results)} 个目标)")
            for target, results in all_results.items():
                Out.blank()
                Out._print(f"    {C.BOLD}▶ {target}{C.RESET}")
                engine.print_results(results, target)
                # 保存到数据库
                result_dicts = [r.to_dict() for r in results if r.matched]
                save_scan_results(target, result_dicts, template_count=len(templates), elapsed=elapsed)
            return []

    # 执行扫描
    if args.loop:
        # 持续性扫描模式
        round_num = 0
        try:
            while True:
                round_num += 1
                Out.blank()
                Out.separator("═")
                Out._print(f"  {C.BOLD}第 {round_num} 轮扫描{C.RESET}")
                Out.dim(f"  时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
                Out.separator("═")

                results = run_single_scan()

                Out.blank()
                Out.info(f"下一轮扫描将在 {args.interval}s 后...")
                Out.dim("(按 Ctrl+C 停止)")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            Out.blank()
            Out.warning(f"持续性扫描已停止 (共 {round_num} 轮)")
            if args.stealth and engine._stealth_client:
                engine._stealth_client.print_stats()
    else:
        # 单次扫描
        results = run_single_scan()

    # 保存结果
    if args.output and results:
        save_path = engine.save_results(results, args.output)
        Out.success(f"结果已保存: {save_path}")

    # P1-D: OAST 带外验证（扫描后查询回调服务器）
    if getattr(args, "oast_check", False):
        try:
            from src.oast.server import query_calls
            domains = list(engine._oast_domains)
            Out.blank()
            Out.section("OAST 带外验证", "📡")
            if not domains:
                Out.info("本次扫描未生成 OAST 子域（需 --oast 启用变量）")
                return
            hits = 0
            for d in domains:
                calls = query_calls(domain=d)
                if calls:
                    hits += 1
                    Out.success(f"回调命中: {d}")
                    for c in calls[:3]:
                        Out._print(f"    {c['method']} {c.get('path', '')} "
                                   f"{C.DIM}({c['timestamp'][:19]}){C.RESET}")
            if hits == 0:
                Out.info(f"未检测到 {len(domains)} 个 OAST 子域的回调（确认带外验证结果）")
            else:
                Out.success(f"共 {hits}/{len(domains)} 个子域产生回调")
        except Exception as e:
            Out.warning(f"OAST 验证失败（已忽略）: {e}")

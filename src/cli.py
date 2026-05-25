"""破晓 CLI 入口"""

import argparse
import asyncio
import sys
import time
from pathlib import Path

from src.target.manager import TargetManager
from src.target.discovery import DomainDiscovery
from src.scanner.engine import ScanEngine
from src.reporter.reporter import Reporter
from src.reporter.src_reporter import SRCReporter
from src.collector.shuangyue import ShuangYue
from src.verifier.jingzhe import JingZhe
from src.monitor import import_from_summary, start_server, get_stats
import json


def main():
    parser = argparse.ArgumentParser(
        prog="破晓",
        description="Bug Bounty 辅助工具 — 信息收集 + 技术栈识别 + 敏感路径发现",
    )
    sub = parser.add_subparsers(dest="command")

    # ── scan 命令 ─────────────────────────────────
    scan_parser = sub.add_parser("scan", help="扫描目标")
    scan_parser.add_argument(
        "target",
        nargs="?",
        help="目标文件（每行一个URL）或单个URL",
    )
    scan_parser.add_argument(
        "-f", "--file",
        help="目标文件路径",
    )
    scan_parser.add_argument(
        "-c", "--concurrency",
        type=int, default=5,
        help="并发数（默认 5）",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float, default=5.0,
        help="HTTP 超时秒数（默认 5）",
    )
    scan_parser.add_argument(
        "--no-sensitive",
        action="store_true",
        help="跳过敏感路径检测（更快）",
    )
    scan_parser.add_argument(
        "-o", "--output",
        default="scan_results",
        help="报告输出目录（默认 scan_results）",
    )

    # ── discover 命令 ────────────────────────────
    discover_parser = sub.add_parser("discover", help="公司名 → 域名发现")
    discover_parser.add_argument("name", help="公司名称 或 --file 指定文件")
    discover_parser.add_argument(
        "-f", "--file",
        help="公司名单文件（每行一个公司名）",
    )
    discover_parser.add_argument(
        "-o", "--output",
        default="data/targets_discovered.txt",
        help="输出域名列表（默认 data/targets_discovered.txt）",
    )
    discover_parser.add_argument(
        "--search",
        action="store_true",
        help="启用搜索引擎辅助（较慢）",
    )

    # ── check 命令 ────────────────────────────────
    check_parser = sub.add_parser("check", help="检测目标是否存活")
    check_parser.add_argument("target", help="目标文件")
    # ── subdomain 命令 ─────────────────────────
    subdomain_parser = sub.add_parser("subdomain", help="子域名收集（crt.sh + DNS爆破）")
    subdomain_parser.add_argument("domain", help="目标域名")
    subdomain_parser.add_argument("--no-crtsh", action="store_true", help="跳过 crt.sh")
    subdomain_parser.add_argument("--no-brute", action="store_true", help="跳过 DNS 爆破")
    subdomain_parser.add_argument("--no-alive", action="store_true", help="跳过存活验证")
    subdomain_parser.add_argument("-o", "--output", help="输出文件（URL列表格式）")

    # ── monitor 命令 ───────────────────────────
    monitor_parser = sub.add_parser("monitor", help="资产监控平台（观星）")
    mon_subs = monitor_parser.add_subparsers(dest="mon_action")
    mon_subs.add_parser("serve", help="启动 Web 面板")
    mon_import = mon_subs.add_parser("import", help="导入扫描结果")
    mon_import.add_argument("path", help="扫描汇总 JSON 文件")
    mon_subs.add_parser("stats", help="查看统计")

    # ── verify 命令 ────────────────────────────
    verify_parser = sub.add_parser("verify", help="漏洞自动验证（惊蛰）")
    verify_parser.add_argument("target", help="目标URL 或 扫描汇总JSON文件")
    verify_parser.add_argument("--from-scan", action="store_true", help="从扫描汇总JSON批量验证")

    # ── report 命令 ─────────────────────────────
    report_parser = sub.add_parser("report", help="从扫描结果生成 SRC 报告")
    report_parser.add_argument("summary", nargs="?", help="扫描汇总 JSON 文件")
    report_parser.add_argument("-o", "--output", default="scan_results", help="输出目录")

    check_parser.add_argument("-c", "--concurrency", type=int, default=10)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "check":
        _cmd_check(args)
    elif args.command == "scan":
        _cmd_scan(args)
    elif args.command == "discover":
        _cmd_discover(args)
    elif args.command == "subdomain":
        _cmd_subdomain(args)
    elif args.command == "verify":
        _cmd_verify(args)
    elif args.command == "monitor":
        _cmd_monitor(args)
    elif args.command == "report":
        _cmd_report(args)


def _cmd_scan(args):
    """执行扫描"""
    # 1. 加载目标
    mgr = TargetManager()

    if args.file:
        raw_targets = mgr.load_from_file(args.file)
    elif args.target:
        if Path(args.target).exists():
            raw_targets = mgr.load_from_file(args.target)
        else:
            raw_targets = mgr.load_from_list([args.target])
    else:
        # 尝试默认路径
        for default in ["targets.txt", "data/targets.txt"]:
            if Path(default).exists():
                raw_targets = mgr.load_from_file(default)
                print(f"使用默认目标文件: {default}")
                break
        else:
            print("错误: 请指定目标文件或URL")
            print("  poxiao scan http://example.com")
            print("  poxiao scan -f targets.txt")
            return

    # 2. 去重
    targets = mgr.deduplicate(raw_targets)
    print(f"加载 {len(raw_targets)} 个目标，去重后 {len(targets)} 个")

    # 3. 存活检测 + 信息收集（一个 event loop）
    print(f"\n存活检测中...")
    t0 = time.perf_counter()

    engine = ScanEngine(
        timeout=args.timeout,
        concurrency=args.concurrency,
        enable_sensitive=not args.no_sensitive,
    )
    reporter = Reporter(output_dir=args.output)

    async def _run_all():
        # 存活检测
        checked = await mgr.check_alive(targets)
        mgr.classify(checked)
        alive_targets = [t for t in checked if t.is_alive]
        print(f"存活: {len(alive_targets)}/{len(checked)} ({time.perf_counter()-t0:.1f}s)")

        # 信息收集
        print(f"\n开始信息收集...\n")
        total = len(alive_targets)
        sem = asyncio.Semaphore(args.concurrency)

        async def _do_one(url: str, idx: int):
            async with sem:
                r = await engine.scan_one(url)
                d = r.to_dict()
                reporter.save_target_report(d)
                reporter.print_progress(idx + 1, total, d)
                return r

        tasks = [_do_one(t.url, i) for i, t in enumerate(alive_targets)]
        results = await asyncio.gather(*tasks)
        return results, alive_targets

    t_start = time.perf_counter()
    scan_results, alive_targets = asyncio.run(_run_all())
    total = len(alive_targets) if alive_targets else 0

    elapsed = time.perf_counter() - t_start

    # 5. 汇总
    print(f"\n{'=' * 50}")
    print(f"扫描完成！耗时: {elapsed:.1f}s")

    summary_path = reporter.save_summary()
    md_path = reporter.save_markdown()

    print(f"\n报告已生成:")
    print(f"  汇总 JSON: {summary_path}")
    print(f"  Markdown:  {md_path}")
    print(f"  单目标报告: {reporter.output_dir}/")

    # 生成 SRC 报告
    if alive_targets:
        src = SRCReporter()
        all_dicts = [r.to_dict() for r in scan_results]
        src_result = src.generate_batch(all_dicts, output_dir=reporter.output_dir)
        if src_result["total"] > 0:
            print(f"\n📋 SRC 报告: {src_result['total']} 个")
            print(f"  目录: {src_result['output_dir']}")
            print(f"  索引: {src_result['index']}")
            for r in src_result["reports"][:3]:
                sev_icon = "🔴" if r["severity"] in ("CRITICAL","HIGH") else "🟡"
                print(f"  {sev_icon} {r['title'][:60]}")
            if src_result["total"] > 3:
                print(f"  ... 共 {src_result['total']} 个")
        else:
            print(f"\n  (无可用于SRC提交的发现)")


def _cmd_check(args):
    """存活检测命令"""
    mgr = TargetManager()
    targets = mgr.load_from_file(args.target)
    targets = mgr.deduplicate(targets)

    print(f"检测 {len(targets)} 个目标...")
    t0 = time.perf_counter()
    targets = asyncio.run(mgr.check_alive(targets))
    elapsed = time.perf_counter() - t0

    alive = [t for t in targets if t.is_alive]
    dead = [t for t in targets if not t.is_alive]

    print(f"\n结果 ({elapsed:.1f}s):")
    print(f"  存活: {len(alive)}")
    for t in alive:
        print(f"    ✓ {t.url} [{t.status_code}]")
    print(f"  不可达: {len(dead)}")
    for t in dead:
        print(f"    ✗ {t.url}")

    # 保存存活列表
    alive_path = Path("data/targets_alive.txt")
    alive_path.parent.mkdir(parents=True, exist_ok=True)
    alive_path.write_text("\n".join(t.url for t in alive), encoding="utf-8")
    print(f"\n存活列表已保存: {alive_path}")


def _cmd_discover(args):
    """域名发现命令"""
    dd = DomainDiscovery(timeout=5.0, enable_search=args.search)

    try:
        # 加载公司列表
        if args.file:
            filepath = Path(args.file)
            if not filepath.exists():
                print(f"错误: 文件不存在 {args.file}")
                return
            names = [l.strip() for l in filepath.read_text(encoding="utf-8").splitlines()
                    if l.strip() and not l.strip().startswith("#")]
        elif args.name:
            if Path(args.name).exists():
                names = [l.strip() for l in Path(args.name).read_text(encoding="utf-8").splitlines()
                        if l.strip() and not l.strip().startswith("#")]
            else:
                names = [args.name]
        else:
            print("错误: 请指定公司名或 --file")
            return

        print(f"发现 {len(names)} 家公司的域名...\n")

        found = []
        for i, name in enumerate(names):
            best = dd.discover_best(name)
            bar = "█" * (i + 1) + "░" * (len(names) - i - 1)
            if best:
                found.append(best)
                print(f"  [{bar}] {name} → {best}")
            else:
                print(f"  [{bar}] {name} → 未找到")

        # 保存
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("\n".join(found), encoding="utf-8")
        print(f"\n找到 {len(found)}/{len(names)} 个域名")
        print(f"已保存: {output}")

    finally:
        dd.close()


def _cmd_subdomain(args):
    """子域名收集"""
    import asyncio
    sy = ShuangYue(timeout=5.0)

    print(f"收集 {args.domain} 的子域名...")
    print(f"  crt.sh: {'启用' if not args.no_crtsh else '跳过'}")
    print(f"  DNS爆破: {'启用' if not args.no_brute else '跳过'}")
    print(f"  存活验证: {'启用' if not args.no_alive else '跳过'}")
    print()

    subs = asyncio.run(sy.collect(
        domain=args.domain,
        use_crtsh=not args.no_crtsh,
        use_brute=not args.no_brute,
        check_alive=not args.no_alive,
    ))

    alive = [s for s in subs if s.alive]
    dead = [s for s in subs if not s.alive]

    print(f"共收集 {len(subs)} 个子域名")
    print(f"  存活: {len(alive)}")
    print(f"  其他: {len(dead)}")
    print()

    for s in alive:
        print(f"  ✅ {s.domain:45s} [{s.status_code}] {s.title[:40]} ({s.source})")
    for s in dead:
        print(f"  ❌ {s.domain:45s} ({s.source})")

    # 保存
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        urls = [s.to_url() for s in subs if s.alive]
        out.write_text("\n".join(urls), encoding="utf-8")
        print(f"\n存活URL已保存: {out}")


def _cmd_monitor(args):
    """观星 资产监控"""
    if args.mon_action == "serve":
        start_server(port=5099)
    elif args.mon_action == "import":
        print(f"导入: {args.path}")
        import_from_summary(args.path)
        stats = get_stats()
        print(f"  目标: {stats['total']} | 存活: {stats['alive']} | 有发现: {stats['with_findings']}")
        print(f"  启动面板: poxiao monitor serve")
    elif args.mon_action == "stats":
        stats = get_stats()
        print(f"总目标: {stats['total']}")
        print(f"存活:   {stats['alive']}")
        print(f"有发现: {stats['with_findings']}")
        print(f"技术栈: {dict(sorted(stats['tech_distribution'].items(), key=lambda x:-x[1])[:8])}")
    else:
        print("用法: poxiao monitor {serve|import|stats}")


def _cmd_verify(args):
    """漏洞验证"""
    import asyncio
    jz = JingZhe(timeout=8.0)

    if args.from_scan:
        print(f"从扫描汇总验证: {args.target}")
        findings = asyncio.run(jz.verify_from_scan(args.target))
    else:
        print(f"验证目标: {args.target}")
        findings = asyncio.run(jz.verify(args.target))

    exploitable = [f for f in findings if f.exploitable]
    suspicious = [f for f in findings if not f.exploitable]

    score = jz.score(findings)

    print(f"\n验证结果: {len(findings)} 个发现")
    print(f"  可利用: {len(exploitable)}")
    print(f"  可疑: {len(suspicious)}")
    print(f"  风险评分: {score['summary']}")
    print()

    for f in exploitable:
        print(f"  🔥 [{f.confidence}] {f.url}")
        print(f"      类型: {f.finding_type} | {f.evidence}")
        print(f"      详情: {f.detail}")
        print()

    for f in suspicious:
        print(f"  ⚠️ [{f.confidence}] {f.url} — {f.evidence}")


def _cmd_report(args):
    """SRC 报告生成"""
    src = SRCReporter()

    # 找最新的 summary JSON
    import glob
    summary_path = args.summary
    if not summary_path:
        candidates = sorted(glob.glob(f"scan_results/summary_*.json"), reverse=True)
        if not candidates:
            print("未找到扫描汇总文件。请先运行 poxiao scan ...")
            return
        summary_path = candidates[0]
        print(f"使用最近汇总: {summary_path}")

    if not Path(summary_path).exists():
        print(f"文件不存在: {summary_path}")
        return

    data = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    targets = data.get("targets", [])

    result = src.generate_batch(targets, output_dir=args.output)
    print(f"\n生成 {result['total']} 个 SRC 报告")
    print(f"目录: {result['output_dir']}")
    print(f"索引: {result['index']}")
    for r in result["reports"]:
        sev_icon = "🔴" if r["severity"] in ("CRITICAL", "HIGH") else "🟡"
        print(f"  {sev_icon} [{r['severity']}] {r['title'][:60]}")


if __name__ == "__main__":
    main()

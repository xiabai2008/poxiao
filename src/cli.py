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


if __name__ == "__main__":
    main()

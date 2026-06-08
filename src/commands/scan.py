"""扫描命令"""

import asyncio
import time
from pathlib import Path

from src.scanner.engine import ScanEngine
from src.reporter.reporter import Reporter
from src.reporter.src_reporter import SRCReporter
from src.target.manager import TargetManager
from src.utils.output import Out, C


def cmd_scan(args):
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
                Out.info(f"使用默认目标文件: {default}")
                break
        else:
            Out.error("请指定目标文件或URL")
            Out._print("    poxiao scan http://example.com")
            Out._print("    poxiao scan -f targets.txt")
            return

    # 2. 去重
    targets = mgr.deduplicate(raw_targets)
    Out.info(f"加载 {len(raw_targets)} 个目标，去重后 {len(targets)} 个")

    # 3. 存活检测 + 信息收集（一个 event loop）
    Out.info("存活检测中...")
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
        Out.success(f"存活: {len(alive_targets)}/{len(checked)} ({time.perf_counter()-t0:.1f}s)")

        # 信息收集
        Out.info("开始信息收集...")
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
    Out.blank()
    Out.section("扫描完成", "✓")
    Out.success(f"耗时: {Out.elapsed(elapsed)}")
    Out.info(f"目标: {total} 个存活")

    summary_path = reporter.save_summary()
    md_path = reporter.save_markdown()

    Out.blank()
    Out.info(f"汇总 JSON: {summary_path}")
    Out.info(f"Markdown:  {md_path}")
    Out.info(f"单目标报告: {reporter.output_dir}/")

    # ── Full depth: 调用 RayScan 做 SQLi+XSS 深度扫描 ──
    import os
    if args.depth == "full" and alive_targets:
        Out.blank()
        Out.section("RayScan 深度检测", "🔬")
        try:
            import sys as _sys

            # RayScan 路径: 环境变量 > 配置 > 默认路径
            raydir = os.environ.get(
                "POXIAO_RAYSCAN_PATH",
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "RayScan")
            )
            if not os.path.isdir(raydir):
                Out.warning("RayScan 未找到，跳过深度检测")
                Out.info("设置环境变量 POXIAO_RAYSCAN_PATH 或将 RayScan 放在同级目录")
                return

            if raydir not in _sys.path:
                _sys.path.insert(0, raydir)

            from wvs.config import ConfigManager as RayConfig
            from wvs.core.session import HTTPPool
            from wvs.core.scanner import WAVScanner
            from wvs.models import ScanTarget

            for t in alive_targets[:5]:  # 最多 5 个目标（深度扫描较慢）
                Out.info(f"深度扫描: {t.url}")
                try:
                    rc = RayConfig()
                    rc.set("verify_ssl", False)
                    rc.set("crawl_depth", 2)
                    rc.set("crawl_max_urls", 200)
                    rc.set("threads", 3)
                    session = HTTPPool(rc)
                    scanner = WAVScanner(rc, session)
                    scanner.load_all_modules()

                    target = ScanTarget(url=t.url)

                    async def _scan_once():
                        return await scanner.scan(target)

                    result = asyncio.run(_scan_once())

                    deep_findings = []
                    for v in result.vulnerabilities:
                        deep_findings.append({
                            "type": v.type.value,
                            "severity": v.severity.value,
                            "url": v.url,
                            "param": v.parameter,
                            "evidence": (v.evidence or "")[:200],
                            "module": "rayscan",
                        })

                    if deep_findings:
                        Out.success(f"RayScan 发现 {len(deep_findings)} 个漏洞:")
                        for f in deep_findings:
                            icon = Out.severity_icon(f["severity"])
                            Out._print(f"      {icon} [{f['severity']}] {f['type']} on {f['url']}")
                    else:
                        Out.info("RayScan 未发现漏洞")

                    # 保存深度扫描结果
                    safe_name = t.url.split("//")[-1].rstrip("/").replace("/", "_")
                    outdir = Path(reporter.output_dir) / "rayscan"
                    outdir.mkdir(exist_ok=True)
                    (outdir / f"{safe_name}.json").write_text(
                        __import__("json").dumps(deep_findings, indent=2, ensure_ascii=False),
                        encoding="utf-8",
                    )
                    async def _close_session():
                        await session.close()
                    asyncio.run(_close_session())
                except Exception as e:
                    Out.warning(f"RayScan 深度扫描失败: {e}")

            Out.info(f"RayScan 报告: {reporter.output_dir}/rayscan/")
        except ImportError as e:
            Out.warning(f"RayScan 未安装: {e}")
            Out.info("请确保 RayScan 在 PYTHONPATH 中或已安装")
        except Exception as e:
            Out.warning(f"RayScan 深度扫描异常: {e}")

    # 自动导入到观星（如果数据库已初始化）
    try:
        from src.monitor.db import import_from_summary, get_stats
        import_from_summary(summary_path)
        stats = get_stats()
        Out.info(f"观星已同步: {stats['total']} 目标 | 启动面板: poxiao monitor serve")
    except Exception:
        pass

    # 生成 SRC 报告
    if alive_targets:
        src = SRCReporter()
        all_dicts = [r.to_dict() for r in scan_results]
        src_result = src.generate_batch(all_dicts, output_dir=reporter.output_dir)
        if src_result["total"] > 0:
            Out.blank()
            Out.section(f"SRC 报告 ({src_result['total']} 个)", "📋")
            Out.info(f"目录: {src_result['output_dir']}")
            Out.info(f"索引: {src_result['index']}")
            for r in src_result["reports"][:3]:
                sev_icon = Out.severity_icon(r["severity"])
                Out._print(f"      {sev_icon} {r['title'][:60]}")
            if src_result["total"] > 3:
                Out.dim(f"      ... 共 {src_result['total']} 个")
        else:
            Out.dim("(无可用于SRC提交的发现)")

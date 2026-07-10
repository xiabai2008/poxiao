"""观星资产监控命令"""

from pathlib import Path

from src.guanxing import import_from_summary, start_server, get_stats
from src.guanxing.db import export_data
from src.utils.output import Out, C


def cmd_monitor(args):
    """观星 资产监控"""
    if args.mon_action == "serve":
        start_server(port=5099)
    elif args.mon_action == "import":
        Out.info(f"导入: {args.path}")
        import_from_summary(args.path)
        stats = get_stats()
        Out.success(f"目标: {stats['total']} | 存活: {stats['alive']} | 有发现: {stats['with_findings']}")
        Out.info(f"启动面板: poxiao monitor serve")
    elif args.mon_action == "stats":
        stats = get_stats()
        Out.section("资产统计", "📊")
        Out.kv_row("总目标", str(stats['total']))
        Out.kv_row("存活", str(stats['alive']))
        Out.kv_row("有发现", str(stats['with_findings']))
        if stats.get('tech_distribution'):
            tech_sorted = dict(sorted(stats['tech_distribution'].items(), key=lambda x: -x[1])[:8])
            Out.kv_row("技术栈", str(tech_sorted))
    elif args.mon_action == "export":
        content, mimetype, filename = export_data(args.format)
        out = args.out or f"scan_results/{filename}"
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(content, encoding="utf-8")
        Out.success(f"已导出: {out} ({len(content)} 字节, {mimetype})")
    else:
        Out.info("用法: poxiao monitor {serve|import|stats}")

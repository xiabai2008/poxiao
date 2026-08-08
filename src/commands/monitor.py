"""观星资产监控命令"""

from pathlib import Path

from src.config import get_config
from src.guanxing import import_from_summary, start_server, get_stats
from src.guanxing.db import export_data
from src.utils.output import Out


def cmd_monitor(args):
    """观星 资产监控"""
    if args.mon_action == "serve":
        # 优先级: CLI 参数 > 配置文件 (monitor.host/port) > 默认值
        cfg = get_config().get("monitor")
        host = getattr(args, "host", "") or cfg.get("host", "127.0.0.1")
        port = getattr(args, "port", 0) or int(cfg.get("port", 5099))
        Out.info(f"启动观星面板: http://{host}:{port}")
        if cfg.get("auth"):
            Out.info("已启用认证 (monitor.auth=true)")
        start_server(host=host, port=port)
    elif args.mon_action == "import":
        Out.info(f"导入: {args.path}")
        import_from_summary(args.path)
        stats = get_stats()
        Out.success(f"目标: {stats['total']} | 存活: {stats['alive']} | 有发现: {stats['with_findings']}")
        Out.info("启动面板: poxiao monitor serve")
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

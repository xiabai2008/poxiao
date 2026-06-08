"""SRC 报告生成命令"""

import json
from pathlib import Path

from src.reporter.src_reporter import SRCReporter
from src.utils.output import Out, C


def cmd_report(args):
    """SRC 报告生成"""
    src = SRCReporter()

    # 找最新的 summary JSON
    import glob
    summary_path = args.summary
    if not summary_path:
        candidates = sorted(glob.glob(f"scan_results/summary_*.json"), reverse=True)
        if not candidates:
            Out.error("未找到扫描汇总文件。请先运行 poxiao scan ...")
            return
        summary_path = candidates[0]
        Out.info(f"使用最近汇总: {summary_path}")

    if not Path(summary_path).exists():
        Out.error(f"文件不存在: {summary_path}")
        return

    data = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    targets = data.get("targets", [])

    result = src.generate_batch(targets, output_dir=args.output)
    Out.blank()
    Out.section(f"SRC 报告 ({result['total']} 个)", "📋")
    Out.info(f"目录: {result['output_dir']}")
    Out.info(f"索引: {result['index']}")
    for r in result["reports"]:
        sev_icon = Out.severity_icon(r["severity"])
        Out._print(f"      {sev_icon} [{r['severity']}] {r['title'][:60]}")

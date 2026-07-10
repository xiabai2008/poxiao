"""SRC 报告生成命令"""

import glob
import json
from datetime import datetime
from pathlib import Path

from src.dawn.src_reporter import SRCReporter
from src.utils.html_report import render_html_report
from src.utils.output import Out, C


def cmd_report(args):
    """SRC 报告生成"""
    src = SRCReporter()

    # 找最新的 summary JSON（支持环境变量指定输出目录）
    import os
    output_dir = os.environ.get("POXIAO_SCAN_OUTPUT", "scan_results")
    summary_path = args.summary
    if not summary_path:
        candidates = sorted(glob.glob(f"{output_dir}/summary_*.json"), reverse=True)
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

    # HTML 报告（P2-4 / Q5：纯标准库，不引 Jinja2）
    if getattr(args, "format", "src") == "html":
        html_doc = render_html_report(data)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"report_{ts}.html"
        out_path.write_text(html_doc, encoding="utf-8")
        Out.success(f"HTML 报告: {out_path}")
        return

    result = src.generate_batch(targets, output_dir=args.output)
    Out.blank()
    Out.section(f"SRC 报告 ({result['total']} 个)", "📋")
    Out.info(f"目录: {result['output_dir']}")
    Out.info(f"索引: {result['index']}")
    for r in result["reports"]:
        sev_icon = Out.severity_icon(r["severity"])
        Out._print(f"      {sev_icon} [{r['severity']}] {r['title'][:60]}")

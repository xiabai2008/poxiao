"""报告系统 — JSON + Markdown 渐进式输出"""

import json
from datetime import datetime
from pathlib import Path


class Reporter:
    """报告生成器 — 渐进式输出"""

    def __init__(self, output_dir: str = "scan_results"):
        """初始化报告生成器（输出目录 + 会话 ID）"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._targets: list[dict] = []

    # ── 渐进式保存（每个目标扫完立即写报告）─────

    def save_target_report(self, result: dict) -> str:
        """保存单个目标报告 → 返回文件路径"""
        self._targets.append(result)

        # 文件名：host_sessionid.json
        host = result.get("host", "unknown").replace(":", "_").replace("/", "_")
        filename = f"{host}_{self.session_id}.json"
        filepath = self.output_dir / filename

        filepath.write_text(
            json.dumps(result, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return str(filepath)

    # ── 进度输出 ─────────────────────────────────

    def print_progress(self, index: int, total: int, result: dict):
        """打印进度条"""
        url = result.get("target_url", "?")[:50]
        alive = "✓" if result.get("alive") else "✗"
        tech = "+".join(result.get("tech_tags", [])[:3])
        sens = result.get("sensitive_count", 0)
        dur = result.get("duration_sec", 0)

        bar_len = 20
        filled = int(bar_len * index / max(1, total))
        bar = "█" * filled + "░" * (bar_len - filled)

        print(
            f"  [{bar}] {index}/{total}  "
            f"{alive} {url}  "
            f"{tech}  "
            f"sensitive={sens}  "
            f"{dur:.1f}s"
        )

    # ── 汇总报告 ─────────────────────────────────

    def save_summary(self) -> str:
        """保存汇总报告 → 返回文件路径"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        alive = [t for t in self._targets if t.get("alive")]
        dead = [t for t in self._targets if not t.get("alive")]
        with_findings = [t for t in self._targets if t.get("sensitive_count", 0) > 0]

        # 统计技术栈
        tech_stats = {}
        for t in self._targets:
            for tag in t.get("tech_tags", []):
                tech_stats[tag] = tech_stats.get(tag, 0) + 1

        summary = {
            "scan_time": now,
            "session_id": self.session_id,
            "total": len(self._targets),
            "alive": len(alive),
            "dead": len(dead),
            "with_findings": len(with_findings),
            "tech_stats": dict(
                sorted(tech_stats.items(), key=lambda x: -x[1])
            ),
            "targets": self._targets,
        }

        filepath = self.output_dir / f"summary_{self.session_id}.json"
        filepath.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return str(filepath)

    # ── Markdown 报告 ────────────────────────────

    def save_markdown(self) -> str:
        """生成 Markdown 汇总报告"""
        alive = [t for t in self._targets if t.get("alive")]
        dead = [t for t in self._targets if not t.get("alive")]
        with_findings = [t for t in self._targets if t.get("sensitive_count", 0) > 0]

        lines = []
        lines.append("# 破晓扫描报告")
        lines.append(f"**扫描时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Session:** `{self.session_id}`")
        lines.append("")
        lines.append("## 概要")
        lines.append(f"- 总目标: {len(self._targets)}")
        lines.append(f"- 存活: {len(alive)}")
        lines.append(f"- 不可达: {len(dead)}")
        lines.append(f"- 有发现: {len(with_findings)}")
        lines.append("")

        # 有发现的目标
        if with_findings:
            lines.append("## 有敏感发现的目标")
            lines.append("")
            lines.append("| 目标 | 状态 | 技术栈 | 敏感路径 |")
            lines.append("|------|------|--------|----------|")
            for t in with_findings:
                tech = "+".join(t.get("tech_tags", [])[:3]) or "-"
                paths = t.get("sensitive_count", 0)
                lines.append(
                    f"| {t['target_url']} | {t.get('status_code','?')} | {tech} | {paths} |"
                )
            lines.append("")

            # 列出敏感路径详情
            lines.append("## 敏感路径详情")
            for t in with_findings:
                paths = t.get("sensitive_paths", [])
                if paths:
                    lines.append(f"### {t['target_url']}")
                    lines.append(f"技术栈: {' '.join(t.get('tech_tags',[]))}")
                    lines.append("")
                    for p in paths:
                        lines.append(f"- `{p['url']}` [{p['status']}] ({p['category']})")
                    lines.append("")

        # 所有目标表
        lines.append("## 全部目标")
        lines.append("")
        lines.append("| # | 目标 | 存活 | 状态码 | 技术栈 | 敏感路径 | 耗时 |")
        lines.append("|---|------|------|--------|--------|----------|------|")
        for i, t in enumerate(self._targets, 1):
            alive_mark = "✓" if t.get("alive") else "✗"
            tech = "+".join(t.get("tech_tags", [])[:3]) or "-"
            sens = t.get("sensitive_count", 0)
            dur = f"{t.get('duration_sec',0):.1f}s"
            url = t["target_url"][:50]
            lines.append(
                f"| {i} | {url} | {alive_mark} | {t.get('status_code','?')} | {tech} | {sens} | {dur} |"
            )

        filepath = self.output_dir / f"summary_{self.session_id}.md"
        filepath.write_text("\n".join(lines), encoding="utf-8")
        return str(filepath)

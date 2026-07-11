"""
破晓 · 输出格式化
==================
统一的输出样式：进度条、表格、颜色、状态图标

用法:
  from src.utils.output import Out
  Out.title("扫描目标")
  Out.table(headers, rows)
  Out.progress(current, total)
  Out.success("发现 3 个漏洞")
  Out.warning("跳过 CDN 目标")
  Out.error("连接超时")
  Out.info("正在收集 DNS 记录...")
"""

import sys
import time
from typing import List, Dict, Any, Optional

from src.i18n import _


class C:
    """ANSI 颜色"""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"


class Out:
    """统一输出格式化"""

    @staticmethod
    def _print(text: str):
        """安全打印"""
        try:
            print(text)
        except UnicodeEncodeError:
            print(text.encode("utf-8", errors="replace").decode("utf-8", errors="replace"))

    # ── 标题 ──────────────────────────────────────────

    @staticmethod
    def title(text: str, icon: str = ""):
        """打印标题"""
        prefix = f"{icon} " if icon else ""
        Out._print(f"\n{C.BOLD}{C.CYAN}{prefix}{_(text)}{C.RESET}")
        Out._print(f"{C.DIM}{'─' * 60}{C.RESET}")

    @staticmethod
    def subtitle(text: str):
        """打印副标题"""
        Out._print(f"\n  {C.BOLD}{_(text)}{C.RESET}")

    @staticmethod
    def section(text: str, icon: str = ""):
        """打印区块标题"""
        prefix = f"{icon} " if icon else ""
        Out._print(f"\n  {C.CYAN}{C.BOLD}{prefix}{_(text)}{C.RESET}")
        Out._print(f"  {C.DIM}{'─' * 50}{C.RESET}")

    # ── 状态消息 ──────────────────────────────────────

    @staticmethod
    def success(text: str):
        """成功消息"""
        Out._print(f"  {C.GREEN}[+]{C.RESET} {_(text)}")

    @staticmethod
    def error(text: str):
        """错误消息"""
        Out._print(f"  {C.RED}[!]{C.RESET} {_(text)}")

    @staticmethod
    def warning(text: str):
        """警告消息"""
        Out._print(f"  {C.YELLOW}[*]{C.RESET} {_(text)}")

    @staticmethod
    def info(text: str):
        """信息消息"""
        Out._print(f"  {C.BLUE}[i]{C.RESET} {_(text)}")

    @staticmethod
    def dim(text: str):
        """暗淡消息"""
        Out._print(f"  {C.DIM}{_(text)}{C.RESET}")

    # ── 关键值对 ──────────────────────────────────────

    @staticmethod
    def kv(key: str, value: str, indent: int = 2):
        """打印 key: value 对"""
        spaces = " " * indent
        Out._print(f"{spaces}{C.DIM}{_(key)}:{C.RESET} {value}")

    @staticmethod
    def kv_row(key: str, value: str, key_width: int = 16, indent: int = 4):
        """打印对齐的 key: value 行"""
        spaces = " " * indent
        padded_key = _(key).ljust(key_width)
        Out._print(f"{spaces}{C.DIM}{padded_key}{C.RESET} {value}")

    # ── 进度条 ────────────────────────────────────────

    @staticmethod
    def progress(current: int, total: int, prefix: str = "", suffix: str = "",
                 width: int = 30, fill: str = "█", empty: str = "░"):
        """打印进度条"""
        if total == 0:
            return
        percent = min(100, int(current / total * 100))
        filled = int(width * current / total)
        bar = fill * filled + empty * (width - filled)

        # 颜色
        if percent < 30:
            color = C.RED
        elif percent < 70:
            color = C.YELLOW
        else:
            color = C.GREEN

        prefix_str = f"{prefix} " if prefix else ""
        suffix_str = f" {suffix}" if suffix else ""

        # 清除当前行并打印
        sys.stdout.write(f"\r  {prefix_str}{color}{bar}{C.RESET} {percent}%{suffix_str}")
        sys.stdout.flush()

        if current >= total:
            sys.stdout.write("\n")
            sys.stdout.flush()

    @staticmethod
    def progress_done(prefix: str = "", count: int = 0, elapsed: float = 0):
        """进度完成"""
        elapsed_str = f" ({elapsed:.1f}s)" if elapsed > 0 else ""
        count_str = f" {count} 个" if count > 0 else ""
        Out._print(f"  {C.GREEN}✓{C.RESET} {prefix}{count_str}{elapsed_str}")

    # ── 表格 ──────────────────────────────────────────

    @staticmethod
    def table(headers: List[str], rows: List[List[str]], 
              colors: List[str] = None, max_widths: List[int] = None):
        """打印表格"""
        if not rows:
            return

        # 计算列宽
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))

        # 限制最大宽度
        if max_widths:
            for i, mw in enumerate(max_widths):
                if i < len(col_widths) and mw:
                    col_widths[i] = min(col_widths[i], mw)

        # 打印表头
        header_line = "  "
        for i, h in enumerate(headers):
            w = col_widths[i] if i < len(col_widths) else len(h)
            header_line += f"{C.BOLD}{h.ljust(w)}{C.RESET}  "
        Out._print(header_line)

        # 打印分隔线
        sep = "  " + "  ".join("─" * w for w in col_widths)
        Out._print(f"{C.DIM}{sep}{C.RESET}")

        # 打印数据行
        for row in rows:
            line = "  "
            for i, cell in enumerate(row):
                w = col_widths[i] if i < len(col_widths) else len(str(cell))
                cell_str = str(cell)
                # 截断过长内容
                if len(cell_str) > w:
                    cell_str = cell_str[:w-2] + ".."
                # 应用颜色
                if colors and i < len(colors):
                    line += f"{colors[i]}{cell_str.ljust(w)}{C.RESET}  "
                else:
                    line += f"{cell_str.ljust(w)}  "
            Out._print(line)

    # ── 框 ────────────────────────────────────────────

    @staticmethod
    def box(title: str, lines: List[str], color: str = C.CYAN):
        """打印信息框"""
        # 计算最大宽度
        max_w = max(len(title), max(len(l) for l in lines) if lines else 0) + 4
        max_w = min(max_w, 60)

        Out._print(f"\n  {color}┌{'─' * max_w}┐{C.RESET}")
        Out._print(f"  {color}│{C.RESET} {C.BOLD}{title.center(max_w - 2)}{C.RESET} {color}│{C.RESET}")
        Out._print(f"  {color}├{'─' * max_w}┤{C.RESET}")
        for line in lines:
            padded = line.ljust(max_w - 2)
            Out._print(f"  {color}│{C.RESET} {padded} {color}│{C.RESET}")
        Out._print(f"  {color}└{'─' * max_w}┘{C.RESET}")

    # ── 统计摘要 ──────────────────────────────────────

    @staticmethod
    def summary(items: Dict[str, Any], title: str = "扫描摘要"):
        """打印统计摘要"""
        Out.section(_(title))
        for key, value in items.items():
            if isinstance(value, dict):
                Out._print(f"    {C.DIM}{_(key)}:{C.RESET}")
                for k, v in value.items():
                    Out._print(f"      {k}: {v}")
            elif isinstance(value, list):
                Out._print(f"    {C.DIM}{_(key)}:{C.RESET} {', '.join(str(v) for v in value[:5])}")
            else:
                Out._print(f"    {C.DIM}{_(key)}:{C.RESET} {value}")

    # ── 分隔线 ────────────────────────────────────────

    @staticmethod
    def separator(char: str = "─", width: int = 60):
        """打印分隔线"""
        Out._print(f"  {C.DIM}{char * width}{C.RESET}")

    @staticmethod
    def blank():
        """空行"""
        Out._print("")

    # ── 严重级别标签 ──────────────────────────────────

    @staticmethod
    def severity_tag(severity: str) -> str:
        """返回带颜色的严重级别标签"""
        tags = {
            "critical": f"{C.BG_RED}{C.WHITE} CRITICAL {C.RESET}",
            "high": f"{C.RED}[HIGH]{C.RESET}",
            "medium": f"{C.YELLOW}[MEDIUM]{C.RESET}",
            "low": f"{C.BLUE}[LOW]{C.RESET}",
            "info": f"{C.DIM}[INFO]{C.RESET}",
        }
        return tags.get(severity.lower(), f"[{severity.upper()}]")

    @staticmethod
    def severity_icon(severity: str) -> str:
        """返回严重级别图标"""
        icons = {
            "critical": f"{C.RED}●{C.RESET}",
            "high": f"{C.RED}●{C.RESET}",
            "medium": f"{C.YELLOW}●{C.RESET}",
            "low": f"{C.BLUE}●{C.RESET}",
            "info": f"{C.DIM}●{C.RESET}",
        }
        return icons.get(severity.lower(), "●")

    # ── 时间 ──────────────────────────────────────────

    @staticmethod
    def elapsed(seconds: float) -> str:
        """格式化时间"""
        if seconds < 1:
            return f"{seconds*1000:.0f}ms"
        elif seconds < 60:
            return f"{seconds:.1f}s"
        else:
            minutes = int(seconds // 60)
            secs = seconds % 60
            return f"{minutes}m {secs:.0f}s"

    # ── 数量 ──────────────────────────────────────────

    @staticmethod
    def count_label(count: int, singular: str = "个", plural: str = "个") -> str:
        """返回数量标签"""
        if count == 0:
            return f"无{plural}"
        elif count == 1:
            return f"1 {singular}"
        else:
            return f"{count} {plural}"

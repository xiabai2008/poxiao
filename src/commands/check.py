"""存活检测命令"""

import asyncio
import time
from pathlib import Path

from src.target.manager import TargetManager
from src.utils.output import Out, C


def cmd_check(args):
    """存活检测命令"""
    mgr = TargetManager()
    targets = mgr.load_from_file(args.target)
    targets = mgr.deduplicate(targets)

    Out.info(f"检测 {len(targets)} 个目标...")
    t0 = time.perf_counter()
    targets = asyncio.run(mgr.check_alive(targets))
    elapsed = time.perf_counter() - t0

    alive = [t for t in targets if t.is_alive]
    dead = [t for t in targets if not t.is_alive]

    Out.blank()
    Out.section(f"结果 ({Out.elapsed(elapsed)})", "📊")
    Out.success(f"存活: {len(alive)}")
    for t in alive:
        Out._print(f"      {C.GREEN}+{C.RESET} {t.url} [{t.status_code}]")
    if dead:
        Out.error(f"不可达: {len(dead)}")
        for t in dead:
            Out._print(f"      {C.RED}-{C.RESET} {t.url}")

    # 保存存活列表
    alive_path = Path("data/targets_alive.txt")
    alive_path.parent.mkdir(parents=True, exist_ok=True)
    alive_path.write_text("\n".join(t.url for t in alive), encoding="utf-8")
    Out.success(f"已保存: {alive_path}")

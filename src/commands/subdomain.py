"""子域名收集命令"""

import asyncio
from collections import defaultdict

from src.frostmoon import ShuangYue
from src.utils.output import Out, C
from src.utils.scope import scope_enforced, check_scope


def cmd_subdomain(args):
    """子域名收集"""
    # Phase 3 反滥用红线：越界阻断
    if scope_enforced() and not check_scope(args.domain, reason="subdomain"):
        Out.error(f"目标不在授权范围内，已阻断: {args.domain}")
        Out.info("查看范围: poxiao scope list | 添加: poxiao scope add <target>")
        return

    sy = ShuangYue(timeout=5.0)

    # 配置框
    config_lines = [
        f"目标: {args.domain}",
        f"crt.sh: {'启用' if not args.no_crtsh else '跳过'}",
        f"DNS爆破: {'启用' if not args.no_brute else '跳过'}",
        f"存活验证: {'启用' if not args.no_alive else '跳过'}",
    ]
    Out.box("子域名收集", config_lines, C.CYAN)

    subs = asyncio.run(sy.collect(
        domain=args.domain,
        use_crtsh=not args.no_crtsh,
        use_brute=not args.no_brute,
        check_alive=not args.no_alive,
    ))

    alive = [s for s in subs if s.alive]

    # 摘要
    Out.blank()
    Out.section("收集结果", "📊")
    Out.success(f"共 {len(subs)} 个子域名 | 存活 {len(alive)}")

    # 按类别分组显示
    by_cat = defaultdict(list)
    for s in alive:
        by_cat[s.category].append(s)

    for cat in ["admin", "dev", "api", "portal", "mail", "biz", "internal"]:
        items = by_cat.get(cat, [])
        if items:
            Out.blank()
            Out._print(f"    {C.BOLD}[{cat}]{C.RESET} ({len(items)})")
            for s in items[:6]:
                icon = f"{C.GREEN}●{C.RESET}" if s.status_code == 200 else f"{C.YELLOW}●{C.RESET}"
                Out._print(f"      {icon} {s.domain:40s} [{s.status_code}] {s.title[:35]}")
            if len(items) > 6:
                Out.dim(f"      ... 共 {len(items)} 个")

    # 保存
    if args.output:
        sy.to_target_file(subs, args.output)
        Out.success(f"已保存: {args.output}")

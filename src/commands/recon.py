"""被动信息收集命令"""

import asyncio

from src.vernalequinox import ReconEngine
from src.utils.output import Out, C
from src.utils.scope import scope_enforced, check_scope


def cmd_recon(args):
    """被动信息收集"""
    # Phase 3 反滥用红线：越界阻断
    if scope_enforced() and not check_scope(args.domain, reason="recon"):
        Out.error(f"目标不在授权范围内，已阻断: {args.domain}")
        Out.info("查看范围: poxiao scope list | 添加: poxiao scope add <target>")
        return

    # 设置环境变量
    import os
    if args.shodan_key:
        os.environ["SHODAN_API_KEY"] = args.shodan_key
    if args.fofa_key:
        os.environ["FOFA_KEY"] = args.fofa_key
    if args.fofa_email:
        os.environ["FOFA_EMAIL"] = args.fofa_email
    if args.censys_id:
        os.environ["CENSYS_API_ID"] = args.censys_id
    if args.censys_secret:
        os.environ["CENSYS_API_SECRET"] = args.censys_secret
    if args.github_token:
        os.environ["GITHUB_TOKEN"] = args.github_token
    if args.quake_token:
        os.environ["QUAKE_TOKEN"] = args.quake_token
    if args.hunter_key:
        os.environ["HUNTER_API_KEY"] = args.hunter_key
    if args.hunter_email:
        os.environ["HUNTER_EMAIL"] = args.hunter_email

    engine = ReconEngine(
        timeout=args.timeout,
        shodan_key=args.shodan_key,
        fofa_key=args.fofa_key,
        fofa_email=args.fofa_email,
        censys_id=args.censys_id,
        censys_secret=args.censys_secret,
        github_token=args.github_token,
        quake_token=args.quake_token,
        hunter_key=args.hunter_key,
        hunter_email=args.hunter_email,
    )

    # 配置框
    config_lines = [
        f"目标: {args.domain}",
        f"模式: {'快速' if args.quick else '全量'}",
    ]
    Out.box("被动信息收集", config_lines, C.GREEN)

    if args.quick:
        report = asyncio.run(engine.quick_recon(args.domain))
    else:
        report = asyncio.run(engine.full_recon(args.domain))

    # 打印报告
    ReconEngine.print_report(report)

    # 保存报告
    if args.output:
        save_path = engine.save_report(report, args.output)
    else:
        save_path = engine.save_report(report)
    Out.success(f"报告已保存: {save_path}")

    # 自动导入到观星
    try:
        from src.guanxing.db import init_db
        init_db()
    except Exception:
        pass

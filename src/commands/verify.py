"""漏洞验证命令"""

import asyncio

from src.jingzhe import JingZhe
from src.utils.output import Out, C
from src.utils.scope import scope_enforced, check_scope


def cmd_verify(args):
    """漏洞验证"""
    # Phase 3 反滥用红线：单目标越界阻断
    if scope_enforced() and not check_scope(args.target, reason="verify"):
        Out.error(f"目标不在授权范围内，已阻断: {args.target}")
        Out.info("查看范围: poxiao scope list | 添加: poxiao scope add <target>")
        return

    jz = JingZhe(timeout=8.0)

    # 配置框
    config_lines = [f"目标: {args.target}"]
    Out.box("漏洞验证", config_lines, C.YELLOW)

    if args.from_scan:
        findings = asyncio.run(jz.verify_from_scan(args.target))
    else:
        findings = asyncio.run(jz.verify(args.target))

    exploitable = [f for f in findings if f.exploitable]
    suspicious = [f for f in findings if not f.exploitable]

    score = jz.score(findings)

    Out.blank()
    Out.section("验证结果", "📊")
    Out.success(f"发现 {len(findings)} 个")
    if exploitable:
        Out.error(f"可利用: {len(exploitable)}")
    if suspicious:
        Out.warning(f"可疑: {len(suspicious)}")
    Out.info(f"风险评分: {score['summary']}")

    if exploitable:
        Out.blank()
        Out.section("可利用漏洞", "🔥")
        for f in exploitable:
            Out._print(f"    [{f.confidence}] {f.url}")
            Out._print(f"      类型: {f.finding_type} | {f.evidence}")
            Out._print(f"      详情: {f.detail}")
            Out.blank()

    if suspicious:
        Out.section("可疑发现", "⚠️")
        for f in suspicious:
            Out._print(f"    [{f.confidence}] {f.url} — {f.evidence}")

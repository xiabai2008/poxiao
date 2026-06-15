"""惊蛰 JingZhe — 漏洞验证器入口"""
import sys
import asyncio
from pathlib import Path
from src.jingzhe import JingZhe, VerifiedFinding
from src.utils.output import Out, C


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        Out.title("惊蛰 JingZhe — 漏洞验证器", "*")
        Out._print("")
        Out._print("用法: jingzhe <URL> [选项]")
        Out._print("       jingzhe -f <scan_results.json>")
        Out._print("")
        Out._print("选项:")
        Out._print("  -f <file>        从破晓扫描结果验证")
        Out._print("  --timeout <sec>  超时时间 (默认 8)")
        Out._print("  --score          只输出高置信度")
        Out._print("")
        Out._print("示例:")
        Out._print("  jingzhe https://example.com")
        Out._print("  jingzhe -f scan_results/target_example.com.json")
        return

    timeout = 8.0
    for i, arg in enumerate(sys.argv):
        if arg == "--timeout" and i + 1 < len(sys.argv):
            timeout = float(sys.argv[i + 1])

    jz = JingZhe(timeout=timeout)
    Out.title("惊蛰 JingZhe — 漏洞验证", "*")

    if "-f" in sys.argv:
        idx = sys.argv.index("-f")
        if idx + 1 < len(sys.argv):
            path = sys.argv[idx + 1]
            Out.info(f"从文件验证: {path}")
            findings = asyncio.run(jz.verify_from_scan(path))
        else:
            Out.error("缺少 -f 参数")
            return
    else:
        target = sys.argv[1]
        if not target.startswith("http"):
            target = f"https://{target}"
        Out.info(f"验证目标: {target}")
        findings = asyncio.run(jz.verify(target))

    Out.blank()
    Out.section(f"验证结果", "*")
    if findings:
        score_info = jz.score(findings)
        Out.success(f"发现 {len(findings)} 个漏洞 (风险评分: {score_info['total_score']})")
        for f in findings:
            icon = Out.severity_icon(f.severity)
            Out._print(f"  {icon} [{f.severity.upper()}] {f.title}")
            Out._print(f"    {C.DIM}{f.url}{C.RESET}")
            if f.evidence:
                Out._print(f"    证据: {f.evidence[:80]}")
    else:
        Out.info("未发现可验证的漏洞")


if __name__ == "__main__":
    main()

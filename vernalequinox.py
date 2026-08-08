"""春分 VernalEquinox — 被动侦察框架入口"""
import sys
import asyncio
from src.vernalequinox import ReconEngine
from src.vernalequinox.ip_info import IPCollector
from src.utils.output import Out


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        Out.title("春分 VernalEquinox — 被动侦察", "*")
        Out._print("")
        Out._print("用法: vernalequinox <域名> [选项]")
        Out._print("")
        Out._print("选项:")
        Out._print("  --quick          快速模式 (只做 DNS+WHOIS)")
        Out._print("  --scope full     完整模式 (含 Wayback+GitHub)")
        Out._print("  --discover       公司名→域名发现模式")
        Out._print("  --ip             IP 情报模式")
        Out._print("")
        Out._print("示例:")
        Out._print("  vernalequinox example.com")
        Out._print("  vernalequinox example.com --quick")
        Out._print("  vernalequinox 1.2.3.4 --ip")
        return

    target = sys.argv[1]
    quick = "--quick" in sys.argv
    ip_mode = "--ip" in sys.argv

    Out.title("春分 VernalEquinox — 被动侦察", "*")
    Out.info(f"目标: {target}")

    engine = ReconEngine()

    if ip_mode:
        # IP 情报模式：直接批量收集 IP 情报（Shodan 端口/漏洞/CDN 等）
        infos = asyncio.run(engine.ip.batch_collect([target]))
        for info in infos:
            IPCollector.print_result(info)
        return

    if quick:
        report = asyncio.run(engine.quick_recon(target))
    else:
        report = asyncio.run(engine.full_recon(target))

    engine.print_report(report)


if __name__ == "__main__":
    main()

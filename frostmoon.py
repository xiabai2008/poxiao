"""霜月 FrostMoon — 子域名收集器入口"""
import sys
import asyncio
from src.frostmoon import ShuangYue
from src.utils.output import Out, C


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        Out.title("霜月 FrostMoon — 子域名收集器", "*")
        Out._print("")
        Out._print("用法: frostmoon <域名> [选项]")
        Out._print("")
        Out._print("选项:")
        Out._print("  --brute          启用 DNS 字典爆破")
        Out._print("  --no-alive       跳过存活检测")
        Out._print("  -o <file>        输出到文件")
        Out._print("  --timeout <sec>  超时时间 (默认 5)")
        Out._print("")
        Out._print("示例:")
        Out._print("  frostmoon example.com")
        Out._print("  frostmoon example.com --brute")
        Out._print("  frostmoon example.com -o subs.txt")
        return

    domain = sys.argv[1]
    use_brute = "--brute" in sys.argv
    check_alive = "--no-alive" not in sys.argv
    timeout = 5.0
    output = ""

    for i, arg in enumerate(sys.argv):
        if arg == "--timeout" and i + 1 < len(sys.argv):
            timeout = float(sys.argv[i + 1])
        if arg == "-o" and i + 1 < len(sys.argv):
            output = sys.argv[i + 1]

    Out.title("霜月 FrostMoon — 子域名收集", "*")
    Out.info(f"目标: {domain}")
    Out.blank()

    sy = ShuangYue(timeout=timeout)
    result = asyncio.run(sy.collect(domain, use_brute=use_brute, check_alive=check_alive))
    sy.summary(result)

    if output:
        sy.to_target_file(result, output)


if __name__ == "__main__":
    main()

"""夏至 XiaZhi — 隐匿扫描引擎 + POC 模板执行入口"""
import sys
import asyncio
from src.xiazhi import POCEngine, TemplateLoader
from src.utils.output import Out


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        Out.title("夏至 XiaZhi — 隐匿扫描引擎", "*")
        Out._print("")
        Out._print("用法: xiazhi <命令> [选项]")
        Out._print("")
        Out._print("命令:")
        Out._print("  scan <target> -t <templates>   POC 扫描")
        Out._print("  list -t <templates>            列出模板")
        Out._print("  validate <template.yaml>       验证模板")
        Out._print("")
        Out._print("选项:")
        Out._print("  -t <dir>           模板目录")
        Out._print("  --stealth          启用隐匿模式")
        Out._print("  --proxies <file>   代理文件")
        Out._print("  --timeout <sec>    超时时间")
        Out._print("  --severity <s>     过滤严重度 (critical,high,medium,low,info)")
        Out._print("")
        Out._print("示例:")
        Out._print("  xiazhi scan example.com -t templates/")
        Out._print("  xiazhi scan example.com -t templates/ --stealth")
        Out._print("  xiazhi list -t templates/")
        return

    cmd = sys.argv[1]

    if cmd == "list":
        template_dir = ""
        for i, arg in enumerate(sys.argv):
            if arg == "-t" and i + 1 < len(sys.argv):
                template_dir = sys.argv[i + 1]
        loader = TemplateLoader(template_dir)
        templates = loader.load_all()
        loader.list_templates(templates)

    elif cmd == "scan":
        if len(sys.argv) < 3:
            Out.error("缺少目标参数")
            return
        target = sys.argv[2]
        template_dir = ""
        stealth = "--stealth" in sys.argv
        timeout = 10.0

        for i, arg in enumerate(sys.argv):
            if arg == "-t" and i + 1 < len(sys.argv):
                template_dir = sys.argv[i + 1]
            if arg == "--timeout" and i + 1 < len(sys.argv):
                timeout = float(sys.argv[i + 1])

        if not template_dir:
            Out.error("缺少模板目录 (-t)")
            return

        if not target.startswith("http"):
            target = f"https://{target}"

        Out.title("夏至 XiaZhi — POC 扫描", "*")
        Out.info(f"目标: {target}")
        Out.info(f"模板: {template_dir}")

        loader = TemplateLoader(template_dir)
        templates = loader.load_all()
        if not templates:
            Out.error("未找到模板")
            return

        Out.info(f"已加载 {len(templates)} 个模板")

        engine = POCEngine(timeout=timeout, stealth=stealth)
        results = asyncio.run(engine.scan_target(target, templates))
        engine.print_results(results, target)

    else:
        Out.error(f"未知命令: {cmd}")


if __name__ == "__main__":
    main()

"""观星 GuanXing — 资产监控仪表盘入口"""
import sys
from src.guanxing import start_server, get_stats, import_from_summary
from src.utils.output import Out


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        Out.title("观星 GuanXing — 资产监控", "*")
        Out._print("")
        Out._print("用法: guanxing <命令> [选项]")
        Out._print("")
        Out._print("命令:")
        Out._print("  serve [--port N]   启动 Web 仪表盘")
        Out._print("  import <path>      导入扫描结果")
        Out._print("  stats              显示统计信息")
        Out._print("")
        Out._print("示例:")
        Out._print("  guanxing serve")
        Out._print("  guanxing serve --port 8080")
        Out._print("  guanxing import scan_results/")
        return

    cmd = sys.argv[1]

    if cmd == "serve":
        port = 5099
        host = "127.0.0.1"
        for i, arg in enumerate(sys.argv):
            if arg == "--port" and i + 1 < len(sys.argv):
                port = int(sys.argv[i + 1])
            if arg == "--host" and i + 1 < len(sys.argv):
                host = sys.argv[i + 1]
        Out.title("观星 GuanXing — 资产监控", "*")
        Out.info(f"启动仪表盘: http://{host}:{port}")
        start_server(host=host, port=port)

    elif cmd == "import":
        if len(sys.argv) < 3:
            Out.error("缺少路径参数")
            return
        path = sys.argv[2]
        Out.info(f"导入: {path}")
        count = import_from_summary(path)
        Out.success(f"已导入 {count} 条记录")

    elif cmd == "stats":
        stats = get_stats()
        Out.title("观星 GuanXing — 统计", "*")
        Out.kv_row("总目标数", str(stats.get("total", 0)))
        Out.kv_row("存活", str(stats.get("alive", 0)))
        Out.kv_row("有发现", str(stats.get("with_findings", 0)))

    else:
        Out.error(f"未知命令: {cmd}")


if __name__ == "__main__":
    main()

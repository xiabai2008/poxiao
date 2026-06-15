"""破晓 CLI 入口"""

import argparse
import asyncio
import sys
import os
import time
import traceback
from pathlib import Path

# Windows UTF-8 修复
if sys.platform == "win32":
    os.system("chcp 65001 >nul 2>&1")
    os.environ["PYTHONIOENCODING"] = "utf-8"
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

from src.utils.banner import print_banner
from src.utils.output import Out
from src.utils.help import get_examples
from src.commands import CMD_MAP, BANNER_MAP


def safe_run(func, *args, **kwargs):
    """安全执行函数，捕获异常并友好提示"""
    try:
        return func(*args, **kwargs)
    except KeyboardInterrupt:
        Out.blank()
        Out.warning("用户中断")
        sys.exit(0)
    except FileNotFoundError as e:
        Out.error(f"文件不存在: {e.filename}")
        sys.exit(1)
    except PermissionError as e:
        Out.error(f"权限不足: {e}")
        sys.exit(1)
    except ConnectionError as e:
        Out.error(f"连接失败: {e}")
        Out.info("请检查网络连接或目标地址")
        sys.exit(1)
    except TimeoutError as e:
        Out.error(f"请求超时: {e}")
        Out.info("请尝试增加 --timeout 参数")
        sys.exit(1)
    except Exception as e:
        Out.error(f"执行失败: {e}")
        if os.environ.get("POXIAO_DEBUG"):
            traceback.print_exc()
        else:
            Out.dim("设置环境变量 POXIAO_DEBUG=1 查看详细错误")
        sys.exit(1)


def main():
    # 显示主 Banner (仅无参数时)
    if len(sys.argv) == 1:
        print_banner("main")
        Out.dim("用法: poxiao <command> [options]")
        Out.dim("帮助: poxiao --help 或 poxiao <command> --help")
        return

    parser = argparse.ArgumentParser(
        prog="破晓",
        description="Bug Bounty 辅助工具 — 信息收集 + 技术栈识别 + 敏感路径发现",
        epilog=get_examples("main"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    # ── scan 命令 ─────────────────────────────────
    scan_parser = sub.add_parser("scan", help="扫描目标",
        epilog=get_examples("scan"), formatter_class=argparse.RawDescriptionHelpFormatter)
    scan_parser.add_argument("target", nargs="?", help="目标文件或单个URL")
    scan_parser.add_argument("-f", "--file", help="目标文件路径")
    scan_parser.add_argument("--depth", choices=["normal", "full"], default="normal", help="扫描深度")
    scan_parser.add_argument("-c", "--concurrency", type=int, default=5, help="并发数")
    scan_parser.add_argument("--timeout", type=float, default=5.0, help="HTTP 超时秒数")
    scan_parser.add_argument("--no-sensitive", action="store_true", help="跳过敏感路径检测")
    scan_parser.add_argument("-o", "--output", default="scan_results", help="报告输出目录")

    # ── discover 命令 ────────────────────────────
    discover_parser = sub.add_parser("discover", help="公司名 → 域名发现",
        epilog=get_examples("discover"), formatter_class=argparse.RawDescriptionHelpFormatter)
    discover_parser.add_argument("name", help="公司名称")
    discover_parser.add_argument("-f", "--file", help="公司名单文件")
    discover_parser.add_argument("-o", "--output", default="data/targets_discovered.txt", help="输出文件")
    discover_parser.add_argument("--search", action="store_true", help="启用搜索引擎辅助")

    # ── check 命令 ────────────────────────────────
    check_parser = sub.add_parser("check", help="检测目标是否存活",
        epilog=get_examples("check"), formatter_class=argparse.RawDescriptionHelpFormatter)
    check_parser.add_argument("target", help="目标文件")
    check_parser.add_argument("-c", "--concurrency", type=int, default=10)

    # ── subdomain 命令 ─────────────────────────
    subdomain_parser = sub.add_parser("subdomain", help="子域名收集（crt.sh + DNS爆破）",
        epilog=get_examples("subdomain"), formatter_class=argparse.RawDescriptionHelpFormatter)
    subdomain_parser.add_argument("domain", help="目标域名")
    subdomain_parser.add_argument("--no-crtsh", action="store_true", help="跳过 crt.sh")
    subdomain_parser.add_argument("--no-brute", action="store_true", help="跳过 DNS 爆破")
    subdomain_parser.add_argument("--no-alive", action="store_true", help="跳过存活验证")
    subdomain_parser.add_argument("-o", "--output", help="输出文件")

    # ── monitor 命令 ───────────────────────────
    monitor_parser = sub.add_parser("monitor", help="资产监控平台（观星）",
        epilog=get_examples("monitor"), formatter_class=argparse.RawDescriptionHelpFormatter)
    mon_subs = monitor_parser.add_subparsers(dest="mon_action")
    mon_subs.add_parser("serve", help="启动 Web 面板")
    mon_import = mon_subs.add_parser("import", help="导入扫描结果")
    mon_import.add_argument("path", help="扫描汇总 JSON 文件")
    mon_subs.add_parser("stats", help="查看统计")

    # ── verify 命令 ────────────────────────────
    verify_parser = sub.add_parser("verify", help="漏洞自动验证（惊蛰）",
        epilog=get_examples("verify"), formatter_class=argparse.RawDescriptionHelpFormatter)
    verify_parser.add_argument("target", help="目标URL 或 扫描汇总JSON文件")
    verify_parser.add_argument("--from-scan", action="store_true", help="从扫描汇总批量验证")

    # ── recon 命令 ─────────────────────────────
    recon_parser = sub.add_parser("recon", help="被动信息收集（Whois/备案/DNS/证书/IP情报/CDN检测）",
        epilog=get_examples("recon"), formatter_class=argparse.RawDescriptionHelpFormatter)
    recon_parser.add_argument("domain", help="目标域名")
    recon_parser.add_argument("--quick", action="store_true", help="快速模式")
    recon_parser.add_argument("--shodan-key", default="", help="Shodan API Key")
    recon_parser.add_argument("--fofa-key", default="", help="FOFA API Key")
    recon_parser.add_argument("--fofa-email", default="", help="FOFA 邮箱")
    recon_parser.add_argument("--censys-id", default="", help="Censys API ID")
    recon_parser.add_argument("--censys-secret", default="", help="Censys API Secret")
    recon_parser.add_argument("--github-token", default="", help="GitHub Token")
    recon_parser.add_argument("-o", "--output", default="", help="报告输出路径")
    recon_parser.add_argument("--timeout", type=float, default=10.0, help="超时秒数")

    # ── poc 命令 ─────────────────────────────────
    poc_parser = sub.add_parser("poc", help="POC 模板漏洞扫描",
        epilog=get_examples("poc"), formatter_class=argparse.RawDescriptionHelpFormatter)
    poc_sub = poc_parser.add_subparsers(dest="poc_action")
    # poc scan
    poc_scan = poc_sub.add_parser("scan", help="用 POC 模板扫描目标")
    poc_scan.add_argument("target", help="目标 URL 或目标文件")
    poc_scan.add_argument("-t", "--templates", default="", help="模板目录或文件")
    poc_scan.add_argument("--template-dir", default="", help="自定义 POC 模板目录 (额外加载)")
    poc_scan.add_argument("--tags", default="", help="按标签过滤")
    poc_scan.add_argument("--severity", default="", help="按严重级别过滤")
    poc_scan.add_argument("-c", "--concurrency", type=int, default=10, help="并发数")
    poc_scan.add_argument("--timeout", type=float, default=10.0, help="HTTP 超时秒数")
    poc_scan.add_argument("-o", "--output", default="", help="结果输出路径")
    poc_scan.add_argument("--stealth", action="store_true", help="隐匿模式")
    poc_scan.add_argument("--proxies", default="", help="代理列表文件")
    poc_scan.add_argument("--qps", type=float, default=10.0, help="全局每秒请求数")
    poc_scan.add_argument("--domain-qps", type=float, default=3.0, help="单域名每秒请求数")
    poc_scan.add_argument("--loop", action="store_true", help="持续性扫描")
    poc_scan.add_argument("--interval", type=int, default=3600, help="循环间隔秒数")
    poc_scan.add_argument("--history", action="store_true", help="显示历史对比")
    # poc history
    poc_hist = poc_sub.add_parser("history", help="查看目标扫描历史")
    poc_hist.add_argument("target", help="目标 URL")
    poc_hist.add_argument("--findings", action="store_true", help="显示漏洞发现详情")
    poc_hist.add_argument("--only-new", action="store_true", help="只显示新增")
    # poc list
    poc_list = poc_sub.add_parser("list", help="列出可用 POC 模板")
    poc_list.add_argument("-t", "--templates", default="", help="模板目录")
    poc_list.add_argument("--template-dir", default="", help="自定义 POC 模板目录 (额外加载)")
    poc_list.add_argument("--tags", default="", help="按标签过滤")
    poc_list.add_argument("--severity", default="", help="按严重级别过滤")

    # ── util 命令 ─────────────────────────────────
    util_parser = sub.add_parser("util", help="编解码 / 加解密工具",
        epilog=get_examples("util"), formatter_class=argparse.RawDescriptionHelpFormatter)
    util_sub = util_parser.add_subparsers(dest="util_action")
    util_enc = util_sub.add_parser("encode", help="编码")
    util_enc.add_argument("type", help="编码类型")
    util_enc.add_argument("text", help="输入文本")
    util_dec = util_sub.add_parser("decode", help="解码")
    util_dec.add_argument("type", help="解码类型")
    util_dec.add_argument("text", help="输入文本")
    util_hash = util_sub.add_parser("hash", help="哈希计算")
    util_hash.add_argument("type", help="哈希类型")
    util_hash.add_argument("text", help="输入文本")
    util_jwt = util_sub.add_parser("jwt-decode", help="JWT 解码")
    util_jwt.add_argument("token", help="JWT Token")
    util_auto = util_sub.add_parser("auto", help="自动识别编码并解码")
    util_auto.add_argument("text", help="输入文本")

    # ── stealth 命令 ─────────────────────────────────
    stealth_parser = sub.add_parser("stealth", help="反封禁 & 代理池管理",
        epilog=get_examples("stealth"), formatter_class=argparse.RawDescriptionHelpFormatter)
    stealth_sub = stealth_parser.add_subparsers(dest="stealth_action")
    proxy_test = stealth_sub.add_parser("proxy-test", help="测试代理可用性")
    proxy_test.add_argument("proxies", help="代理列表文件或单个代理 URL")
    proxy_test.add_argument("--timeout", type=float, default=10.0, help="超时秒数")
    proxy_test.add_argument("-c", "--concurrency", type=int, default=20, help="并发数")
    check_waf = stealth_sub.add_parser("check-waf", help="检测目标 WAF")
    check_waf.add_argument("target", help="目标 URL")
    check_waf.add_argument("--timeout", type=float, default=10.0, help="超时秒数")
    gen_ua = stealth_sub.add_parser("gen-ua", help="生成随机 User-Agent")
    gen_ua.add_argument("-n", "--count", type=int, default=5, help="生成数量")
    gen_ua.add_argument("--category", default="random", help="分类")

    # ── report 命令 ─────────────────────────────
    report_parser = sub.add_parser("report", help="从扫描结果生成 SRC 报告",
        epilog=get_examples("report"), formatter_class=argparse.RawDescriptionHelpFormatter)
    report_parser.add_argument("summary", nargs="?", help="扫描汇总 JSON 文件")
    report_parser.add_argument("-o", "--output", default="scan_results", help="输出目录")

    # ── config 命令 ─────────────────────────────────
    config_parser = sub.add_parser("config", help="配置管理",
        epilog=get_examples("config"), formatter_class=argparse.RawDescriptionHelpFormatter)
    config_sub = config_parser.add_subparsers(dest="config_action")
    config_sub.add_parser("init", help="创建默认配置文件")
    config_sub.add_parser("show", help="显示当前配置")
    config_sub.add_parser("path", help="显示配置文件路径")

    args = parser.parse_args()

    if not args.command:
        print_banner("main")
        parser.print_help()
        return

    # 显示模块 Banner
    if args.command in BANNER_MAP:
        print_banner(BANNER_MAP[args.command])

    # 命令分发
    handler = CMD_MAP.get(args.command)
    if handler:
        safe_run(handler, args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

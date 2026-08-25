"""破晓 CLI 入口"""

import argparse
import sys
import os
import traceback

from src.utils.win_utf8 import fix_windows_utf8
fix_windows_utf8()

# noqa: E402 — 必须先 fix_windows_utf8 再导入含中文输出的模块
from src.utils.banner import print_banner  # noqa: E402
from src.utils.output import Out  # noqa: E402
from src.utils.help import get_examples  # noqa: E402
from src.commands import CMD_MAP, BANNER_MAP  # noqa: E402
from src.i18n import set_locale  # noqa: E402


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
    """破晓 CLI 入口（解析参数 → 分发命令 → 统一异常处理）"""
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
    # 全局语言选项（i18n / D13）：需在子命令前指定，如 `poxiao --lang en scan ...`
    parser.add_argument("--lang", choices=["zh", "en"], default=None,
                        help="界面语言 (zh=中文 / en=English)，默认中文；亦可设环境变量 POXIAO_LANG")
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
    scan_parser.add_argument("--sarif", action="store_true",
                             help="扫描完成后同时生成 SARIF 2.1.0 报告（对接 GitHub Code Scanning）")

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

    # ── mcp 命令 ──────────────────────────────
    mcp_parser = sub.add_parser("mcp", help="启动 MCP 服务端 (AI 辅助，stdio/SSE)",
        epilog=get_examples("mcp"), formatter_class=argparse.RawDescriptionHelpFormatter)
    mcp_parser.add_argument("--transport", default="stdio", choices=["stdio", "sse"],
        help="传输方式：stdio（默认，本地 AI 助手接入）或 sse（HTTP 网络接入）")
    mcp_parser.add_argument("--host", default="127.0.0.1",
        help="SSE 监听地址（--transport sse 时生效，默认 127.0.0.1 仅本机）")
    mcp_parser.add_argument("--port", type=int, default=8765,
        help="SSE 监听端口（--transport sse 时生效，默认 8765）")
    mcp_parser.add_argument("--token", default="",
        help="SSE 访问令牌（--transport sse 时生效；留空则仅建议回环监听，"
             "设置后 GET /sse 与 POST /messages 均须携带 Bearer 令牌或 ?token= 参数）")

    # ── oast 命令（P1-D）────────────────────────────
    oast_parser = sub.add_parser("oast", help="OAST 带外回调服务器（盲注/XXE/SSRF 验证）",
        epilog=get_examples("oast"), formatter_class=argparse.RawDescriptionHelpFormatter)
    oast_subs = oast_parser.add_subparsers(dest="oast_action")
    oast_serve = oast_subs.add_parser("serve", help="启动回调服务器")
    oast_serve.add_argument("--host", default="0.0.0.0", help="监听地址（默认 0.0.0.0）")
    oast_serve.add_argument("--port", type=int, default=8899, help="监听端口（默认 8899）")
    oast_query = oast_subs.add_parser("query", help="查询回调记录")
    oast_query.add_argument("--domain", default="", help="按子域/标签过滤")
    oast_query.add_argument("--limit", type=int, default=100, help="最大条数")
    oast_subs.add_parser("flush", help="清空回调记录")

    # ── proxy 命令（P1-E）────────────────────────────
    proxy_parser = sub.add_parser("proxy", help="被动代理（xray 式，浏览器挂代理记录流量）",
        epilog=get_examples("proxy"), formatter_class=argparse.RawDescriptionHelpFormatter)
    proxy_subs = proxy_parser.add_subparsers(dest="proxy_action")
    proxy_serve = proxy_subs.add_parser("serve", help="启动被动代理")
    proxy_serve.add_argument("--host", default="127.0.0.1", help="监听地址（默认 127.0.0.1）")
    proxy_serve.add_argument("--port", type=int, default=8080, help="监听端口（默认 8080）")
    proxy_query = proxy_subs.add_parser("query", help="查询代理流量记录")
    proxy_query.add_argument("--domain", default="", help="按 URL 包含过滤")
    proxy_query.add_argument("--limit", type=int, default=100, help="最大条数")

    # ── monitor 命令 ───────────────────────────
    monitor_parser = sub.add_parser("monitor", help="资产监控平台（观星）",
        epilog=get_examples("monitor"), formatter_class=argparse.RawDescriptionHelpFormatter)
    mon_subs = monitor_parser.add_subparsers(dest="mon_action")
    mon_serve = mon_subs.add_parser("serve", help="启动 Web 面板")
    mon_serve.add_argument("--host", default="",
        help="监听地址（默认读配置 monitor.host，缺省 127.0.0.1）")
    mon_serve.add_argument("--port", type=int, default=0,
        help="监听端口（默认读配置 monitor.port，缺省 5099）")
    mon_import = mon_subs.add_parser("import", help="导入扫描结果")
    mon_import.add_argument("path", help="扫描汇总 JSON 文件")
    mon_subs.add_parser("stats", help="查看统计")
    mon_export = mon_subs.add_parser("export", help="导出资产/变更（csv|json）")
    mon_export.add_argument("--format", default="json", choices=["csv", "json"], help="导出格式")
    mon_export.add_argument("-o", "--out", default="", help="输出文件路径")

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
    recon_parser.add_argument("--quake-token", default="", help="Quake API Token（P1-F）")
    recon_parser.add_argument("--hunter-key", default="", help="Hunter API Key（P1-F）")
    recon_parser.add_argument("--hunter-email", default="", help="Hunter 账号邮箱（P1-F）")
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
    poc_scan.add_argument("--waf-bypass", action="store_true",
                          help="启用 WAF 绕过（可选能力，默认关；建议配合 --stealth 走代理）")
    poc_scan.add_argument("--proxies", default="", help="代理列表文件")
    poc_scan.add_argument("--qps", type=float, default=10.0, help="全局每秒请求数")
    poc_scan.add_argument("--domain-qps", type=float, default=3.0, help="单域名每秒请求数")
    poc_scan.add_argument("--loop", action="store_true", help="持续性扫描")
    poc_scan.add_argument("--interval", type=int, default=3600, help="循环间隔秒数")
    poc_scan.add_argument("--history", action="store_true", help="显示历史对比")
    poc_scan.add_argument("--oast", action="store_true",
                          help="启用 OAST 变量（{{oast-url}}/{{oast-domain}}）并追踪子域")
    poc_scan.add_argument("--oast-check", action="store_true",
                          help="扫描后查询 OAST 回调服务器，确认带外命中（需先 poxiao oast serve）")
    poc_scan.add_argument("--verify-signatures", action="store_true",
                          help="启用模板 ECDSA 签名校验（P1-C，未签名/不匹配的模板拒绝加载）")
    poc_scan.add_argument("--public-key", default="",
                          help="签名校验用公钥 PEM 路径（--verify-signatures 时必填）")
    poc_scan.add_argument("--include-community", action="store_true",
                          help="P2-5: 同时加载社区模板库（默认 templates-community/，"
                               "可用 POXIAO_COMMUNITY_PATH 覆盖；社区库标注实验性）")
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
    report_parser.add_argument("--format", default="src", choices=["src", "html", "sarif"],
                               help="报告格式（src=文本/Markdown，html=网页，sarif=SARIF 2.1.0）")

    # ── config 命令 ─────────────────────────────────
    config_parser = sub.add_parser("config", help="配置管理",
        epilog=get_examples("config"), formatter_class=argparse.RawDescriptionHelpFormatter)
    config_sub = config_parser.add_subparsers(dest="config_action")
    config_sub.add_parser("init", help="创建默认配置文件")
    config_sub.add_parser("show", help="显示当前配置")
    config_sub.add_parser("path", help="显示配置文件路径")

    # ── scope 命令（授权范围管理，Phase 3）────────────
    scope_parser = sub.add_parser("scope", help="授权范围管理（反滥用红线）",
        epilog='示例:\n  poxiao scope add example.com\n  poxiao scope rm example.com\n  poxiao scope list\n  poxiao scope check http://foo.example.com\n  poxiao scope status',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    scope_sub = scope_parser.add_subparsers(dest="scope_action")
    scope_sub.add_parser("list", help="列出授权范围")
    scope_check = scope_sub.add_parser("check", help="检查目标是否在范围内")
    scope_check.add_argument("target", help="目标 URL / 域名 / IP")
    scope_add = scope_sub.add_parser("add", help="添加范围条目（域名/IP/CIDR/URL）")
    scope_add.add_argument("entry", help="范围条目")
    scope_rm = scope_sub.add_parser("rm", help="移除范围条目")
    scope_rm.add_argument("entry", help="范围条目")
    scope_sub.add_parser("status", help="查看范围文件与校验状态")

    # ── audit 命令（审计日志管理与 hash 链校验，§7.2）──────
    audit_parser = sub.add_parser("audit", help="审计日志管理（hash 链校验 / 清理）",
        epilog='示例:\n  poxiao audit verify\n  poxiao audit cleanup\n  poxiao audit path',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    audit_sub = audit_parser.add_subparsers(dest="audit_action")
    audit_sub.add_parser("verify", help="校验审计 hash 链完整性（不可篡改）")
    audit_cleanup = audit_sub.add_parser("cleanup", help="清理超过保留期的审计文件")
    audit_cleanup.add_argument("--days", type=int, default=0,
                               help="保留天数（默认 365）")
    audit_sub.add_parser("path", help="显示审计目录")

    args = parser.parse_args()

    # 应用语言设置（i18n / D13）：--lang 优先于环境变量 POXIAO_LANG
    if args.lang:
        set_locale(args.lang)

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
        # Poc 单目标 & 子目标集的 scope 预检（Phase 3 反滥用红线）
        if args.command == "poc" and getattr(args, "poc_action", "") == "scan":
            _target = getattr(args, "target", "")
            if _target and not os.path.exists(_target):
                from src.utils.scope import check_scope
                if not check_scope(_target, reason="poc_scan"):
                    Out.error(f"目标不在授权范围内，已阻断: {_target}")
                    Out.info("查看范围: poxiao scope list | 添加: poxiao scope add <target>")
                    return
        # mcp 模式 stdout 必须专用于 JSON-RPC 协议流，跳过一切 stdout 输出（含 redline 告警）
        if args.command != "mcp":
            # 启动安全红线自检（仅告警，不阻断）— P1-3 / D5 / R1
            from src.utils.redline import check_security_config
            for _w in check_security_config():
                Out.warning(_w)
        safe_run(handler, args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

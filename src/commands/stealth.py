"""反封禁命令"""

import asyncio
from pathlib import Path

from src.xiazhi import ProxyPool
from src.xiazhi.waf_bypass import WAFBypass
from src.xiazhi.user_agents import UserAgentPool
from src.utils.output import Out, C


def cmd_stealth(args):
    """反封禁 & 代理池管理"""
    if not args.stealth_action:
        Out.info("用法: poxiao stealth {proxy-test|check-waf|gen-ua}")
        return

    if args.stealth_action == "proxy-test":
        _cmd_stealth_proxy_test(args)
    elif args.stealth_action == "check-waf":
        _cmd_stealth_check_waf(args)
    elif args.stealth_action == "gen-ua":
        _cmd_stealth_gen_ua(args)


def _cmd_stealth_proxy_test(args):
    """测试代理可用性"""
    pool = ProxyPool(validate_timeout=args.timeout)

    # 加载代理
    if Path(args.proxies).exists():
        count = pool.load_from_file(args.proxies)
        Out.info(f"加载 {count} 个代理: {args.proxies}")
    else:
        # 当作单个代理 URL
        count = pool.load_from_list([args.proxies])
        Out.info(f"测试代理: {args.proxies}")

    if count == 0:
        Out.warning("未加载到代理")
        return

    # 验证
    Out.info(f"验证中... (并发: {args.concurrency})")
    results = asyncio.run(pool.validate_all(concurrency=args.concurrency))

    alive = sum(1 for v in results.values() if v)
    Out.blank()
    Out.success(f"可用: {alive}/{len(results)}")
    pool.print_stats()


def _cmd_stealth_check_waf(args):
    """检测目标 WAF"""
    import httpx

    bypass = WAFBypass()
    target = args.target
    if not target.startswith("http"):
        target = f"https://{target}"

    Out.box("WAF 检测", [f"目标: {target}"], C.MAGENTA)

    try:
        # 发送正常请求
        resp = httpx.get(target, timeout=args.timeout, verify=False, follow_redirects=True)
        headers = dict(resp.headers)

        waf = bypass.detect_waf(headers, resp.text)
        if waf:
            Out.error(f"检测到 WAF: {waf}")
            # 显示相关 header
            for k, v in headers.items():
                if any(sig in f"{k}: {v}".lower() for sig in bypass.WAF_SIGNATURES.get(waf, [])):
                    Out._print(f"      {C.DIM}{k}: {v}{C.RESET}")
        else:
            Out.success("未检测到已知 WAF")

        # 显示服务器信息
        server = headers.get("Server", headers.get("server", ""))
        if server:
            Out.kv_row("服务器", server)

        powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        if powered:
            Out.kv_row("技术栈", powered)

    except Exception as e:
        Out.error(f"请求失败: {e}")


def _cmd_stealth_gen_ua(args):
    """生成随机 User-Agent"""
    pool = UserAgentPool()
    category = args.category

    Out.section(f"随机 User-Agent ({category})", "🎲")
    for i in range(args.count):
        ua = pool.get(category)
        Out._print(f"    {i+1}. {ua}")

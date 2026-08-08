"""
破晓 · ASCII 艺术字
====================
每个模块有自己的 banner，启动时显示
"""

from datetime import datetime


# ── 颜色定义 (从 output.py 导入，避免重复定义) ────────

from src.utils.output import C


# Windows 编码修复
def _safe_print(text: str):
    """安全打印，处理编码问题"""
    try:
        print(text)
    except UnicodeEncodeError:
        # 替换无法编码的字符
        print(text.encode("utf-8", errors="replace").decode("utf-8", errors="replace"))


# ── 主 Banner ─────────────────────────────────────────

BANNER_MAIN = f"""{C.CYAN}{C.BOLD}
 ____            _       ___ 
|  _ \\ ___  _ _| | __  / _ \\
| |_) / _ \\| '__| |/ / | | | |
|  __/ (_) | |  |   <  | |_| |
|_|   \\___/|_|  |_|\\_\\  \\___/  {C.RESET}{C.DIM}v2.1{C.RESET}
{C.CYAN}
  +====================================================+
  |  {C.WHITE}破晓 - Bug Bounty 自动化工具链{C.CYAN}                  |
  |  {C.DIM}信息收集 -> 漏洞发现 -> 漏洞验证 -> 报告生成{C.CYAN}     |
  +====================================================+{C.RESET}
{C.DIM}
  {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
  python -m src.cli <command> --help  查看帮助{C.RESET}
"""


# ── 模块 Banner ───────────────────────────────────────

BANNER_RECON = f"""{C.GREEN}{C.BOLD}
  ____  _____ ____  _   _ ____ ___ _____ _   _ ____  
 |  _ \\| ____| __ )| \\ | / ___|_ _| ____| \\ | / ___| 
 | |_) |  _| |  _ \\|  \\| \\___ \\| ||  _| |  \\| \\___ \\ 
 |  _ <| |___| |_) | |\\  |___) | || |___| |\\  |___) |
 |_| \\_\\_____|____/|_| \\_|____/___|_____|_| \\_|____/ 
{C.RESET}{C.DIM}
  被动信息收集 - Whois / 备案 / DNS / 证书 / IP情报 / CDN检测{C.RESET}
"""

BANNER_POC = f"""{C.YELLOW}{C.BOLD}
  ____   ___   ____ _   _ 
 |  _ \\ / _ \\ / ___| | | |
 | |_) | | | | |   | |_| |
 |  __/| |_| | |___|  _  |
 |_|    \\___/ \\____|_| |_|
{C.RESET}{C.DIM}
  POC 模板引擎 - 207个模板 - CVE / 未授权 / 注入 / 信息泄露{C.RESET}
"""

BANNER_STEALTH = f"""{C.MAGENTA}{C.BOLD}
  ____  _____ _____ _   _ _____ _   _ _____ 
 / ___|| ____|_   _| | | |_   _| | | | ____|
 \\___ \\|  _|   | | | | | | | | | |_| |  _|  
  ___) | |___  | | | |_| | | | |  _  | |___ 
 |____/|_____| |_|  \\___/  |_| |_| |_|_____|
{C.RESET}{C.DIM}
  反封禁 - 代理池 / UA轮换 / 限速器 / WAF绕过{C.RESET}
"""

BANNER_UTIL = f"""{C.BLUE}{C.BOLD}
  _   _ ___ _     _____ 
 | | | |_ _| |   |___ / 
 | | | || || |     |_ \\ 
 | |_| || || |___ ___) |
  \\___/|___|_____|____/ 
{C.RESET}{C.DIM}
  编解码工具 - Base64 / Hex / URL / JWT / MD5 / SHA / AES - 29种操作{C.RESET}
"""

BANNER_SCAN = f"""{C.RED}{C.BOLD}
  ____   ____    _    _   _ _   _ ____  
 / ___| / ___|  / \\  | \\ | | \\ | |  _ \\ 
 \\___ \\| |     / _ \\ |  \\| |  \\| | | | |
  ___) | |___ / ___ \\| |\\  | |\\  | |_| |
 |____/ \\____/_/   \\_\\_| \\_|_| \\_|____/ 
{C.RESET}{C.DIM}
  主机扫描 - 技术栈识别 / 敏感路径 / CVE匹配{C.RESET}
"""

BANNER_SUBDOMAIN = f"""{C.CYAN}{C.BOLD}
  ____  _   _ ___  ____  __  __    _    ____  ____  ____ _____ _   _  ____ _____ 
 / ___|| | | | _ \\| __ )|  \\/  |  / \\  |  _ \\|  _ \\|  _ \\_   _| \\ | |/ ___| ____|
 \\___ \\| | | | | | |  _ \\| |\\/| | / _ \\ | | | | | | | | | || | |  \\| | |   |  _|  
  ___) | |_| | |_| | |_) | |  | |/ ___ \\| |_| | |_| | |_| || | | |\\  | |___| |___ 
 |____/ \\___/|____/|____/|_|  |_/_/   \\_\\____/|____/|____/ |_| |_| \\_|\\____|_____|
{C.RESET}{C.DIM}
  霜月 - crt.sh + DNS爆破 + 泛解析检测{C.RESET}
"""

BANNER_VERIFY = f"""{C.YELLOW}{C.BOLD}
  _   _ ___ _   _ _____   _   _ _____ _____ _____ ____  
 | | | |_ _| \\ | | ____| | | | | ____|_   _| ____|  _ \\ 
 | | | || ||  \\| |  _|   | |_| |  _|   | | |  _| | |_) |
 | |_| || || |\\  | |___  |  _  | |___  | | | |___|  _ < 
  \\___/|___|_| \\_|_____| |_| |_|_____| |_| |_____|_| \\_\\
{C.RESET}{C.DIM}
  惊蛰 - 10模块漏洞验证 + 三层降噪 + 评分系统{C.RESET}
"""

BANNER_MONITOR = f"""{C.GREEN}{C.BOLD}
   __  __  ___  _   _ ___ _   _    _    ____  
  |  \\/  |/ _ \\| \\ | |_ _| \\ | |  / \\  |  _ \\ 
  | |\\/| | | | |  \\| || ||  \\| | / _ \\ | | | |
  | |  | | |_| | |\\  || || |\\  |/ ___ \\| |_| |
  |_|  |_|\\___/|_| \\_|___|_| \\_/_/   \\_\\____/ 
{C.RESET}{C.DIM}
  观星 - SQLite资产监控 + Flask Web面板{C.RESET}
"""

BANNER_REPORT = f"""{C.BLUE}{C.BOLD}
  ____  ___  ____ ____      _    ____  _____ 
 |  _ \\| _ \\/ ___|  _ \\    / \\  |  _ \\| ____|
 | |_) | | | |   | |_) |  / _ \\ | |_) |  _|  
 |  _ <| |_| |___|  _ <  / ___ \\|  __/| |___ 
 |_| \\_\\___/\\____|_| \\_\\/_/   \\_\\_|   |_____|
{C.RESET}{C.DIM}
  SRC 报告生成 - 补天 / 漏洞盒子 格式{C.RESET}
"""


# ── Banner 映射 ───────────────────────────────────────

BANNERS = {
    "main": BANNER_MAIN,
    "recon": BANNER_RECON,
    "poc": BANNER_POC,
    "stealth": BANNER_STEALTH,
    "util": BANNER_UTIL,
    "scan": BANNER_SCAN,
    "subdomain": BANNER_SUBDOMAIN,
    "verify": BANNER_VERIFY,
    "monitor": BANNER_MONITOR,
    "report": BANNER_REPORT,
}


def print_banner(name: str = "main"):
    """打印指定模块的 banner"""
    banner = BANNERS.get(name)
    if banner:
        _safe_print(banner)


def print_mini_banner(name: str):
    """打印简化版 banner (单行)"""
    icons = {
        "recon": "🔎",
        "poc": "🧪",
        "stealth": "🥷",
        "util": "🔧",
        "scan": "🔍",
        "subdomain": "🥇",
        "verify": "🥈",
        "monitor": "🥉",
        "report": "📋",
        "discover": "🏢",
    }
    icon = icons.get(name, "▶")
    _safe_print(f"\n  {icon} 破晓 · {name.upper()}\n")

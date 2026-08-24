"""破晓命令注册"""

from .scan import cmd_scan
from .discover import cmd_discover
from .check import cmd_check
from .subdomain import cmd_subdomain
from .monitor import cmd_monitor
from .verify import cmd_verify
from .mcp import cmd_mcp
from .recon import cmd_recon
from .poc import cmd_poc
from .stealth import cmd_stealth
from .util import cmd_util
from .report import cmd_report
from .config import cmd_config
from .oast import cmd_oast
from .proxy import cmd_proxy
from .scope import cmd_scope
from .audit import cmd_audit

# 命令映射表
CMD_MAP = {
    "check": cmd_check,
    "scan": cmd_scan,
    "discover": cmd_discover,
    "subdomain": cmd_subdomain,
    "verify": cmd_verify,
    "monitor": cmd_monitor,
    "mcp": cmd_mcp,
    "recon": cmd_recon,
    "poc": cmd_poc,
    "stealth": cmd_stealth,
    "util": cmd_util,
    "report": cmd_report,
    "config": cmd_config,
    "oast": cmd_oast,
    "proxy": cmd_proxy,
    "scope": cmd_scope,
    "audit": cmd_audit,
}

# Banner 映射表
BANNER_MAP = {
    "recon": "recon",
    "poc": "poc",
    "stealth": "stealth",
    "util": "util",
    "scan": "scan",
    "subdomain": "subdomain",
    "verify": "verify",
    "monitor": "monitor",
    "report": "report",
}

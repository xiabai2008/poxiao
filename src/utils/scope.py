"""
破晓 授权范围管理 (scope) — 工具侧反滥用控制
=============================================

为 SRC 工具提供**可执行的授权范围校验**，把 README 的免责声明从"纯文案"
升级为"硬控制"（安全设计中"越界即拒绝 + 审计留痕"的落地）。

功能：
  * 范围文件：`data/scope.txt`（默认）或 `POXIAO_SCOPE_FILE` 指定。
    支持条目类型：
      - 域名        example.com      （匹配自身及其任意子域 *.example.com）
      - 域名通配    *.example.com
      - IP         1.2.3.4
      - CIDR       10.0.0.0/8
      - 精确 URL    https://a.example.com/path
      - 注释        # ...
  * 校验：`target_in_scope(target)` 返回是否授权；越界目标被拒并记审计。
  * CLI：`poxiao scope` 子命令（list / add / rm / check / status）。

设计约束：
  * 未配置范围文件 / 未启用 -> 不拦截（向后兼容，默认扫描可继续）。
  * 显式启用（存在范围文件或 POXIAO_SCOPE_ENFORCE=1）后，越界目标**阻断**。
  * 拒绝记录写入审计日志（audit 模块），留取证边界。
  * 不引入网络请求；纯本地匹配，逻辑可单测。
"""

import ipaddress
import os
from pathlib import Path
from typing import Iterable, Optional

from src.utils.audit import audit

# 默认范围文件（相对项目根 / cwd）
_DEFAULT_SCOPE_FILE = "data/scope.txt"


def scope_file() -> Path:
    """返回范围文件路径：环境变量优先，默认 data/scope.txt。"""
    env = os.environ.get("POXIAO_SCOPE_FILE", "")
    return Path(env) if env else Path(_DEFAULT_SCOPE_FILE)


def scope_enforced() -> bool:
    """范围校验是否启用：范围文件存在 或 POXIAO_SCOPE_ENFORCE=1。"""
    if os.environ.get("POXIAO_SCOPE_ENFORCE", "") == "1":
        return True
    return scope_file().exists()


def _normalize_target(target: str) -> str:
    """提取目标的主域名/主机/IP，用于隶属判断。"""
    t = (target or "").strip().strip("/").lower()
    if not t:
        return ""
    # 去协议
    if "://" in t:
        t = t.split("://", 1)[1]
    # 去端口 / 路径 / 参数
    t = t.split("/", 1)[0]
    if ":" in t and t.count(":") == 1:  # host:port
        t = t.split(":", 1)[0]
    return t


class ScopeManager:
    """授权范围管理器。"""

    def __init__(self, file: Optional[Path] = None):
        """初始化授权范围（目标/资产列表）"""
        self.file = Path(file) if file else scope_file()
        self._domains: list[str] = []      # 精确域名（匹配自身及子域）
        self._wildcards: list[str] = []    # 通配域名 *.x 仅子域
        self._ips: set[str] = set()        # 精确 IP
        self._networks: list = []          # ipaddress network 对象
        self._urls: list[str] = []         # 精确 URL 前缀
        self.load()

    # ── 加载 ────────────────────────────────────

    def load(self) -> None:
        """从范围文件加载规则（文件不存在则空集）。"""
        self._domains = []
        self._wildcards = []
        self._ips = set()
        self._networks = []
        self._urls = []
        if not self.file.exists():
            return
        for raw in self.file.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            self._add(line)

    def _add(self, entry: str) -> None:
        """添加单个授权目标（规范化）"""
        e = entry.strip().lower()
        if not e:
            return
        if "://" in e:  # 精确 URL（需放最前，避免 / 被当 CIDR）
            self._urls.append(e.rstrip("/"))
        elif e.startswith("*."):
            self._wildcards.append(e[2:].lstrip("."))
        elif "/" in e and "." in e and e.split("/")[0].count(".") == 3:  # CIDR 如 10.0.0.0/8
            try:
                self._networks.append(ipaddress.ip_network(e, strict=False))
            except ValueError:
                self._domains.append(e)
        elif self._is_ip(e):
            self._ips.add(e)
        else:  # 普通域名
            self._domains.append(e.lstrip("."))

    @staticmethod
    def _is_ip(value: str) -> bool:
        """判断字符串是否为 IP 地址"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    # ── 匹配 ────────────────────────────────────

    def matches(self, target: str) -> bool:
        """目标是否在授权范围内。"""
        t = _normalize_target(target)
        if not t:
            return False
        if self._is_ip(t):
            if t in self._ips:
                return True
            ip = ipaddress.ip_address(t)
            return any(ip in net for net in self._networks)
        # 域名匹配：自身 / 子域 来自精确域名，或有子域通配
        if any(self._domain_match(t, d) for d in self._domains):
            return True
        if any(self._wildcard_match(t, w) for w in self._wildcards):
            return True
        return self._url_match(target)

    def _domain_match(self, host: str, scope_domain: str) -> bool:
        """域名精确/子域匹配判断"""
        if host == scope_domain:
            return True
        if host.endswith("." + scope_domain):
            return True
        return False

    def _wildcard_match(self, host: str, scope_domain: str) -> bool:
        # 通配 *.example.com 仅匹配子域，不含裸域 example.com
        """通配符域名匹配判断"""
        return host.endswith("." + scope_domain)

    def _url_match(self, target: str) -> bool:
        """URL 授权匹配（协议/端口/路径）"""
        t = (target or "").strip().strip("/").lower()
        if not t:
            return False
        for u in self._urls:
            if t.startswith(u):
                return True
        return False

    def describe(self) -> list[str]:
        """返回人类可读的范围条目（用于 poxiao scope list）。"""
        out = []
        out += [f"domain\t{d}" for d in sorted(set(self._domains))]
        out += [f"wildcard\t*.{w}" for w in sorted(set(self._wildcards))]
        out += [f"ip\t{ip}" for ip in sorted(self._ips)]
        out += [str(n) for n in self._networks]
        out += [f"url\t{u}" for u in self._urls]
        return out

    def count(self) -> int:
        """授权目标数量"""
        return (len(self._domains) + len(self._wildcards) + len(self._ips)
                + len(self._networks) + len(self._urls))


# ── 顶层 API ────────────────────────────────────

def target_in_scope(target: str, enforce: Optional[bool] = None) -> bool:
    """判断目标是否在授权范围内。

    Args:
        target: 目标（URL / 域名 / IP）。
        enforce: 是否启用校验。None 时按 scope_enforced() 判断；
                 未启用时恒 True（不拦截，向后兼容）。

    Returns:
        True=授权/未启用；False=越界。
    """
    if enforce is None:
        enforce = scope_enforced()
    if not enforce:
        return True
    mgr = ScopeManager()
    return mgr.matches(target)


def check_scope(target: str, enforce: Optional[bool] = None,
                reason: str = "scope_check") -> bool:
    """越界阻断判定：越界时写审计日志并返回 False。

    供各扫描命令在扫描目标前调用：返回 False 即应中止该目标的扫描。
    """
    if enforce is None:
        enforce = scope_enforced()
    if not enforce:
        return True
    ok = target_in_scope(target, enforce=True)
    if not ok:
        audit("scope", "block_off_scope", msg=f"越界目标被阻断: {target}",
              level="warn", **{"reason": reason})
    return ok


# ── 便利函数：过滤目标集合 ─────────────────────────

def filter_targets(targets: Iterable[str]) -> tuple[list, list]:
    """把一个目标集合分为 (授权, 越界) 两组。越界目标不扫描但保留留痕。"""
    enforced = scope_enforced()
    allowed, denied = [], []
    mgr = ScopeManager() if enforced else None
    for t in targets:
        if not enforced or (mgr and mgr.matches(t)):
            allowed.append(t)
        else:
            denied.append(t)
            audit("scope", "block_off_scope", msg=f"越界目标被阻断: {t}",
                  level="warn")
    return allowed, denied

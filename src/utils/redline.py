"""
破晓 · 启动安全红线自检 (P1-3 / D3 / D4 / D5)
============================================

原则（见升级方案 §三 Phase 1 / R1）：
  * `verify_ssl` **保持默认 false**（守内网/自签场景），不翻转默认值；
    仅在关闭时打印醒目告警，提示公网目标的 MITM 风险（安全设计 A02）。
  * 自检**只告警、不阻断运行**，避免破坏既有内网工作流。
"""

from typing import List


def check_security_config() -> List[str]:
    """启动时安全红线自检，返回告警字符串列表（不阻断运行）"""
    from src.config import get_config

    cfg = get_config()
    warns: List[str] = []

    # ── D3 / R1: verify_ssl 默认 false 的全局告警 ──
    verify_ssl = bool(cfg.get("scan", "verify_ssl", False))
    if not verify_ssl:
        warns.append(
            "SSL 证书校验未开启 (verify_ssl=false)：公网目标存在中间人篡改"
            " CVE/情报响应的风险 (安全设计 A02)。内网/自签场景属预期；"
            " 公网扫描建议显式开启校验。"
        )

    # ── D4 / D5: 观星 Web 面板认证 ──
    mon = cfg.get("monitor", default={}) or {}
    if mon.get("auth"):
        host = str(mon.get("host", "127.0.0.1"))
        if host in ("0.0.0.0", ""):
            warns.append(
                "观星 Web 面板已开启认证且绑定 " + host +
                "（全网暴露）：建议仅绑定 127.0.0.1，避免未授权访问 (A05)。"
            )
        if not mon.get("password"):
            warns.append(
                "观星认证已开启但密码为空：请设置强密码，避免裸奔 (A05)。"
            )
        elif str(mon.get("password")) in ("", "admin", "password", "123456"):
            warns.append(
                "观星认证使用弱默认口令：请修改 config 中的 monitor.password。"
            )

    return warns


def warn_insecure_target(url: str, verify_ssl: bool) -> str | None:
    """针对单个目标的 SSL 告警（供 scan/poc 命令在发起请求前调用）。

    返回告警文本；若无需告警则返回 None。
    """
    if verify_ssl:
        return None
    u = url.lower()
    if u.startswith("https://"):
        return f"目标 {url} 为公网 HTTPS 但 verify_ssl=false：响应可能被中间人篡改，请谨慎采信结果。"
    return None

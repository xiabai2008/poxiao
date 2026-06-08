"""
破晓 · 被动信息收集模块
=======================
深度情报收集 — 不主动触碰目标，仅通过公开数据源获取信息

模块:
  - whois_lookup  域名注册信息
  - icp_query     ICP 备案查询
  - dns_records   全量 DNS 记录枚举
  - ip_info       IP 情报 (ASN / 地理 / Shodan / FOFA)
  - cdn_detect    CDN / WAF 检测 & 真实 IP 推断
  - cert_info     证书透明度深度分析
  - recon_engine  编排引擎 (一键全量收集)
"""

from .recon_engine import ReconEngine

__all__ = ["ReconEngine"]

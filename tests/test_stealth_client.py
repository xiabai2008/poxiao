"""P2-3 / X2：WAF 绕过默认关 + 显式 --waf-bypass 两态验证"""

import sys

from src.xiazhi.stealth_client import StealthClient
from src.xiazhi import POCEngine
from src.commands import CMD_MAP
from src.cli import main as cli_main


def test_stealth_client_waf_bypass_off_by_default():
    """StealthClient 默认不启用 WAF 绕过（修正 X2 越界）"""
    client = StealthClient()
    assert client.enable_waf_bypass is False


def test_stealth_client_waf_bypass_can_be_enabled():
    client = StealthClient(enable_waf_bypass=True)
    assert client.enable_waf_bypass is True


def test_poc_engine_default_no_stealth_client():
    """默认（无 stealth / 无 waf）不构造 StealthClient，WAF 不生效"""
    engine = POCEngine()
    assert engine._stealth_client is None
    assert engine.enable_waf_bypass is False


def test_poc_engine_waf_bypass_constructs_stealth_client():
    """显式 enable_waf_bypass 时构造 StealthClient 并开启 WAF 绕过"""
    engine = POCEngine(enable_waf_bypass=True)
    assert engine._stealth_client is not None
    assert engine._stealth_client.enable_waf_bypass is True


def test_poc_engine_waf_bypass_propagates_with_stealth():
    engine = POCEngine(stealth=True, enable_waf_bypass=True)
    assert engine._stealth_client is not None
    assert engine._stealth_client.enable_waf_bypass is True


def test_cli_poc_scan_has_waf_bypass_flag(monkeypatch):
    """cli 的 poc scan 子命令提供 --waf-bypass 开关，默认关闭"""
    captured = {}

    def fake_cmd_poc(args):
        captured["waf_bypass"] = getattr(args, "waf_bypass", False)

    monkeypatch.setitem(CMD_MAP, "poc", fake_cmd_poc)

    # 不带 --waf-bypass
    monkeypatch.setattr(sys, "argv", ["poxiao", "poc", "scan", "http://example.com"])
    cli_main()
    assert captured["waf_bypass"] is False

    # 带 --waf-bypass
    monkeypatch.setattr(
        sys, "argv", ["poxiao", "poc", "scan", "http://example.com", "--waf-bypass"]
    )
    cli_main()
    assert captured["waf_bypass"] is True

"""命令层测试：用 Namespace 直接驱动 cmd_*，并对底层引擎做 monkeypatch。"""

from argparse import Namespace

import pytest

from src.commands import (
    cmd_check, cmd_config, cmd_discover, cmd_monitor, cmd_recon,
    cmd_report, cmd_stealth, cmd_subdomain, cmd_util, cmd_verify,
)
from src.commands.config import _is_sensitive


# ── config ────────────────────────────────────────────────

def _reset_config():
    from src.config import Config
    Config._instance = None


def test_config_no_action(capsys):
    cmd_config(Namespace(config_action=None))
    assert "用法" in capsys.readouterr().out


def test_config_init_creates(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    _reset_config()
    cmd_config(Namespace(config_action="init"))
    assert (tmp_path / ".poxiao" / "config.yaml").exists()


def test_config_init_already_exists(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    _reset_config()
    p = tmp_path / ".poxiao" / "config.yaml"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("scan:\n  concurrency: 9\n", encoding="utf-8")
    cmd_config(Namespace(config_action="init"))
    assert "concurrency: 9" in p.read_text(encoding="utf-8")


def test_config_show(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    _reset_config()
    cmd_config(Namespace(config_action="show"))
    assert "当前配置" in capsys.readouterr().out


def test_config_show_masks_sensitive(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    monkeypatch.setenv("POXIAO_NVD_API_KEY", "abc123secret")
    _reset_config()
    cmd_config(Namespace(config_action="show"))
    out = capsys.readouterr().out
    assert "nvd_api_key" in out
    assert "abc***" in out


def test_config_path(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    _reset_config()
    cmd_config(Namespace(config_action="path"))
    out = capsys.readouterr().out
    assert "配置文件路径" in out


def test_is_sensitive():
    assert _is_sensitive("cve", "nvd_api_key")
    assert _is_sensitive("monitor", "password")
    assert _is_sensitive("recon", "shodan_api_key")
    assert not _is_sensitive("scan", "concurrency")


# ── util ──────────────────────────────────────────────────

def test_util_no_action(capsys):
    cmd_util(Namespace(util_action=None))
    assert "编解码工具" in capsys.readouterr().out


def test_util_auto(capsys):
    cmd_util(Namespace(util_action="auto", text="aGVsbG8="))
    assert "base64" in capsys.readouterr().out


def test_util_auto_no_match(capsys):
    cmd_util(Namespace(util_action="auto", text="!!!notencoded!!!"))
    assert "未能识别" in capsys.readouterr().out


def test_util_encode(capsys):
    cmd_util(Namespace(util_action="encode", type="base64", text="hello"))
    assert "aGVsbG8=" in capsys.readouterr().out


def test_util_encode_unsupported(capsys):
    cmd_util(Namespace(util_action="encode", type="unknown", text="x"))
    assert "不支持" in capsys.readouterr().out


def test_util_decode(capsys):
    cmd_util(Namespace(util_action="decode", type="base64", text="aGVsbG8="))
    assert "hello" in capsys.readouterr().out


def test_util_decode_unsupported(capsys):
    cmd_util(Namespace(util_action="decode", type="unknown", text="x"))
    assert "不支持" in capsys.readouterr().out


def test_util_decode_oneway(capsys):
    cmd_util(Namespace(util_action="decode", type="md5", text="x"))
    assert "单向哈希" in capsys.readouterr().out


def test_util_decode_dict(capsys):
    token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.x"
    cmd_util(Namespace(util_action="decode", type="jwt", text=token))
    assert "admin" in capsys.readouterr().out


def test_util_hash(capsys):
    cmd_util(Namespace(util_action="hash", type="md5", text="admin123"))
    assert "admin123" in capsys.readouterr().out


def test_util_hash_unsupported(capsys):
    cmd_util(Namespace(util_action="hash", type="unknown", text="x"))
    assert "不支持" in capsys.readouterr().out


def test_util_jwt(capsys):
    token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.x"
    cmd_util(Namespace(util_action="jwt-decode", token=token))
    assert "admin" in capsys.readouterr().out


# ── check ─────────────────────────────────────────────────

class _Target:
    def __init__(self, url, alive, status_code=200):
        self.url = url
        self.is_alive = alive
        self.status_code = status_code


class _FakeTargetMgr:
    def load_from_file(self, path):
        return [_Target("http://alive.example", True, 200),
                _Target("http://dead.example", False, 0)]

    def deduplicate(self, targets):
        return targets

    async def check_alive(self, targets):
        return targets


def test_cmd_check(tmp_path, monkeypatch):
    monkeypatch.setattr("src.commands.check.TargetManager", _FakeTargetMgr)
    monkeypatch.setenv("POXIAO_CHECK_OUTPUT", str(tmp_path))
    cmd_check(Namespace(target="targets.txt"))
    assert (tmp_path / "targets_alive.txt").exists()
    alive = tmp_path / "targets_alive.txt"
    assert "alive.example" in alive.read_text(encoding="utf-8")
    assert "dead.example" not in alive.read_text(encoding="utf-8")


# ── discover ──────────────────────────────────────────────

class _FakeDiscovery:
    def __init__(self, *a, **k):
        pass

    def discover_best(self, name):
        if name == "NONE":
            return None
        return f"{name}.com"

    def close(self):
        pass


def test_cmd_discover_from_name(tmp_path, monkeypatch):
    monkeypatch.setattr("src.commands.discover.DomainDiscovery", _FakeDiscovery)
    out = tmp_path / "out.txt"
    cmd_discover(Namespace(name="Acme", file=None, search=False, output=str(out)))
    assert "Acme.com" in out.read_text(encoding="utf-8")


def test_cmd_discover_from_file(tmp_path, monkeypatch):
    monkeypatch.setattr("src.commands.discover.DomainDiscovery", _FakeDiscovery)
    names = tmp_path / "names.txt"
    names.write_text("# comment\nFoo\nBar\nNONE\n", encoding="utf-8")
    out = tmp_path / "out.txt"
    cmd_discover(Namespace(name=None, file=str(names), search=True, output=str(out)))
    txt = out.read_text(encoding="utf-8")
    assert "Foo.com" in txt
    assert "NONE.com" not in txt


def test_cmd_discover_file_missing(monkeypatch, capsys):
    monkeypatch.setattr("src.commands.discover.DomainDiscovery", _FakeDiscovery)
    cmd_discover(Namespace(name=None, file="__no_such_file__.txt",
                           search=False, output="x"))
    assert "文件不存在" in capsys.readouterr().out


def test_cmd_discover_no_args(monkeypatch, capsys):
    monkeypatch.setattr("src.commands.discover.DomainDiscovery", _FakeDiscovery)
    cmd_discover(Namespace(name=None, file=None, search=False, output="x"))
    assert "请指定公司名" in capsys.readouterr().out


# ── subdomain ─────────────────────────────────────────────

class _Sub:
    def __init__(self, domain, alive, category, status_code=200, title=""):
        self.domain = domain
        self.alive = alive
        self.category = category
        self.status_code = status_code
        self.title = title


class _FakeShuangYue:
    def __init__(self, *a, **k):
        pass

    async def collect(self, **kw):
        return [
            _Sub("admin.x.com", True, "admin", 200, "Admin"),
            _Sub("old.x.com", False, "dev", 404, "Old"),
            _Sub("api.x.com", True, "api", 200, "API"),
        ]

    def to_target_file(self, subs, out):
        from pathlib import Path
        Path(out).write_text("\n".join(s.domain for s in subs), encoding="utf-8")


def test_cmd_subdomain(tmp_path, monkeypatch):
    monkeypatch.setattr("src.commands.subdomain.ShuangYue", _FakeShuangYue)
    out = tmp_path / "subs.txt"
    cmd_subdomain(Namespace(domain="x.com", no_crtsh=False, no_brute=False,
                            no_alive=False, output=str(out)))
    assert out.exists()


# ── recon ─────────────────────────────────────────────────

class _FakeReconEngine:
    def __init__(self, *a, **k):
        pass

    async def full_recon(self, domain):
        return {"domain": domain, "mode": "full"}

    async def quick_recon(self, domain):
        return {"domain": domain, "mode": "quick"}

    @staticmethod
    def print_report(report):
        pass

    def save_report(self, report, output=None):
        from pathlib import Path
        p = output or "recon_report.json"
        Path(p).write_text("{}", encoding="utf-8")
        return p


def _recon_args(domain, quick, output):
    return Namespace(domain=domain, quick=quick, timeout=10.0, shodan_key="",
                     fofa_key="", fofa_email="", censys_id="", censys_secret="",
                     github_token="", output=output)


def test_cmd_recon_full(tmp_path, monkeypatch):
    monkeypatch.setattr("src.commands.recon.ReconEngine", _FakeReconEngine)
    out = tmp_path / "r.json"
    cmd_recon(_recon_args("x.com", quick=False, output=str(out)))
    assert out.exists()


def test_cmd_recon_quick(tmp_path, monkeypatch):
    monkeypatch.setattr("src.commands.recon.ReconEngine", _FakeReconEngine)
    cmd_recon(_recon_args("x.com", quick=True, output=""))


# ── verify ────────────────────────────────────────────────

class _Finding:
    def __init__(self, exploitable, confidence="high", url="http://t",
                 finding_type="t", evidence="e", detail="d"):
        self.exploitable = exploitable
        self.confidence = confidence
        self.url = url
        self.finding_type = finding_type
        self.evidence = evidence
        self.detail = detail


class _FakeJingZhe:
    def __init__(self, *a, **k):
        pass

    async def verify(self, target):
        return [_Finding(True), _Finding(False)]

    async def verify_from_scan(self, target):
        return [_Finding(True)]

    def score(self, findings):
        return {"summary": "HIGH"}


def test_cmd_verify_single(monkeypatch, capsys):
    monkeypatch.setattr("src.commands.verify.JingZhe", _FakeJingZhe)
    cmd_verify(Namespace(target="http://t", from_scan=False))
    out = capsys.readouterr().out
    assert "可利用" in out
    assert "可疑" in out


def test_cmd_verify_from_scan(monkeypatch, capsys):
    monkeypatch.setattr("src.commands.verify.JingZhe", _FakeJingZhe)
    cmd_verify(Namespace(target="scan.json", from_scan=True))
    assert "验证结果" in capsys.readouterr().out


# ── report ───────────────────────────────────────────────

class _FakeSRCReporter:
    def generate_batch(self, targets, output_dir="scan_results"):
        return {"total": 1, "output_dir": output_dir, "index": "idx.md",
                "reports": [{"severity": "high", "title": "Test Finding"}]}


def test_cmd_report_src(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("src.commands.report.SRCReporter", _FakeSRCReporter)
    summary = tmp_path / "summary_x.json"
    summary.write_text('{"targets": [{"url": "http://a"}]}', encoding="utf-8")
    cmd_report(Namespace(summary=str(summary), output=str(tmp_path / "out"),
                        format="src"))
    assert "SRC 报告" in capsys.readouterr().out


def test_cmd_report_html(tmp_path):
    summary = tmp_path / "summary_x.json"
    summary.write_text('{"targets": [{"url": "http://a"}]}', encoding="utf-8")
    out_dir = tmp_path / "html"
    cmd_report(Namespace(summary=str(summary), output=str(out_dir), format="html"))
    files = list(out_dir.glob("report_*.html"))
    assert files
    assert "<html" in files[0].read_text(encoding="utf-8").lower()


def test_cmd_report_no_summary(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("POXIAO_SCAN_OUTPUT", str(tmp_path))
    cmd_report(Namespace(summary=None, output=str(tmp_path / "o"), format="src"))
    assert "未找到扫描汇总" in capsys.readouterr().out


def test_cmd_report_missing_file(tmp_path, capsys):
    cmd_report(Namespace(summary=str(tmp_path / "nope.json"),
                        output="x", format="src"))
    assert "文件不存在" in capsys.readouterr().out


# ── stealth ───────────────────────────────────────────────

def test_stealth_no_action(capsys):
    cmd_stealth(Namespace(stealth_action=None))
    assert "用法" in capsys.readouterr().out


class _FakeUA:
    def get(self, category):
        return "Mozilla/5.0 (fake)"


def test_stealth_gen_ua(monkeypatch, capsys):
    monkeypatch.setattr("src.commands.stealth.UserAgentPool", _FakeUA)
    cmd_stealth(Namespace(stealth_action="gen-ua", count=3, category="random"))
    out = capsys.readouterr().out
    assert out.count("Mozilla") == 3


class _FakeProxyPool:
    def __init__(self, *a, **k):
        pass

    def load_from_file(self, p):
        return 0

    def load_from_list(self, lst):
        return len(lst)

    async def validate_all(self, concurrency=20):
        return {"http://1.2.3.4:8080": True, "http://5.6.7.8:8080": False}

    def print_stats(self):
        pass


def test_stealth_proxy_test_list(monkeypatch, capsys):
    monkeypatch.setattr("src.commands.stealth.ProxyPool", _FakeProxyPool)
    cmd_stealth(Namespace(stealth_action="proxy-test",
                          proxies="http://1.2.3.4:8080", timeout=10.0,
                          concurrency=20))
    assert "可用" in capsys.readouterr().out


class _FakeResp:
    def __init__(self, headers, text):
        self.headers = headers
        self.text = text


def test_stealth_check_waf_found(monkeypatch, capsys):
    class _WAF:
        WAF_SIGNATURES = {"Cloudflare": ["cf-ray"]}

        def detect_waf(self, headers, text):
            return "Cloudflare"

    monkeypatch.setattr("httpx.get",
                        lambda *a, **k: _FakeResp({"Server": "nginx", "cf-ray": "x"},
                                                  "<html>WAF</html>"))
    monkeypatch.setattr("src.commands.stealth.WAFBypass", lambda: _WAF())
    cmd_stealth(Namespace(stealth_action="check-waf", target="http://t",
                          timeout=10.0))
    assert "Cloudflare" in capsys.readouterr().out


def test_stealth_check_waf_none(monkeypatch, capsys):
    class _WAF:
        WAF_SIGNATURES = {}

        def detect_waf(self, headers, text):
            return None

    monkeypatch.setattr("httpx.get",
                        lambda *a, **k: _FakeResp({"Server": "nginx"}, ""))
    monkeypatch.setattr("src.commands.stealth.WAFBypass", lambda: _WAF())
    cmd_stealth(Namespace(stealth_action="check-waf", target="http://t",
                          timeout=10.0))
    assert "未检测到已知 WAF" in capsys.readouterr().out


# ── monitor ───────────────────────────────────────────────

def test_monitor_no_action(capsys):
    cmd_monitor(Namespace(mon_action=None))
    assert "用法" in capsys.readouterr().out


def test_monitor_stats(monkeypatch, capsys):
    monkeypatch.setattr("src.commands.monitor.get_stats",
                        lambda: {"total": 0, "alive": 0, "with_findings": 0,
                                 "tech_distribution": {}})
    cmd_monitor(Namespace(mon_action="stats"))
    assert "资产统计" in capsys.readouterr().out


def test_monitor_import(monkeypatch, capsys):
    monkeypatch.setattr("src.commands.monitor.import_from_summary", lambda p: None)
    monkeypatch.setattr("src.commands.monitor.get_stats",
                        lambda: {"total": 5, "alive": 3, "with_findings": 2})
    cmd_monitor(Namespace(mon_action="import", path="x.json"))
    out = capsys.readouterr().out
    assert "5" in out


def test_monitor_serve(monkeypatch):
    called = {}

    def _serve(port=5099):
        called["port"] = port

    monkeypatch.setattr("src.commands.monitor.start_server", _serve)
    cmd_monitor(Namespace(mon_action="serve"))
    assert called["port"] == 5099


def test_monitor_export(tmp_path, monkeypatch):
    monkeypatch.setattr("src.commands.monitor.export_data",
                        lambda fmt: ("content", "text/csv", "assets.csv"))
    out = tmp_path / "assets.csv"
    cmd_monitor(Namespace(mon_action="export", format="csv", out=str(out)))
    assert out.exists()
    assert out.read_text(encoding="utf-8") == "content"

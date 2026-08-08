"""poc 命令单元测试（commands/poc.py）— mock 模板加载器/引擎，覆盖纯逻辑

低 ROI 模块（基线 4%）覆盖率提升：用法打印、list/history 子命令、scan 分支
（无模板早退、单目标无结果扫描）。
"""

from argparse import Namespace

from src.commands import cmd_poc


class _Template:
    def __init__(self, name):
        self.name = name


class _FakeLoader:
    def __init__(self, *a, **k):
        # 兼容真实 TemplateLoader(template_dir, extra_dirs=[]) 签名：
        # 真实调用会把 template_dir 当作位置参数传入，这里忽略它，
        # 仅当显式传入 templates= 时才用它（用于"未找到模板"分支）。
        templates = k.get("templates")
        self._templates = templates if templates is not None else [_Template("t1")]

    def load_all(self, tags=None, severity=None, verify_signatures=False,
                 public_key_path=""):
        return self._templates

    def count_by_severity(self, templates):
        return {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}

    def list_templates(self, templates):
        for t in templates:
            print(t.name)


class _FakeEngine:
    def __init__(self, *a, **k):
        pass

    async def scan_target(self, target, templates):
        return []


def test_poc_no_action(capsys):
    cmd_poc(Namespace(poc_action=None))
    assert "用法" in capsys.readouterr().out


def test_poc_list(monkeypatch, capsys):
    monkeypatch.setattr("src.commands.poc.TemplateLoader", _FakeLoader)
    cmd_poc(Namespace(poc_action="list", templates="", template_dir="",
                     tags="", severity=""))
    assert "t1" in capsys.readouterr().out


def test_poc_history(monkeypatch, capsys):
    monkeypatch.setattr("src.commands.poc.get_target_stats",
                        lambda t: {"scan_count": 2, "total_findings": 1,
                                   "severity_counts": {"high": 1}})
    monkeypatch.setattr("src.commands.poc.print_history", lambda t: None)
    monkeypatch.setattr("src.commands.poc.print_findings",
                        lambda t, only_new=False: None)
    cmd_poc(Namespace(poc_action="history", target="example.com",
                     findings=False, only_new=False))
    out = capsys.readouterr().out
    assert "目标统计" in out
    assert "2" in out


def test_poc_scan_no_templates(monkeypatch, capsys):
    monkeypatch.setattr("src.commands.poc.TemplateLoader",
                        lambda *a, **k: _FakeLoader(templates=[]))
    cmd_poc(Namespace(poc_action="scan", target="http://example.com",
                     templates="", template_dir="", tags="", severity="",
                     concurrency=10, timeout=10.0, proxies="", qps=10.0,
                     domain_qps=3.0, stealth=False, waf_bypass=False,
                     loop=False, interval=3600, history=False, output=""))
    assert "未找到模板" in capsys.readouterr().out


def test_poc_scan_single_no_results(monkeypatch, capsys):
    monkeypatch.setattr("src.commands.poc.TemplateLoader", _FakeLoader)
    monkeypatch.setattr("src.commands.poc.POCEngine", _FakeEngine)
    monkeypatch.setattr("src.commands.poc.save_scan_results",
                        lambda *a, **k: "scan_id")
    cmd_poc(Namespace(poc_action="scan", target="http://example.com",
                     templates="", template_dir="", tags="", severity="",
                     concurrency=10, timeout=10.0, proxies="", qps=10.0,
                     domain_qps=3.0, stealth=False, waf_bypass=False,
                     loop=False, interval=3600, history=False, output=""))
    assert "未发现漏洞" in capsys.readouterr().out

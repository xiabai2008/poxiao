"""scan 命令单元测试（commands/scan.py）— mock 引擎，端到端覆盖纯逻辑

低 ROI 模块（基线 8%）覆盖率提升：目标加载/去重、存活检测、信息收集、
汇总落盘、SRC 报告生成分支（无 RayScan 触网）。
"""

import asyncio
from argparse import Namespace

from src.commands import cmd_scan


class _Target:
    def __init__(self, url, alive=True, status_code=200):
        self.url = url
        self.is_alive = alive
        self.status_code = status_code


class _FakeTM:
    def load_from_file(self, p):
        return [_Target(p)]

    def load_from_list(self, ts):
        return [_Target(t) for t in ts]

    def deduplicate(self, ts):
        return ts

    async def check_alive(self, ts):
        for t in ts:
            t.is_alive = True
        return ts

    def classify(self, ts):
        pass


class _ScanResult:
    def __init__(self, url):
        self.url = url

    def to_dict(self):
        return {"target_url": self.url, "alive": True}


class _FakeEngine:
    def __init__(self, *a, **k):
        pass

    async def scan_one(self, url):
        return _ScanResult(url)


class _FakeReporter:
    def __init__(self, *a, **k):
        self.output_dir = "scan_results"

    def save_target_report(self, d):
        pass

    def print_progress(self, i, t, d):
        pass

    def save_summary(self):
        return "summary.json"

    def save_markdown(self):
        return "md.md"


class _FakeSRC:
    def generate_batch(self, targets, output_dir="scan_results"):
        return {"total": 0, "output_dir": output_dir, "index": "idx",
                "reports": []}


def _args():
    return Namespace(target="http://example.com", file=None, depth="normal",
                     no_sensitive=True, concurrency=5, timeout=5.0,
                     output="scan_results")


def test_cmd_scan_end_to_end(monkeypatch, capsys):
    monkeypatch.setattr("src.commands.scan.TargetManager", _FakeTM)
    monkeypatch.setattr("src.commands.scan.ScanEngine", _FakeEngine)
    monkeypatch.setattr("src.commands.scan.Reporter", _FakeReporter)
    monkeypatch.setattr("src.commands.scan.SRCReporter", _FakeSRC)
    cmd_scan(_args())
    out = capsys.readouterr().out
    assert "扫描完成" in out
    assert "未发现" in out or "SRC" in out


def test_cmd_scan_no_target(monkeypatch, capsys):
    # 无 target/file，且默认路径不存在 → 打印错误并返回
    monkeypatch.setattr("src.commands.scan.TargetManager", _FakeTM)
    cmd_scan(Namespace(target=None, file=None, depth="normal",
                       no_sensitive=True, concurrency=5, timeout=5.0,
                       output="scan_results"))
    assert "请指定目标" in capsys.readouterr().out


def test_cmd_scan_from_file(monkeypatch, capsys, tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("http://a.com\nhttp://b.com\n", encoding="utf-8")
    monkeypatch.setattr("src.commands.scan.TargetManager", _FakeTM)
    monkeypatch.setattr("src.commands.scan.ScanEngine", _FakeEngine)
    monkeypatch.setattr("src.commands.scan.Reporter", _FakeReporter)
    monkeypatch.setattr("src.commands.scan.SRCReporter", _FakeSRC)
    cmd_scan(Namespace(target=str(f), file=None, depth="normal",
                       no_sensitive=True, concurrency=5, timeout=5.0,
                       output=str(tmp_path / "out")))
    assert "扫描完成" in capsys.readouterr().out

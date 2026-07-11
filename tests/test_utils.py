"""工具层测试：output / redline / help / banner"""

import pytest

from src.utils import output as output_mod
from src.utils.output import Out, C
from src.utils import redline
from src.utils.help import get_examples, print_examples
from src.utils.banner import print_banner, print_mini_banner


# ── output ────────────────────────────────────────────────

def test_output_title_subtitle_section():
    Out.title("T"); Out.subtitle("S"); Out.section("Sec", "🔧")


def test_output_status_messages():
    Out.success("ok"); Out.error("err"); Out.warning("warn")
    Out.info("info"); Out.dim("dim"); Out.blank()


def test_output_kv():
    Out.kv("key", "val"); Out.kv_row("key", "val")
    Out.kv_row("key", "val", key_width=20, indent=2)


def test_output_progress_zero_total():
    # total == 0 应提前返回，不抛错
    Out.progress(0, 0)


def test_output_progress_partial_and_done(capsys):
    Out.progress(5, 10, prefix="p");  # 不换行
    Out.progress(10, 10, prefix="p");  # 完成换行
    out = capsys.readouterr().out
    assert "50%" in out and "100%" in out


def test_output_progress_done():
    Out.progress_done(prefix="完成", count=3, elapsed=1.5)
    Out.progress_done(prefix="无耗时")  # elapsed=0 不显示耗时
    Out.progress_done(prefix="无数量", count=0)  # count=0 不显示数量


def test_output_table_empty():
    Out.table(["a", "b"], [])


def test_output_table_with_rows():
    Out.table(["Name", "Val"], [["x", "1"], ["y", "2"]])
    Out.table(["Name", "Val"], [["x", "1"]], colors=[C.RED, C.GREEN])
    Out.table(["Name", "Val"], [["longvalue", "1"]], max_widths=[4, 4])


def test_output_box():
    Out.box("标题", ["line1", "line2"], color=C.MAGENTA)
    Out.box("空", [])


def test_output_summary_scalar_dict_list():
    Out.summary({"n": 1, "d": {"k": "v"}, "l": ["a", "b", "c", "d", "e", "f"]},
                title="摘要")


def test_output_separator():
    Out.separator()
    Out.separator("=", 20)


def test_output_severity_tag_and_icon():
    for sev in ("critical", "high", "medium", "low", "info", "weird"):
        assert sev.lower() in Out.severity_tag(sev).lower() or "[" in Out.severity_tag(sev)
        assert Out.severity_icon(sev)


def test_output_elapsed():
    assert Out.elapsed(0.5) == "500ms"
    assert "s" in Out.elapsed(5.0)
    assert "m" in Out.elapsed(125.0)


def test_output_count_label():
    assert "无" in Out.count_label(0)
    assert Out.count_label(1) == "1 个"
    assert Out.count_label(3) == "3 个"


def test_output_print_unicode_fallback(monkeypatch):
    # 首次写入抛 UnicodeEncodeError，验证兜底分支（后续写入成功，不无限循环）
    import io

    class _Broken(io.TextIOBase):
        def __init__(self):
            self.n = 0

        def write(self, s):
            self.n += 1
            if self.n == 1:
                raise UnicodeEncodeError("ascii", "é", 0, 1, "bad")
            return len(s)

    monkeypatch.setattr("sys.stdout", _Broken())
    Out._print("é")  # 应落入 except 兜底且不抛异常


# ── redline ───────────────────────────────────────────────

class _FakeCfg:
    def __init__(self, data):
        self._data = data

    def get(self, section, key=None, default=None):
        sec = self._data.get(section, {})
        if key is None:
            return sec
        return sec.get(key, default)


def test_redline_clean(monkeypatch):
    cfg = _FakeCfg({"scan": {"verify_ssl": True},
                    "monitor": {"auth": False, "host": "127.0.0.1",
                                "password": "x"}})
    monkeypatch.setattr("src.config.get_config", lambda: cfg)
    assert redline.check_security_config() == []


def test_redline_warns(monkeypatch):
    cfg = _FakeCfg({
        "scan": {"verify_ssl": False},
        "monitor": {"auth": True, "host": "0.0.0.0", "password": ""},
    })
    monkeypatch.setattr("src.config.get_config", lambda: cfg)
    warns = redline.check_security_config()
    assert any("verify_ssl" in w for w in warns)
    assert any("0.0.0.0" in w for w in warns)
    assert any("密码为空" in w for w in warns)


def test_redline_auth_no_password(monkeypatch):
    cfg = _FakeCfg({"scan": {"verify_ssl": True},
                    "monitor": {"auth": True, "host": "127.0.0.1",
                                "password": "123456"}})
    monkeypatch.setattr("src.config.get_config", lambda: cfg)
    warns = redline.check_security_config()
    assert any("弱默认口令" in w for w in warns)


def test_warn_insecure_target():
    assert redline.warn_insecure_target("https://x.com", False) is not None
    assert redline.warn_insecure_target("https://x.com", True) is None
    assert redline.warn_insecure_target("http://x.com", False) is None


# ── help ──────────────────────────────────────────────────

def test_get_examples():
    assert "poxiao" in get_examples("main")
    assert get_examples("zzz") == ""


def test_print_examples(capsys):
    print_examples("scan")
    assert "poxiao scan" in capsys.readouterr().out


# ── banner ────────────────────────────────────────────────

def test_print_banner_all():
    for name in ("main", "recon", "poc", "stealth", "util", "scan",
                 "subdomain", "verify", "monitor", "report"):
        print_banner(name)


def test_print_banner_unknown():
    print_banner("__no_such__")  # 无 banner，不应抛错


def test_print_mini_banner():
    print_mini_banner("recon")
    print_mini_banner("__unknown__")

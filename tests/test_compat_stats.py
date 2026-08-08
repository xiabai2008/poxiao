"""模板兼容性统计测试（S4：compat 命令）"""

import pytest

from tools.template_sync import compat_stats, print_compat


def _write(d, name, content):
    f = d / name
    f.write_text(content, encoding="utf-8")
    return f


@pytest.fixture
def mixed_dir(tmp_path):
    d = tmp_path / "tpls"
    d.mkdir()
    _write(d, "word.yaml",
           'id: w\ninfo:\n  name: "W"\nhttp:\n  method: GET\n  path:\n    - "{{BaseURL}}/"\n'
           '  matchers:\n    - type: word\n      words:\n        - "admin"\n')
    _write(d, "dsl.yaml",
           'id: d\ninfo:\n  name: "D"\nhttp:\n  method: GET\n  path:\n    - "{{BaseURL}}/"\n'
           '  matchers:\n    - type: dsl\n      dsl:\n        - "to_lower(body) contains \'x\'"\n')
    _write(d, "raw.yaml",
           'id: r\ninfo:\n  name: "R"\nhttp:\n  raw:\n'
           '    - "GET / HTTP/1.1\\nHost: {{Hostname}}"\n'
           '  matchers:\n    - type: word\n      words:\n        - "ok"\n')
    _write(d, "tcp.yaml",
           'id: t\ninfo:\n  name: "T"\ntcp:\n  host:\n    - "{{Hostname}}"\n')
    _write(d, "xpath.yaml",
           'id: x\ninfo:\n  name: "X"\nhttp:\n  method: GET\n  path:\n    - "{{BaseURL}}/"\n'
           '  matchers:\n    - type: xpath\n      xpath:\n        - "//a"\n')
    return d


class TestCompatStats:
    def test_counts_and_protocols(self, mixed_dir):
        s = compat_stats(mixed_dir)
        assert s["yaml_total"] == 5
        assert s["http_supported"] == 4
        assert s["other_protocols"] == {"tcp": 1}

    def test_matcher_types(self, mixed_dir):
        s = compat_stats(mixed_dir)
        assert s["matcher_types"]["word"] == 2
        assert s["matcher_types"]["dsl"] == 1
        assert s["matcher_types"]["xpath"] == 1

    def test_raw_feature_detected(self, mixed_dir):
        s = compat_stats(mixed_dir)
        assert s["unsupported_features"]["raw"] == 1

    def test_dsl_count(self, mixed_dir):
        s = compat_stats(mixed_dir)
        assert s["dsl_count"] == 1

    def test_xpath_template_flagged(self, mixed_dir):
        s = compat_stats(mixed_dir)
        assert any("xpath.yaml" in t for t in s["unsupported_templates"])

    def test_empty_dir(self, tmp_path):
        s = compat_stats(tmp_path)
        assert s["yaml_total"] == 0

    def test_print_compat_runs(self, mixed_dir, capsys):
        print_compat(compat_stats(mixed_dir))
        out = capsys.readouterr().out
        assert "HTTP 可执行" in out

"""P3-2 模板工具链测试：validate + diff（差异作指标不失败）"""
import yaml
from pathlib import Path

from tools.template_sync import validate_path, diff_dirs, main


def _write_tpl(path: Path, tid: str, sev: str = "info", has_http: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"id": tid, "info": {"name": tid, "severity": sev}}
    if has_http:
        doc["http"] = [{"method": "GET", "path": "/"}]
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")


def test_validate_valid_template(tmp_path):
    p = tmp_path / "t.yaml"
    _write_tpl(p, "test-valid")
    res = validate_path(p)
    assert res["files"] == 1
    assert res["valid"] == 1
    assert not res["field_errors"]


def test_validate_missing_id(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump({"info": {"name": "x", "severity": "info"}}), encoding="utf-8")
    res = validate_path(p)
    assert res["field_errors"]  # 缺 id 应报错


def test_validate_bad_severity_warns(tmp_path):
    p = tmp_path / "w.yaml"
    _write_tpl(p, "test-warn", sev="unknown")
    res = validate_path(p)
    assert res["valid"] == 1
    assert res["sev_warns"]  # 未知 severity 仅告警


def test_diff_detects_added_removed_modified(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    _write_tpl(a / "same.yaml", "same-id")
    _write_tpl(a / "rm.yaml", "rm-id")
    _write_tpl(b / "same.yaml", "same-id")
    _write_tpl(b / "new.yaml", "new-id")
    _write_tpl(b / "mod.yaml", "mod-id")
    # 修改 a 中一个文件放入 b
    _write_tpl(a / "mod.yaml", "mod-id")
    _write_tpl(b / "mod.yaml", "mod-id", sev="high")  # 内容不同 -> modified

    d = diff_dirs(a, b)
    assert d["counts"]["added"] >= 1  # new-id
    assert d["counts"]["removed"] >= 1  # rm-id
    assert d["counts"]["modified"] >= 1  # mod-id
    assert "new.yaml" in d["added"]


def test_diff_exit_zero(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    _write_tpl(a / "x.yaml", "x-id")
    _write_tpl(b / "x.yaml", "x-id")
    _write_tpl(b / "y.yaml", "y-id")
    code = main(["diff", str(a), str(b)])
    assert code == 0  # 差异非错误（守 X1）

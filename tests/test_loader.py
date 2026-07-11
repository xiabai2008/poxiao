"""xiazhi.loader 纯逻辑测试（YAML 模板解析，无网络）"""

from src.xiazhi.loader import TemplateLoader
from src.xiazhi.template import Template, TemplateInfo


def _loader():
    return TemplateLoader()


def test_parse_template_full():
    loader = _loader()
    raw = {
        "id": "CVE-2021-1",
        "info": {
            "name": "Test", "severity": "High", "tags": "rce, test",
            "author": "me", "description": "d",
        },
        "requests": [{
            "method": "GET", "path": ["/x"],
            "matchers": [{"type": "status", "status": [200]}],
            "extractors": [{"type": "regex", "regex": [r"v=(\d+)"], "group": 1, "name": "v"}],
        }],
    }
    t = loader._parse_template(raw, "f.yaml")
    assert t.id == "CVE-2021-1"
    assert t.info.severity == "high"
    assert "rce" in t.info.tags
    assert t.requests[0].method == "GET"
    assert t.requests[0].matchers[0].status == [200]
    assert t.requests[0].extractors[0].name == "v"


def test_parse_template_no_id():
    loader = _loader()
    assert loader._parse_template({"info": {}}, "f") is None


def test_parse_template_no_requests():
    loader = _loader()
    assert loader._parse_template({"id": "x", "info": {}}, "f") is None


def test_parse_template_http_block_alias():
    loader = _loader()
    raw = {"id": "x", "info": {}, "http": {"method": "POST", "path": "/p"}}
    t = loader._parse_template(raw, "f.yaml")
    assert t.requests[0].method == "POST"
    assert t.requests[0].path == ["/p"]


def test_parse_request_body_dict():
    loader = _loader()
    raw = {"id": "x", "info": {}, "requests": [
        {"method": "POST", "path": "/p", "body": {"a": 1}}
    ]}
    t = loader._parse_template(raw, "f.yaml")
    assert t.requests[0].body == '{"a": 1}'


def test_parse_tags_str_and_list():
    loader = _loader()
    assert loader._parse_tags("a, b") == ["a", "b"]
    assert loader._parse_tags(["x", "y"]) == ["x", "y"]
    assert loader._parse_tags("") == []
    assert loader._parse_tags(None) == []


def test_ensure_list():
    loader = _loader()
    assert loader._ensure_list(["a"]) == ["a"]
    assert loader._ensure_list(None) == []
    assert loader._ensure_list("a") == ["a"]


def test_count_by_severity():
    loader = _loader()
    ts = [
        Template(id="1", info=TemplateInfo(severity="high")),
        Template(id="2", info=TemplateInfo(severity="high")),
        Template(id="3", info=TemplateInfo(severity="low")),
    ]
    assert loader.count_by_severity(ts) == {"high": 2, "low": 1}


def test_list_templates(capsys):
    loader = _loader()
    ts = [Template(id="CVE-1", info=TemplateInfo(severity="critical", name="n"))]
    loader.list_templates(ts)
    assert "CRITICAL" in capsys.readouterr().out


def test_load_file_from_disk(tmp_path):
    loader = _loader()
    f = tmp_path / "t.yaml"
    f.write_text(
        "id: CVE-X\n"
        "info:\n  name: t\n  severity: medium\n  tags: x,y\n"
        "requests:\n  - method: GET\n    path: ['/z']\n"
        "    matchers:\n      - type: status\n        status: [200]\n",
        encoding="utf-8",
    )
    t = loader.load_file(f)
    assert t is not None and t.id == "CVE-X"
    assert t.info.severity == "medium"


def test_load_file_invalid_yaml(tmp_path):
    loader = _loader()
    f = tmp_path / "bad.yaml"
    f.write_text("id: [unbalanced\n", encoding="utf-8")
    assert loader.load_file(f) is None


def test_load_file_not_a_dict(tmp_path):
    loader = _loader()
    f = tmp_path / "list.yaml"
    f.write_text("- just\n- a\n- list\n", encoding="utf-8")
    assert loader.load_file(f) is None


def test_load_all_from_dir(tmp_path):
    loader = TemplateLoader(template_dir=str(tmp_path))
    (tmp_path / "a.yaml").write_text(
        "id: CVE-A\ninfo:\n  name: a\n  severity: high\nrequests:\n  - method: GET\n    path: ['/']\n    matchers:\n      - type: status\n        status: [200]\n",
        encoding="utf-8",
    )
    (tmp_path / "b.yaml").write_text(
        "id: CVE-B\ninfo:\n  name: b\n  severity: low\n  tags: rce\nrequests:\n  - method: GET\n    path: ['/']\n    matchers:\n      - type: status\n        status: [200]\n",
        encoding="utf-8",
    )
    templates = loader.load_all()
    assert len(templates) == 2
    # 标签过滤
    only_rce = loader.load_all(tags=["rce"])
    assert len(only_rce) == 1 and only_rce[0].id == "CVE-B"
    # 严重级别过滤
    only_high = loader.load_all(severity=["high"])
    assert len(only_high) == 1 and only_high[0].id == "CVE-A"
    # id 过滤
    by_id = loader.load_all(ids=["CVE-A"])
    assert len(by_id) == 1

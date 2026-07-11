"""xiazhi.extractor 纯逻辑测试（从响应提取数据，无网络）"""

from src.xiazhi.template import Extractor
from src.xiazhi.extractor import ExtractorEngine


def _engine():
    return ExtractorEngine()


def test_regex_extract_with_group():
    e = _engine()
    ext = Extractor(type="regex", name="v", regex=[r"version=(\d+)"], group=1, part="body")
    res = e.extract([ext], 200, {}, "version=5 and more")
    assert res["v"] == "5"


def test_regex_extract_tuple_group_auto():
    e = _engine()
    ext = Extractor(type="regex", name="v", regex=[r"(\d+)\.(\d+)"], group=0, part="body")
    res = e.extract([ext], 200, {}, "1.2")
    # 存在捕获组时 findall 返回各分组；group=0 取第一个分组
    assert res["v"] == "1"


def test_regex_extract_multiple():
    e = _engine()
    ext = Extractor(type="regex", name="v", regex=[r"\d+"], group=0, part="body")
    res = e.extract([ext], 200, {}, "a1 b2 c3")
    assert res["v"] == "1, 2, 3"


def test_regex_no_match():
    e = _engine()
    ext = Extractor(type="regex", name="v", regex=[r"zzz(\d+)"], part="body")
    assert e.extract([ext], 200, {}, "abc") == {}


def test_regex_invalid_pattern_skipped():
    e = _engine()
    ext = Extractor(type="regex", name="v", regex=[r"("], part="body")
    assert e.extract([ext], 200, {}, "abc") == {}


def test_kval_header():
    e = _engine()
    ext = Extractor(type="kval", name="srv", kval=["server"], part="header")
    res = e.extract([ext], 200, {"Server": "nginx"}, "body")
    assert res["srv"] == "nginx"


def test_kval_header_not_found():
    e = _engine()
    ext = Extractor(type="kval", name="srv", kval=["server"], part="header")
    assert e.extract([ext], 200, {"X": "y"}, "body") == {}


def test_kval_cookie():
    e = _engine()
    ext = Extractor(type="kval", name="sid", kval=["cookie_sessionid"], part="header")
    res = e.extract([ext], 200, {"Set-Cookie": "sessionid=abc; x=1"}, "body")
    assert res["sid"] == "abc"


def test_json_extract():
    e = _engine()
    ext = Extractor(type="json", name="j", json=["a.b"], part="body")
    res = e.extract([ext], 200, {}, '{"a":{"b":"x"}}')
    assert res["j"] == "x"


def test_json_extract_array_index():
    e = _engine()
    ext = Extractor(type="json", name="j", json=["a[0]"], part="body")
    res = e.extract([ext], 200, {}, '{"a":["first","second"]}')
    assert res["j"] == "first"


def test_json_invalid_body():
    e = _engine()
    ext = Extractor(type="json", name="j", json=["a"], part="body")
    assert e.extract([ext], 200, {}, "not json") == {}


def test_unknown_type_skipped():
    e = _engine()
    ext = Extractor(type="xpath", name="x", part="body")
    assert e.extract([ext], 200, {}, "body") == {}


def test_get_target_header_and_all():
    e = _engine()
    ext = Extractor(type="kval", name="srv", kval=["server"], part="header")
    res = e.extract([ext], 200, {"server": "nginx", "x": "y"}, "body")
    assert res["srv"] == "nginx"
    # all part
    ext2 = Extractor(type="kval", name="x", kval=["x"], part="all")
    res2 = e.extract([ext2], 200, {"x": "y"}, "body")
    assert res2["x"] == "y"

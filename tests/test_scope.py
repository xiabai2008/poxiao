"""授权范围管理 (Phase 3) — 单元测试"""


from src.utils import scope


def _make_scope(tmp_path, text):
    f = tmp_path / "scope.txt"
    f.write_text(text, encoding="utf-8")
    return f


class TestScopeManagerMatch:
    def test_domain_matches_self_and_subdomain(self, tmp_path):
        f = _make_scope(tmp_path, "example.com\n")
        m = scope.ScopeManager(f)
        assert m.matches("example.com")
        assert m.matches("http://example.com")
        assert m.matches("api.example.com")
        assert m.matches("a.b.example.com")
        assert m.matches("https://api.example.com:8080/path")
        assert not m.matches("other.com")
        assert not m.matches("notexample.com")  # 前缀混淆不应命中

    def test_wildcard_domain(self, tmp_path):
        f = _make_scope(tmp_path, "*.example.com\n")
        m = scope.ScopeManager(f)
        assert m.matches("sub.example.com")
        assert not m.matches("example.com")

    def test_ip_and_cidr(self, tmp_path):
        f = _make_scope(tmp_path, "1.2.3.4\n10.0.0.0/8\n")
        m = scope.ScopeManager(f)
        assert m.matches("1.2.3.4")
        assert m.matches("10.1.2.3")
        assert not m.matches("1.2.3.5")
        assert not m.matches("11.0.0.1")

    def test_exact_url(self, tmp_path):
        f = _make_scope(tmp_path, "https://a.example.com/x\n")
        m = scope.ScopeManager(f)
        assert m.matches("https://a.example.com/x")
        assert m.matches("https://a.example.com/xyz")  # 前缀
        assert not m.matches("https://a.example.com")

    def test_comments_and_blank_ignored(self, tmp_path):
        f = _make_scope(tmp_path, "# 注释\n\n  example.com  \n")
        m = scope.ScopeManager(f)
        assert m.count() == 1
        assert m.matches("example.com")

    def test_empty_file_zero(self, tmp_path):
        f = _make_scope(tmp_path, "")
        m = scope.ScopeManager(f)
        assert m.count() == 0
        assert not m.matches("example.com")


class TestNormalize:
    def test_various_target_format(self):
        assert scope._normalize_target("https://Api.Example.com:8443/x?y=1") == "api.example.com"
        assert scope._normalize_target("example.com") == "example.com"
        assert scope._normalize_target("1.2.3.4") == "1.2.3.4"
        assert scope._normalize_target("1.2.3.4:8080") == "1.2.3.4"
        assert scope._normalize_target("") == ""


class TestEnforceGate:
    def test_no_scope_file_not_enforced(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POXIAO_SCOPE_FILE", str(tmp_path / "none.txt"))
        monkeypatch.delenv("POXIAO_SCOPE_ENFORCE", raising=False)
        assert not scope.scope_enforced()
        assert scope.target_in_scope("evil.com") is True  # 未启用不拦截

    def test_enforce_env_forces(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POXIAO_SCOPE_FILE", str(tmp_path / "none.txt"))
        monkeypatch.setenv("POXIAO_SCOPE_ENFORCE", "1")
        _, denied = scope.filter_targets(["evil.com"])
        assert denied

    def test_filter_targets_default(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POXIAO_SCOPE_FILE", str(tmp_path / "none.txt"))
        monkeypatch.delenv("POXIAO_SCOPE_ENFORCE", raising=False)
        allowed, denied = scope.filter_targets(["a.com", "b.com"])
        assert allowed == ["a.com", "b.com"]
        assert denied == []

    def test_filter_with_scope(self, tmp_path, monkeypatch):
        f = _make_scope(tmp_path, "example.com\n")
        monkeypatch.setenv("POXIAO_SCOPE_FILE", str(f))
        monkeypatch.delenv("POXIAO_SCOPE_ENFORCE", raising=False)
        allowed, denied = scope.filter_targets(["example.com", "evil.com"])
        assert allowed == ["example.com"]
        assert denied == ["evil.com"]

"""安全设计 §2.1 认证 — bcrypt 哈希 / 会话 / CSRF / 锁定 单元测试"""



from src.guanxing import auth


class TestPasswordHash:
    def test_hash_not_plaintext(self):
        h = auth.hash_password("s3cret-pass")
        assert h.startswith("$2")  # bcrypt
        assert "s3cret-pass" not in h

    def test_verify_correct(self):
        h = auth.hash_password("correct-password")
        assert auth.verify_password("correct-password", h)

    def test_verify_wrong(self):
        h = auth.hash_password("correct-password")
        assert not auth.verify_password("wrong-password", h)

    def test_verify_non_hash_returns_false(self):
        assert not auth.verify_password("x", None)
        assert not auth.verify_password("x", "")

    def test_normalize_password_fmt(self):
        assert auth.normalize_password_fmt("short")
        assert not auth.normalize_password_fmt("x" * 61)


class TestCredentials:
    def test_credentials_prefer_config_injection(self, monkeypatch):
        monkeypatch.setenv("POXIAO_MONITOR_USER", "envusr")
        monkeypatch.setenv("POXIAO_MONITOR_PASS", "envpass")
        auth.set_credentials("cfguser", "$2config-hash")
        user, pw = auth.get_credentials()
        assert user == "cfguser"
        assert pw == "$2config-hash"
        auth.set_credentials("", None)  # 复位

    def test_credentials_fallback_env(self, monkeypatch):
        auth.set_credentials("", None)
        monkeypatch.setenv("POXIAO_MONITOR_USER", "envusr")
        monkeypatch.setenv("POXIAO_MONITOR_PASS", "envpass")
        user, pw = auth.get_credentials()
        assert user == "envusr"
        assert pw == "envpass"

    def test_auth_enabled(self, monkeypatch):
        auth.set_credentials("", None)
        monkeypatch.delenv("POXIAO_MONITOR_USER", raising=False)
        monkeypatch.delenv("POXIAO_MONITOR_PASS", raising=False)
        assert not auth.auth_enabled()
        auth.set_credentials("u", "$2x")
        assert auth.auth_enabled()
        auth.set_credentials("", None)


class TestSessionToken:
    def test_roundtrip(self):
        tok = auth.issue_session_token("admin")
        assert auth.verify_session_token(tok) == "admin"

    def test_invalid_token_none(self):
        assert auth.verify_session_token("not-a-token") is None
        assert auth.verify_session_token("") is None
        assert auth.verify_session_token(None) is None


class TestCSRF:
    def test_roundtrip(self):
        tok = auth.issue_csrf_token("admin")
        assert auth.verify_csrf_token(tok, "admin")

    def test_wrong_user_rejected(self):
        tok = auth.issue_csrf_token("admin")
        assert not auth.verify_csrf_token(tok, "other")

    def test_invalid_rejected(self):
        assert not auth.verify_csrf_token(None, "admin")
        assert not auth.verify_csrf_token("bad", "admin")


class TestLockout:
    def test_lock_after_threshold(self):
        auth.reset_failed("victim")
        for _ in range(auth._LOGIN_THRESHOLD):
            auth.record_failed("victim")
        assert auth.check_locked("victim")

    def test_below_threshold_not_locked(self):
        auth.reset_failed("user2")
        auth.record_failed("user2")
        assert not auth.check_locked("user2")

    def test_reset(self):
        auth.reset_failed("user3")
        for _ in range(auth._LOGIN_THRESHOLD):
            auth.record_failed("user3")
        auth.reset_failed("user3")
        assert not auth.check_locked("user3")

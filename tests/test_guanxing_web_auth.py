"""安全设计 §2.1 面板认证 — Flask 集成测试（向后兼容验证）

聚焦三点：
  1. 默认无认证 => 页面直接可访问（现状，兼容）。
  2. 启用表单认证 => 未登录重定向 /login；用错误凭据登不上；正确凭据设会话 cookie。
  3. config 注入 bcrypt 哈希凭据可正常登录。
"""

import pytest

from src.guanxing import db, web
from src.guanxing import auth


@pytest.fixture
def client_env_auth(tmp_path, monkeypatch):
    """埋环境变量凭据（明文），指向临时审计目录，复用 Flask test_client。"""
    monkeypatch.setenv("POXIAO_MONITOR_USER", "admin")
    monkeypatch.setenv("POXIAO_MONITOR_PASS", "secret123")
    monkeypatch.setenv("POXIAO_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "gx.db")
    monkeypatch.setattr(db, "_initialized", False)
    web.app.config.update(TESTING=True)
    with web.app.test_client() as c:
        yield c


@pytest.fixture
def client_config_auth(tmp_path, monkeypatch):
    """通过 set_credentials 注入 bcrypt 哈希凭据。"""
    h = auth.hash_password("my-bcrypt-pass")
    auth.set_credentials("cfgadmin", h)
    monkeypatch.setenv("POXIAO_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "gx.db")
    monkeypatch.setattr(db, "_initialized", False)
    web.app.config.update(TESTING=True)
    with web.app.test_client() as c:
        yield c
    auth.set_credentials("", None)


class TestDefaultNoAuth:
    def test_dashboard_accessible_without_credentials(self, tmp_path, monkeypatch):
        monkeypatch.delenv("POXIAO_MONITOR_USER", raising=False)
        monkeypatch.delenv("POXIAO_MONITOR_PASS", raising=False)
        monkeypatch.setattr(db, "DB_PATH", tmp_path / "gx.db")
        monkeypatch.setattr(db, "_initialized", False)
        web.app.config.update(TESTING=True)
        with web.app.test_client() as c:
            r = c.get("/")
            assert r.status_code in (200, 302)  # 无数据时仍可达，仅可能因空库重定向


class TestFormAuthEnv:
    def test_unauthenticated_redirects_to_login(self, client_env_auth):
        r = client_env_auth.get("/")
        # 表单认证启用：未登录应重定向到 /login
        assert r.status_code == 302
        assert "/login" in r.headers.get("Location", "")

    def test_login_wrong_password(self, client_env_auth):
        r = client_env_auth.post("/login", data={
            "username": "admin", "password": "wrong"
        })
        # 未带有效会话 => 重新渲染登录页（含错误提示），状态 200
        assert r.status_code == 200

    def test_login_success_sets_session_cookie(self, client_env_auth):
        r = client_env_auth.post("/login", data={
            "username": "admin", "password": "secret123"
        })
        assert r.status_code == 302
        assert r.headers.get("Location") in ("/", "http://localhost/")
        set_cookie = r.headers.get("Set-Cookie", "")
        assert "session=" in set_cookie
        # 登录后访问受保护页可通
        r2 = client_env_auth.get("/")
        assert r2.status_code == 200


class TestFormAuthConfigBcrypt:
    def test_login_bcrypt_hash(self, client_config_auth):
        r = client_config_auth.post("/login", data={
            "username": "cfgadmin", "password": "my-bcrypt-pass"
        })
        assert r.status_code == 302
        set_cookie = r.headers.get("Set-Cookie", "")
        assert "session=" in set_cookie

    def test_wrong_bcrypt_denied(self, client_config_auth):
        r = client_config_auth.post("/login", data={
            "username": "cfgadmin", "password": "wrong"
        })
        assert r.status_code == 200  # 重新渲染登录页

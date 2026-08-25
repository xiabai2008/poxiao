"""
观星 认证模块 (安全设计 §2.1 / §2.2 / §4.1)
============================================

为 GuanXing Web 面板提供**向后兼容**的表单认证 + 会话/CSRF 防护：

  * 密码哈希：bcrypt 加盐哈希（不可逆，§3.3.2 / §6.1）。
    遗留支持 scrypt 与 $5$ (sha256-crypt) 风格的 bcrypt 前缀校验，
    以便从旧 Basic Auth 平滑迁移。
  * 会话：itsdangerous（Flask 内置依赖）签名带过期时间的 session token，
    密钥取自环境变量 POXIAO_MONITOR_SECRET（未设则进程内随机，重启失效）。
  * CSRF：每会话独立 secret 的 HMAC-SHA256 令牌，表单/Header 双向校验。
  * 密码来源：优先环境变量 POXIAO_MONITOR_USER / POXIAO_MONITOR_PASS
    （兼容现状）；config.monitor.auth=false 时默认不启用完整表单流程。

设计约束（§2.1 / §4.1 / §6.3）：
  * 登录失败不泄露"用户是否存在"（统一错误提示）。
  * 密码比对使用 hmac.compare_digest / bcrypt 自带恒定时间比较，防时序攻击。
  * 任何路径不在日志/异常/响应中打印密码明文（§6.3 红线）。
"""

import hmac
import logging
import os
import secrets

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

try:  # bcrypt 可选依赖：已确认在本机可用
    import bcrypt
    _HAS_BCRYPT = True
except ImportError:  # pragma: no cover
    _HAS_BCRYPT = False


_MODULE = "guanxing.auth"
_SESSION_MAX_AGE = 12 * 3600          # 会话有效期 12h
_CSRF_COOKIE = "csrf_token"
_SESSION_COOKIE = "session"
_USER_COOKIE = "gx_user"
_LOGIN_THRESHOLD = 5                  # §2.1 5 次锁
_LOCK_SECONDS = 900                    # §2.1 锁 15 分钟

# 进程内失败计数（单进程够用；多 worker 由外部限流补充）
_failed_logins: dict = {}

# 从 config 注入的凭据（优先于环境变量；由 start_server 注入，避免 auth 依赖 config）
_config_credentials: tuple[str, str | None] = ("", None)

def set_credentials(username: str, password_or_hash: str | None) -> None:
    """从 config.monitor 注入凭据。password 可为 bcrypt 哈希或明文（兼容）。"""
    global _config_credentials
    _config_credentials = (username or "", password_or_hash or None)


def _logger() -> logging.Logger:
    """模块日志器（避免重复创建）"""
    return logging.getLogger(_MODULE)


def _master_secret() -> bytes:
    """会话签名密钥：优先环境变量，否则进程内随机（重启失效）。"""
    env = os.environ.get("POXIAO_MONITOR_SECRET", "")
    if env:
        return env.encode("utf-8")
    # 进程内稳定密钥缓存
    if not hasattr(_master_secret, "_cache"):
        _master_secret._cache = secrets.token_bytes(32)  # type: ignore[attr-defined]
    return _master_secret._cache  # type: ignore[attr-defined]


# ── 密码哈希 ────────────────────────────────────────

def hash_password(password: str) -> str:
    """bcrypt 加盐哈希（优先）或 scrypt 兜底，返回可存储的字符串。"""
    if _HAS_BCRYPT:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
    # fallback: scrypt (自带)
    salt = os.urandom(16)
    dk = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1).derive(password.encode("utf-8"))
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    """恒定时间校验密码。

    Args:
        password: 明文密码（仅内存使用，不落盘/不进日志）。
        stored: 存储的哈希。支持：bcrypt、scrypt、$5$(sha256-crypt，向后兼容)。
    """
    if not stored:
        return False
    try:
        if _HAS_BCRYPT and stored.startswith("$2"):
            # bcrypt 自带恒定时间比较
            return bcrypt.checkpw(password.encode("utf-8"), stored.encode("utf-8"))
        if stored.startswith("scrypt$"):
            _, salt_hex, dk_hex = stored.split("$", 2)
            salt = bytes.fromhex(salt_hex)
            dk = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1).derive(password.encode("utf-8"))
            return hmac.compare_digest(dk, bytes.fromhex(dk_hex))
        # 兼容 sha256-crypt 风格
        return _verify_sha256crypt(password, stored)
    except Exception:
        return False


def _verify_sha256crypt(password: str, stored: str) -> bool:
    """sha256-crypt ($5$) 兼容校验（避免升级后无法登录旧配置）。"""
    if not stored.startswith("$5$"):
        return False
    import hashlib
    parts = stored.split("$")
    if len(parts) < 4 or not parts[1] or not parts[2]:
        return False
    digest = hashlib.sha256((parts[2] + password).encode("utf-8")).hexdigest()
    return hmac.compare_digest(digest, parts[3] if len(parts) > 3 else "")


def normalize_password_fmt(raw: str) -> bool:
    """判断是否需要哈希化：非哈希原文（长度>60 视为已哈希）。"""
    return len(raw) <= 60


# ── 登录凭证来源（兼容现状）────────────────────────

def get_credentials() -> tuple[str, str | None]:
    """返回 (username, password_hash 或明文)。

    来源优先级：config 注入（set_credentials，bcrypt 哈希可支持）> 环境变量。
    """
    cfg_user, cfg_pw = _config_credentials
    if cfg_user:
        return cfg_user, cfg_pw
    user = os.environ.get("POXIAO_MONITOR_USER", "")
    pass_ = os.environ.get("POXIAO_MONITOR_PASS", "")
    return user, pass_ or None


def auth_enabled() -> bool:
    """是否启用认证（存在任一凭据即视为需要认证）。"""
    user, _ = get_credentials()
    return bool(user)


# ── 会话 Token ─────────────────────────────────────

def _serializer() -> URLSafeTimedSerializer:
    """登录令牌序列化器（itsdangerous）"""
    return URLSafeTimedSerializer(_master_secret(), salt="gx-session")


def _csrf_serializer() -> URLSafeTimedSerializer:
    """CSRF 令牌序列化器"""
    return URLSafeTimedSerializer(_master_secret(), salt="gx-csrf")


def issue_session_token(username: str) -> str:
    """签发会话 token（itsdangerous 签名 + 过期时间）。"""
    return _serializer().dumps({"user": username})


def verify_session_token(token: str | None) -> str | None:
    """校验会话 token，返回 username 或 None（无效/过期）。"""
    if not token:
        return None
    try:
        data = _serializer().loads(token, max_age=_SESSION_MAX_AGE)
        return data.get("user")
    except (BadSignature, SignatureExpired):
        return None


def issue_csrf_token(username: str) -> str:
    """签发绑定用户的 CSRF 令牌。"""
    return _csrf_serializer().dumps({"user": username})


def verify_csrf_token(token: str | None, username: str) -> bool:
    """校验 CSRF 令牌是否对应当前会话用户。"""
    if not token or not username:
        return False
    try:
        data = _csrf_serializer().loads(token, max_age=12 * 3600)
        return hmac.compare_digest(str(data.get("user")), username)
    except (BadSignature, SignatureExpired):
        return False


# ── 失败锁定（§2.1 / A07）──────────────────────────

def check_locked(username: str) -> bool:
    """是否已因连续失败被锁定。"""
    rec = _failed_logins.get(username)
    if not rec:
        return False
    count, locked_until = rec
    if locked_until and locked_until > time_now():
        return True
    if locked_until and locked_until <= time_now():
        _failed_logins[username] = (count, 0)
        return False
    return count >= _LOGIN_THRESHOLD


def record_failed(username: str) -> None:
    """记录一次失败；达到阈值即锁定。# noqa: E501"""
    count, _ = _failed_logins.get(username, (0, 0))
    count += 1
    locked_until = time_now() + _LOCK_SECONDS if count >= _LOGIN_THRESHOLD else 0
    _failed_logins[username] = (count, locked_until)


def reset_failed(username: str) -> None:
    """登录成功后清零失败记录。"""
    _failed_logins.pop(username, None)


def time_now() -> float:
    """当前 UTC 时间（datetime 对象）"""
    import time
    return time.time()

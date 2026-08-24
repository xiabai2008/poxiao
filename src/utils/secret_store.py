"""
破晓 密钥加密存储模块 (安全设计 §6.2 / §6.3)
============================================

L4 高敏数据（E-xx API Key / Token / 密码）本地等价 KMS：
  * AES-256-GCM 加密后落盘，磁盘上不存明文（方案 A，§6.2.1）
  * 加密密钥由用户主密码经 PBKDF2-HMAC-SHA256 派生（scrypt 类口令硬化）
  * 每次加密使用随机 nonce（NewNonce），GCM 提供认证（防篡改)

设计约束：
  * 向后兼容：未设置主密码 / 未启用加密时，读回原始明文（兼容明文 YAML 旧配置）
  * 禁止密钥明文出现在日志 / 异常 / URL / 错误堆栈（§6.3）
  * 不引入新运行时依赖：复用 `cryptography`（已在 pyproject dependencies 中）
"""

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# PBKDF2 硬化参数（OWASP 建议 ≥ 600k 迭代，本机可接受；兼顾启动速度）
_ITERATIONS = 600_000
_KEY_LEN = 32  # AES-256
_NONCE_LEN = 12  # GCM 标准 96-bit nonce

# 密文格式前缀：`enc:v1:<salt_b64>:<nonce_b64>:<ct_b64>`
_PREFIX = "enc:v1:"


def _validate_master(master: str) -> str:
    """校验主密码强度，返回原值。"""
    if not master:
        raise ValueError("主密码不能为空")
    if len(master) < 8:
        raise ValueError("主密码过短：至少 8 位（建议 ≥ 12 位，见安全设计 §2.1.2）")
    return master


def derive_key(master: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 从主密码派生 AES-256 密钥。"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=salt,
        iterations=_ITERATIONS,
    )
    return kdf.derive(master.encode("utf-8"))


def _is_encrypted(value: str) -> bool:
    """判断给定值是否已是本模块加密格式。"""
    return value.startswith(_PREFIX)


def encrypt_secret(plaintext: str, master: str) -> str:
    """用主密码加密明文，返回 `enc:v1:...` 格式字符串（base64 安全存储）。

    Args:
        plaintext: 待加密的密钥明文。
        master: 用户主密码。

    Returns:
        可安全写入 YAML/JSON 的密文字符串。

    Raises:
        ValueError: 主密码强度不足。
    """
    _validate_master(master)
    salt = os.urandom(16)
    nonce = os.urandom(_NONCE_LEN)
    key = derive_key(master, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return "{}{}:{}:{}".format(
        _PREFIX,
        base64.b64encode(salt).decode(),
        base64.b64encode(nonce).decode(),
        base64.b64encode(ct).decode(),
    )


def decrypt_secret(stored: str, master: str) -> str:
    """解密 `enc:v1:...` 密文。

    Args:
        stored: encrypt_secret 产出的密文字符串。
        master: 与加密时相同的主密码。

    Returns:
        明文密钥。

    Raises:
        ValueError: 格式非法 / 主密码错误（GCM 认证失败 / 迭代参数不匹配）。
    """
    if not stored.startswith(_PREFIX):
        raise ValueError("非加密格式，无法解密")
    try:
        # 去掉 `enc:v1:` 前缀后，剩余 `salt:nonce:ct` 用 2 次分割
        body = stored[len(_PREFIX):]
        salt_b64, nonce_b64, ct_b64 = body.split(":", 2)
        salt = base64.b64decode(salt_b64)
        nonce = base64.b64decode(nonce_b64)
        ct = base64.b64decode(ct_b64)
    except (ValueError, TypeError) as e:
        raise ValueError("密文格式非法") from e

    key = derive_key(master, salt)
    try:
        pt = AESGCM(key).decrypt(nonce, ct, None)
    except InvalidTag as e:
        # 主密码错误或密文被篡改。异常信息不携带任何密钥相关内容（§6.3）。
        raise ValueError("解密失败：主密码错误或密文被篡改") from e
    return pt.decode("utf-8")


# ── 配置集成：读写可加密字段 ──────────────────────────

# 配置中视为 L4 高敏、需加密落盘的字段（section -> key）
SENSITIVE_FIELDS = {
    "cve": ["nvd_api_key"],
    "recon": ["shodan_api_key", "fofa_key", "fofa_email"],
}


def encrypt_config_value(section: str, key: str, plaintext: str) -> bool:
    """判断某配置字段是否需要加密；需要则返回 True（由调用方决定落盘方式）。

    纯判断工具，供 config 模块决定是否调用 encrypt_secret。
    """
    return (section in SENSITIVE_FIELDS and key in SENSITIVE_FIELDS[section] and bool(plaintext))

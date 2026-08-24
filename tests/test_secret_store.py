"""安全设计 §6.2 API Key 加密落盘 — 单元测试"""

import pytest

from src.utils import secret_store


class TestEncryptRoundtrip:
    def test_roundtrip(self):
        enc = secret_store.encrypt_secret("sk-live-abc123", "correct-horse-battery")
        assert enc.startswith("enc:v1:")
        assert "sk-live-abc123" not in enc  # 磁盘不存明文
        assert secret_store.decrypt_secret(enc, "correct-horse-battery") == "sk-live-abc123"

    def test_same_plaintext_same_master_different_ciphertext(self):
        """同一明文 + 同一主密码，两次加密的 nonce 随机 => 密文不同（GCM 防重放）"""
        a = secret_store.encrypt_secret("same-key", "master-pass")
        b = secret_store.encrypt_secret("same-key", "master-pass")
        assert a != b

    def test_wrong_master_raises(self):
        enc = secret_store.encrypt_secret("secret-value", "master-pass")
        with pytest.raises(ValueError):
            secret_store.decrypt_secret(enc, "wrong-master")


class TestValidation:
    def test_empty_master_rejected(self):
        with pytest.raises(ValueError):
            secret_store.encrypt_secret("k", "")

    def test_short_master_rejected(self):
        with pytest.raises(ValueError):
            secret_store.encrypt_secret("k", "short")

    def test_decrypt_non_encrypted_raises(self):
        with pytest.raises(ValueError):
            secret_store.decrypt_secret("plaintext", "master-pass")

    def test_is_encrypted_detect(self):
        enc = secret_store.encrypt_secret("k", "master-pass")
        assert secret_store._is_encrypted(enc)
        assert not secret_store._is_encrypted("plain")


class TestSensitiveFieldsMap:
    def test_map_contains_l4_keys(self):
        assert "nvd_api_key" in secret_store.SENSITIVE_FIELDS["cve"]
        assert "shodan_api_key" in secret_store.SENSITIVE_FIELDS["recon"]
        assert "fofa_key" in secret_store.SENSITIVE_FIELDS["recon"]

    def test_encrypt_config_value_decision(self):
        assert secret_store.encrypt_config_value("recon", "shodan_api_key", "xxx")
        assert not secret_store.encrypt_config_value("scan", "timeout", "5")

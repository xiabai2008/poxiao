"""编解码工具测试"""

import pytest
from src.utils.crypto_tools import (
    base64_encode, base64_decode,
    base32_encode, base32_decode,
    hex_encode, hex_decode,
    url_encode, url_decode,
    html_encode, html_decode,
    unicode_encode, unicode_decode,
    rot13_encode, rot13_decode,
    morse_encode, morse_decode,
    md5_hash, sha1_hash, sha256_hash, sha512_hash,
    jwt_decode, jwt_encode,
    auto_decode,
)


class TestBase64:
    """Base64 编解码测试"""

    def test_encode_ascii(self):
        assert base64_encode("hello") == "aGVsbG8="

    def test_decode_ascii(self):
        assert base64_decode("aGVsbG8=") == "hello"

    def test_roundtrip(self):
        original = "破晓测试中文"
        assert base64_decode(base64_encode(original)) == original

    def test_empty_string(self):
        assert base64_encode("") == ""
        assert base64_decode("") == ""

    def test_special_chars(self):
        original = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        assert base64_decode(base64_encode(original)) == original


class TestBase32:
    """Base32 编解码测试"""

    def test_encode(self):
        result = base32_encode("hello")
        assert result == "NBSWY3DP"

    def test_decode(self):
        assert base32_decode("NBSWY3DP") == "hello"

    def test_roundtrip(self):
        original = "test123"
        assert base32_decode(base32_encode(original)) == original


class TestHex:
    """Hex 编解码测试"""

    def test_encode(self):
        assert hex_encode("hello") == "68656c6c6f"

    def test_decode(self):
        assert hex_decode("68656c6c6f") == "hello"

    def test_roundtrip(self):
        original = "破晓"
        assert hex_decode(hex_encode(original)) == original


class TestURL:
    """URL 编解码测试"""

    def test_encode(self):
        assert url_encode("<script>") == "%3Cscript%3E"

    def test_decode(self):
        assert url_decode("%3Cscript%3E") == "<script>"

    def test_roundtrip(self):
        original = "hello world&foo=bar"
        assert url_decode(url_encode(original)) == original


class TestHTML:
    """HTML 编解码测试"""

    def test_encode(self):
        assert html_encode("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"

    def test_decode(self):
        assert html_decode("&lt;script&gt;") == "<script>"


class TestROT13:
    """ROT13 编解码测试"""

    def test_encode(self):
        assert rot13_encode("hello") == "uryyb"

    def test_decode(self):
        assert rot13_decode("uryyb") == "hello"

    def test_symmetric(self):
        """ROT13 是对称的"""
        original = "Hello World"
        assert rot13_decode(rot13_encode(original)) == original


class TestMorse:
    """Morse 编解码测试"""

    def test_encode(self):
        result = morse_encode("SOS")
        assert result == "... --- ..."

    def test_decode(self):
        assert morse_decode("... --- ...") == "SOS"

    def test_roundtrip(self):
        original = "HELLO"
        assert morse_decode(morse_encode(original)) == original


class TestHash:
    """哈希测试"""

    def test_md5(self):
        assert md5_hash("hello") == "5d41402abc4b2a76b9719d911017c592"

    def test_sha1(self):
        assert sha1_hash("hello") == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"

    def test_sha256(self):
        assert sha256_hash("hello") == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_sha512(self):
        result = sha512_hash("hello")
        assert len(result) == 128  # SHA512 输出 128 个十六进制字符

    def test_different_inputs(self):
        assert md5_hash("hello") != md5_hash("world")


class TestJWT:
    """JWT 编解码测试"""

    def test_decode(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = jwt_decode(token)
        assert result["payload"]["sub"] == "1234567890"
        assert result["payload"]["name"] == "John Doe"

    def test_encode_decode(self):
        payload = {"sub": "123", "name": "test"}
        token = jwt_encode(payload)
        result = jwt_decode(token)
        assert result["payload"]["sub"] == "123"
        assert result["payload"]["name"] == "test"


class TestAutoDecode:
    """自动识别测试"""

    def test_detect_base64(self):
        results = auto_decode("aGVsbG8=")
        assert len(results) > 0
        assert any(r[0] == "base64" for r in results)

    def test_detect_hex(self):
        results = auto_decode("68656c6c6f")
        assert len(results) > 0
        assert any(r[0] == "hex" for r in results)

    def test_detect_url(self):
        results = auto_decode("%3Cscript%3E")
        assert len(results) > 0
        assert any(r[0] == "url" for r in results)

    def test_detect_jwt(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        results = auto_decode(token)
        assert len(results) > 0
        assert any(r[0] == "jwt" for r in results)

    def test_no_match(self):
        results = auto_decode("this is plain text")
        # 可能匹配 ROT13，但不应该有 base64/hex/url
        assert not any(r[0] in ("base64", "hex", "url") for r in results)

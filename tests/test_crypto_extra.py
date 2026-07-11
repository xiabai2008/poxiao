"""编解码工具 — 补充覆盖（base58 / url全量 / html实体 / unicode / caesar / auto_decode 分支 / list_operations）"""

import pytest

from src.utils.crypto_tools import (
    base58_encode, base58_decode,
    url_encode_full, double_url_encode, url_decode,
    html_entity_encode, html_entity_decode,
    unicode_encode, unicode_decode,
    caesar_encode, caesar_decode,
    auto_decode, list_operations, jwt_decode,
)


class TestBase58:
    def test_encode(self):
        assert base58_encode("hello") != ""

    def test_decode(self):
        enc = base58_encode("hello")
        assert base58_decode(enc) == "hello"

    def test_roundtrip_unicode(self):
        enc = base58_encode("破晓")
        assert base58_decode(enc) == "破晓"


class TestUrlFull:
    def test_url_encode_full(self):
        # 全量编码连安全字符也编码
        assert url_encode_full("a b") != "a b"

    def test_double_url(self):
        enc = double_url_encode("a")
        dec = url_decode(url_decode(enc))
        assert dec == "a"


class TestHtmlEntity:
    def test_encode(self):
        assert html_entity_encode("A") == "&#65;"

    def test_decode_dec(self):
        assert html_entity_decode("&#65;") == "A"

    def test_decode_hex(self):
        assert html_entity_decode("&#x41;") == "A"

    def test_decode_named(self):
        assert html_entity_decode("&lt;") == "<"


class TestUnicode:
    def test_encode_non_ascii(self):
        assert unicode_encode("中") == "\\u4e2d"

    def test_encode_ascii_passthrough(self):
        assert unicode_encode("a") == "a"

    def test_decode(self):
        assert unicode_decode("\\u4e2d") == "中"


class TestCaesar:
    def test_encode(self):
        assert caesar_encode("abc") == "def"

    def test_decode(self):
        assert caesar_decode("def") == "abc"

    def test_roundtrip(self):
        assert caesar_decode(caesar_encode("Hello", 5), 5) == "Hello"


class TestAutoDecodeBranches:
    def test_base32(self):
        from src.utils.crypto_tools import base32_encode
        results = auto_decode(base32_encode("hello"))
        assert any(r[0] == "base32" for r in results)

    def test_url(self):
        results = auto_decode("%3Cscript%3E")
        assert any(r[0] == "url" for r in results)

    def test_html_entity(self):
        results = auto_decode("&lt;script&gt;")
        assert any(r[0] == "html_entity" for r in results)

    def test_unicode_escape(self):
        results = auto_decode("\\u4e2d")
        assert any(r[0] == "unicode" for r in results)

    def test_rot13_with_common_word(self):
        # "frperg" 是 "secret" 的 ROT13，含常见词
        results = auto_decode("frperg")
        assert any(r[0] == "rot13" for r in results)

    def test_morse(self):
        results = auto_decode("... --- ...")
        assert any(r[0] == "morse" for r in results)

    def test_double_url(self):
        results = auto_decode("%252F")
        assert any(r[0] == "double_url" for r in results)

    def test_jwt(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNa6_c3-Fx44qBH7KOhiTQGnKGaU"
        results = auto_decode(token)
        assert any(r[0] == "jwt" for r in results)


class TestJwtDecodeErrors:
    def test_invalid_format(self):
        assert jwt_decode("not-a-jwt") == {"error": "Invalid JWT format"}

    def test_bad_header(self):
        res = jwt_decode("!!!.payload")
        assert "error" in res["header"]


class TestListOperations:
    def test_returns_all(self):
        ops = list_operations()
        names = {o["name"] for o in ops}
        assert "base64" in names
        assert "md5" in names
        # 哈希操作无解码器
        md5_op = next(o for o in ops if o["name"] == "md5")
        assert md5_op["has_decode"] is False
        # 编解码操作有解码器
        b64_op = next(o for o in ops if o["name"] == "base64")
        assert b64_op["has_decode"] is True

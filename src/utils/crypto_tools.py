"""
编解码 / 加解密工具集
=====================
29 种操作，挖洞时直接调用

支持:
  编解码: base64, base32, base58, hex, url, html, unicode, rot13, caesar, morse
  哈希:   md5, sha1, sha256, sha512
  加解密: aes_encrypt, aes_decrypt
  JWT:    jwt_decode, jwt_encode
  识别:   auto_decode (自动识别编码类型)

CLI:
  poxiao util encode base64 "hello"
  poxiao util decode hex "68656c6c6f"
  poxiao util hash md5 "hello"
  poxiao util jwt-decode "eyJ..."
  poxiao util auto "aGVsbG8="
"""

import base64
import binascii
import hashlib
import html
import json
import re
import string
import urllib.parse
from typing import Optional, Tuple


# ── Base 系列 ────────────────────────────────────────

def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode()).decode()

def base64_decode(text: str) -> str:
    # 补齐 padding
    text = text.strip()
    padding = 4 - len(text) % 4
    if padding != 4:
        text += "=" * padding
    return base64.b64decode(text).decode(errors="ignore")

def base32_encode(text: str) -> str:
    return base64.b32encode(text.encode()).decode()

def base32_decode(text: str) -> str:
    text = text.strip().upper()
    padding = 8 - len(text) % 8
    if padding != 8:
        text += "=" * padding
    return base64.b32decode(text).decode(errors="ignore")

def base58_encode(text: str) -> str:
    """Base58 编码 (Bitcoin 风格)"""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(text.encode(), "big")
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(alphabet[r])
    # 处理前导零字节
    for byte in text.encode():
        if byte == 0:
            result.append(alphabet[0])
        else:
            break
    return "".join(reversed(result))

def base58_decode(text: str) -> str:
    """Base58 解码"""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for char in text:
        n = n * 58 + alphabet.index(char)
    # 转回 bytes
    result = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    # 处理前导 '1'
    leading = 0
    for char in text:
        if char == "1":
            leading += 1
        else:
            break
    result = b"\x00" * leading + result
    return result.decode(errors="ignore")


# ── Hex ──────────────────────────────────────────────

def hex_encode(text: str) -> str:
    return text.encode().hex()

def hex_decode(text: str) -> str:
    text = text.strip().replace(" ", "").replace("0x", "")
    return bytes.fromhex(text).decode(errors="ignore")


# ── URL 编码 ─────────────────────────────────────────

def url_encode(text: str) -> str:
    return urllib.parse.quote(text, safe="")

def url_decode(text: str) -> str:
    return urllib.parse.unquote(text)

def url_encode_full(text: str) -> str:
    """全量 URL 编码 (包括 safe 字符)"""
    return urllib.parse.quote(text, safe="")

def double_url_encode(text: str) -> str:
    """双重 URL 编码"""
    return urllib.parse.quote(urllib.parse.quote(text, safe=""), safe="")


# ── HTML 编码 ────────────────────────────────────────

def html_encode(text: str) -> str:
    return html.escape(text)

def html_decode(text: str) -> str:
    return html.unescape(text)

def html_entity_encode(text: str) -> str:
    """HTML 实体编码 (十进制)"""
    return "".join(f"&#{ord(c)};" for c in text)

def html_entity_decode(text: str) -> str:
    """HTML 实体解码"""
    def replace_entity(match):
        entity = match.group(0)
        if entity.startswith("&#x"):
            return chr(int(entity[3:-1], 16))
        elif entity.startswith("&#"):
            return chr(int(entity[2:-1]))
        return html.unescape(entity)
    return re.sub(r"&[#\w]+;", replace_entity, text)


# ── Unicode ──────────────────────────────────────────

def unicode_encode(text: str) -> str:
    """Unicode 转义序列"""
    return "".join(f"\\u{ord(c):04x}" if ord(c) > 127 else c for c in text)

def unicode_decode(text: str) -> str:
    """Unicode 转义序列解码"""
    return text.encode().decode("unicode_escape")


# ── ROT13 / Caesar ───────────────────────────────────

def rot13_encode(text: str) -> str:
    """ROT13 编码"""
    result = []
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            result.append(chr((ord(c) - base + 13) % 26 + base))
        else:
            result.append(c)
    return "".join(result)

# ROT13 decode = encode (对称)
rot13_decode = rot13_encode

def caesar_encode(text: str, shift: int = 3) -> str:
    """凯撒密码"""
    result = []
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    return "".join(result)

def caesar_decode(text: str, shift: int = 3) -> str:
    return caesar_encode(text, -shift)


# ── Morse ────────────────────────────────────────────

MORSE_CODE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..",
    "!": "-.-.--", "/": "-..-.", "(": "-.--.", ")": "-.--.-", "&": ".-...",
    ":": "---...", ";": "-.-.-.", "=": "-...-", "+": ".-.-.", "-": "-....-",
    "_": "..--.-", '"': ".-..-.", "$": "...-..-", "@": ".--.-.",
}
MORSE_DECODE = {v: k for k, v in MORSE_CODE.items()}

def morse_encode(text: str) -> str:
    words = text.upper().split()
    return " / ".join(
        " ".join(MORSE_CODE.get(c, c) for c in word)
        for word in words
    )

def morse_decode(text: str) -> str:
    words = text.split(" / ")
    return " ".join(
        "".join(MORSE_DECODE.get(c, c) for c in word.split())
        for word in words
    )


# ── 哈希 ─────────────────────────────────────────────

def md5_hash(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()

def sha1_hash(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()

def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def sha512_hash(text: str) -> str:
    return hashlib.sha512(text.encode()).hexdigest()


# ── JWT ──────────────────────────────────────────────

def jwt_decode(token: str) -> dict:
    """JWT 解码 (不验证签名)"""
    token = token.strip()
    parts = token.split(".")
    if len(parts) < 2:
        return {"error": "Invalid JWT format"}

    # 解码 header
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    except Exception:
        header = {"error": "Cannot decode header"}

    # 解码 payload
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    except Exception:
        payload = {"error": "Cannot decode payload"}

    return {"header": header, "payload": payload}

def jwt_encode(payload: dict, header: dict = None, secret: str = "secret") -> str:
    """JWT 编码 (使用 HS256)"""
    import hmac
    import struct

    if header is None:
        header = {"alg": "HS256", "typ": "JWT"}

    # Encode header
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

    # Encode payload
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

    # Sign
    message = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        secret.encode(), message.encode(), hashlib.sha256
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ── AES (简化版，需安装 pycryptodome) ────────────────

def aes_encrypt_cbc(plaintext: str, key: str, iv: str = None) -> str:
    """AES-CBC 加密"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
    except ImportError:
        return "[ERROR] pip install pycryptodome"

    key_bytes = key.encode()[:16].ljust(16, b"\0")
    iv_bytes = (iv or key[:16]).encode()[:16].ljust(16, b"\0")
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(ct).decode()

def aes_decrypt_cbc(ciphertext: str, key: str, iv: str = None) -> str:
    """AES-CBC 解密"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except ImportError:
        return "[ERROR] pip install pycryptodome"

    key_bytes = key.encode()[:16].ljust(16, b"\0")
    iv_bytes = (iv or key[:16]).encode()[:16].ljust(16, b"\0")
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    pt = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return pt.decode(errors="ignore")


# ── 自动识别 ─────────────────────────────────────────

def auto_decode(text: str) -> list:
    """
    自动识别编码类型并解码

    Returns:
        list of (type, decoded_text, confidence)
    """
    results = []
    text = text.strip()

    # 1. Base64
    if re.match(r'^[A-Za-z0-9+/]+=*$', text) and len(text) >= 4:
        try:
            decoded = base64.b64decode(text + "==").decode(errors="ignore")
            if decoded.isprintable():
                results.append(("base64", decoded, "high"))
        except Exception:
            pass

    # 2. Base32
    if re.match(r'^[A-Z2-7]+=*$', text) and len(text) >= 8:
        try:
            decoded = base64.b32decode(text).decode(errors="ignore")
            if decoded.isprintable():
                results.append(("base32", decoded, "high"))
        except Exception:
            pass

    # 3. Hex
    if re.match(r'^(0x)?[0-9a-fA-F]+$', text) and len(text) >= 2:
        try:
            hex_str = text.replace("0x", "")
            if len(hex_str) % 2 == 0:
                decoded = bytes.fromhex(hex_str).decode(errors="ignore")
                if decoded.isprintable():
                    results.append(("hex", decoded, "high"))
        except Exception:
            pass

    # 4. URL 编码
    if "%" in text:
        try:
            decoded = urllib.parse.unquote(text)
            if decoded != text:
                results.append(("url", decoded, "high"))
        except Exception:
            pass

    # 5. HTML 实体
    if "&#" in text or "&amp;" in text or "&lt;" in text:
        try:
            decoded = html.unescape(text)
            if decoded != text:
                results.append(("html_entity", decoded, "high"))
        except Exception:
            pass

    # 6. Unicode 转义
    if "\\u" in text:
        try:
            decoded = text.encode().decode("unicode_escape")
            if decoded != text:
                results.append(("unicode", decoded, "high"))
        except Exception:
            pass

    # 7. ROT13
    decoded = rot13_encode(text)
    if decoded != text and any(c.isalpha() for c in decoded):
        # 检查是否包含常见英文单词
        common = ["the", "is", "flag", "admin", "password", "secret", "key"]
        if any(w in decoded.lower() for w in common):
            results.append(("rot13", decoded, "medium"))

    # 8. Morse
    if re.match(r'^[.\-/ ]+$', text):
        decoded = morse_decode(text)
        if decoded and any(c.isalpha() for c in decoded):
            results.append(("morse", decoded, "high"))

    # 9. JWT
    if text.count(".") == 2:
        parts = text.split(".")
        if all(re.match(r'^[A-Za-z0-9_\-]+=*$', p) for p in parts):
            try:
                decoded = jwt_decode(text)
                if "error" not in decoded.get("payload", {}):
                    results.append(("jwt", json.dumps(decoded["payload"], indent=2), "high"))
            except Exception:
                pass

    # 10. Double URL 编码
    if "%25" in text:
        try:
            decoded = urllib.parse.unquote(urllib.parse.unquote(text))
            if decoded != text:
                results.append(("double_url", decoded, "medium"))
        except Exception:
            pass

    return results


# ── 操作注册表 ───────────────────────────────────────

OPERATIONS = {
    # 编码
    "base64":     (base64_encode, base64_decode),
    "base32":     (base32_encode, base32_decode),
    "base58":     (base58_encode, base58_decode),
    "hex":        (hex_encode, hex_decode),
    "url":        (url_encode, url_decode),
    "url-full":   (url_encode_full, url_decode),
    "double-url": (double_url_encode, url_decode),
    "html":       (html_encode, html_decode),
    "html-entity": (html_entity_encode, html_entity_decode),
    "unicode":    (unicode_encode, unicode_decode),
    "rot13":      (rot13_encode, rot13_decode),
    "morse":      (morse_encode, morse_decode),
    # 哈希
    "md5":        (md5_hash, None),
    "sha1":       (sha1_hash, None),
    "sha256":     (sha256_hash, None),
    "sha512":     (sha512_hash, None),
    # 加解密
    "aes":        (aes_encrypt_cbc, aes_decrypt_cbc),
    # JWT
    "jwt":        (jwt_encode, jwt_decode),
}

def list_operations() -> list:
    """列出所有支持的操作"""
    ops = []
    for name, (enc, dec) in OPERATIONS.items():
        ops.append({
            "name": name,
            "has_encode": enc is not None,
            "has_decode": dec is not None,
        })
    return ops

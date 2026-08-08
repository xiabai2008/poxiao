"""模板 ECDSA 签名 / 校验（P1-C：防供应链投毒，对齐 nuclei 模板签名模型）

设计：
- ECDSA P-256 + SHA-256（cryptography 库；未安装时签名/校验给出明确错误）。
- 签名对象 = 模板文件的**原始字节**（确定性，改动即失效）。
- 签名清单 = 模板目录下 `.signatures.json`：{相对路径: hex 签名}。
- 引擎侧校验为**可选**（默认关闭，守"模板即数据"向后兼容）；
  启用后未签名/签名不匹配的模板被跳过并计数告警。

用法（tools/template_sync.py）:
  python tools/template_sync.py genkey private.pem public.pem
  python tools/template_sync.py sign templates --key private.pem
  python tools/template_sync.py verify templates --key public.pem
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    HAS_CRYPTO = False

SIG_FILENAME = ".signatures.json"


def _require_crypto():
    if not HAS_CRYPTO:  # pragma: no cover
        raise RuntimeError(
            "模板签名需要 cryptography 库: pip install cryptography"
            "（可选依赖，不影响模板加载与扫描）"
        )


# ── 密钥 ─────────────────────────────────────────────

def generate_keypair(private_path: str, public_path: str) -> Tuple[str, str]:
    """生成 ECDSA P-256 密钥对，写入 PEM 文件；返回 (私钥路径, 公钥路径)"""
    _require_crypto()
    private_key = ec.generate_private_key(ec.SECP256R1())
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(private_path).write_bytes(priv_pem)
    Path(public_path).write_bytes(pub_pem)
    return private_path, public_path


def _load_private_key(pem_path: str):
    _require_crypto()
    return serialization.load_pem_private_key(Path(pem_path).read_bytes(), password=None)


def _load_public_key(pem_path: str):
    _require_crypto()
    return serialization.load_pem_public_key(Path(pem_path).read_bytes())


# ── 单文件签名 / 校验 ────────────────────────────────

def sign_file(yaml_path: Path, private_pem_path: str) -> str:
    """签名单个模板文件（原始字节），返回 hex 签名"""
    _require_crypto()
    key = _load_private_key(private_pem_path)
    data = yaml_path.read_bytes()
    signature = key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature.hex()


def verify_file(yaml_path: Path, signature_hex: str, public_pem_path: str) -> bool:
    """校验单个模板文件签名；格式错误/密钥不符返回 False（不抛异常）"""
    if not HAS_CRYPTO:  # pragma: no cover
        return False
    try:
        key = _load_public_key(public_pem_path)
        data = yaml_path.read_bytes()
        signature = bytes.fromhex(signature_hex)
        key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, OSError):
        return False


# ── 目录级签名清单 ───────────────────────────────────

def _iter_yaml_files(directory: Path) -> List[Path]:
    return sorted(p for p in directory.rglob("*.yaml") if p.is_file())


def _sig_manifest_path(templates_dir: Path) -> Path:
    return templates_dir / SIG_FILENAME


def sign_directory(templates_dir: Path, private_pem_path: str,
                   output: str = "") -> Dict[str, str]:
    """为目录下所有模板生成签名清单 `.signatures.json`；返回 {相对路径: 签名}"""
    _require_crypto()
    key = _load_private_key(private_pem_path)
    manifest: Dict[str, str] = {}
    for yml in _iter_yaml_files(templates_dir):
        rel = yml.relative_to(templates_dir).as_posix()
        manifest[rel] = key.sign(yml.read_bytes(), ec.ECDSA(hashes.SHA256())).hex()

    out_path = Path(output) if output else _sig_manifest_path(templates_dir)
    out_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return manifest


def verify_directory(templates_dir: Path, public_pem_path: str,
                     manifest_path: str = "") -> Dict[str, str]:
    """校验目录模板签名；返回 {相对路径: ok|bad|unsigned}

    - ok:      签名匹配
    - bad:     签名存在但不匹配（文件被篡改）→ 应拒绝加载
    - unsigned:无签名记录 → 是否拒绝由调用方策略决定
    """
    if not HAS_CRYPTO:  # pragma: no cover
        return {}
    mpath = Path(manifest_path) if manifest_path else _sig_manifest_path(templates_dir)
    if not mpath.exists():
        return {}
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}

    key = _load_public_key(public_pem_path)
    result: Dict[str, str] = {}
    for yml in _iter_yaml_files(templates_dir):
        rel = yml.relative_to(templates_dir).as_posix()
        sig_hex = manifest.get(rel)
        if not sig_hex:
            result[rel] = "unsigned"
            continue
        try:
            key.verify(bytes.fromhex(sig_hex), yml.read_bytes(), ec.ECDSA(hashes.SHA256()))
            result[rel] = "ok"
        except (InvalidSignature, ValueError, OSError):
            result[rel] = "bad"
    return result

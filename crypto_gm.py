"""国密加解密：SM3 密钥派生 + SM4-CBC 加密。

设计说明：
- 密码管理器必须能解密回填登录，因此使用可逆的 SM4，而不是单向哈希。
- 主密码绝不落盘；磁盘仅保存随机盐 + SM3 校验值。
- 无正确主密码时，密文无法在合理时间内还原（强度取决于主密码）。
- 算法：国密 SM3（派生/校验）+ 国密 SM4-CBC（字段加密）。
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
from typing import Optional

from gmssl import func, sm3
from gmssl.sm4 import CryptSM4, SM4_DECRYPT, SM4_ENCRYPT

CIPHER_PREFIX = "GM1:"  # SM3-KDF + SM4-CBC
# 纯 Python SM3 较慢；4000 次约 1 秒出头，兼顾强度与启动体验
# 已建库仍使用库内保存的 kdf_iterations，不受此默认值影响
KDF_ITERATIONS = 4_000


def _sm3_hex(data: bytes) -> str:
    return sm3.sm3_hash(func.bytes_to_list(data))


def sm3_digest(data: bytes) -> bytes:
    return bytes.fromhex(_sm3_hex(data))


def derive_sm4_key(master_password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """SM3 多轮派生 → 16 字节 SM4 密钥。密钥仅存在内存中。"""
    if not master_password:
        raise ValueError("主密码不能为空")
    block = sm3_digest(master_password.encode("utf-8") + b"|" + salt + b"|gm-vault")
    for i in range(1, iterations):
        block = sm3_digest(block + salt + i.to_bytes(4, "big"))
    return block[:16]


def verifier_from_key(key: bytes, salt: bytes) -> str:
    """由派生密钥生成不可逆校验值（不再二次派生）。"""
    v = sm3_digest(key + salt + b"|verify|\xe8\xb4\xa6\xe6\x88\xb7\xe4\xbf\x9d\xe9\x99\xa9\xe6\x9f\x9c")
    return base64.b64encode(v).decode("ascii")


def make_password_verifier(master_password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> str:
    """不可逆校验：验证主密码，无法反推主密码或 SM4 密钥。"""
    key = derive_sm4_key(master_password, salt, iterations)
    return verifier_from_key(key, salt)


def unlock_with_password(
    master_password: str,
    salt: bytes,
    verifier_b64: str,
    iterations: int = KDF_ITERATIONS,
) -> bytes:
    """一次派生：校验主密码并返回 SM4 密钥。失败抛 ValueError。"""
    key = derive_sm4_key(master_password, salt, iterations)
    expect = verifier_from_key(key, salt)
    if not secrets.compare_digest(expect, verifier_b64):
        raise ValueError("主密码错误")
    return key


def verify_master_password(
    master_password: str,
    salt: bytes,
    verifier_b64: str,
    iterations: int = KDF_ITERATIONS,
) -> bool:
    try:
        unlock_with_password(master_password, salt, verifier_b64, iterations)
        return True
    except Exception:
        return False


def sm4_encrypt(plaintext: str, key: bytes) -> str:
    """SM4-CBC 加密。输出：GM1:base64(iv + ciphertext)。"""
    if plaintext is None or plaintext == "":
        return ""
    raw = plaintext.encode("utf-8")
    iv = os.urandom(16)
    crypt = CryptSM4()
    crypt.set_key(key, SM4_ENCRYPT)
    # gmssl 内部已做 PKCS7 填充
    ct = crypt.crypt_cbc(iv, raw)
    return CIPHER_PREFIX + base64.b64encode(iv + ct).decode("ascii")


def sm4_decrypt(token: str, key: bytes) -> str:
    if not token:
        return ""
    if not token.startswith(CIPHER_PREFIX):
        raise ValueError("非国密密文格式")
    blob = base64.b64decode(token[len(CIPHER_PREFIX) :].encode("ascii"))
    if len(blob) < 32:
        raise ValueError("密文过短")
    iv, ct = blob[:16], blob[16:]
    crypt = CryptSM4()
    crypt.set_key(key, SM4_DECRYPT)
    pt = crypt.crypt_cbc(iv, ct)
    return pt.decode("utf-8")


def try_legacy_fernet_decrypt(token: str, fernet_key: Optional[bytes]) -> Optional[str]:
    """兼容旧版 Fernet 密文（迁移用）。"""
    if not token or not fernet_key:
        return None
    try:
        from cryptography.fernet import Fernet

        return Fernet(fernet_key).decrypt(token.encode("ascii")).decode("utf-8")
    except Exception:
        return None


def is_gm_cipher(token: str) -> bool:
    return bool(token) and token.startswith(CIPHER_PREFIX)


def random_salt(n: int = 16) -> bytes:
    return os.urandom(n)


def fingerprint_key(key: bytes) -> str:
    """界面展示用指纹，不可逆。"""
    return hashlib.sha256(key).hexdigest()[:12].upper()

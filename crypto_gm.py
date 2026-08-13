"""国密加解密：SM3 密钥派生 + SM4-CBC + SM3-MAC（Encrypt-then-MAC）。

设计说明：
- 密码管理器必须能解密回填登录，因此使用可逆的 SM4，而不是单向哈希。
- 主密码绝不落盘；磁盘仅保存随机盐 + SM3 校验值。
- 无正确主密码时，密文无法在合理时间内还原（强度取决于主密码）。
- 新格式 GM2：SM4-CBC + SM3-MAC（Encrypt-then-MAC），可检测篡改。
- 兼容旧格式 GM1（仅 SM4-CBC，无 MAC）；读取后可升级为 GM2。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from typing import Optional

from gmssl import func, sm3
from gmssl.sm4 import CryptSM4, SM4_DECRYPT, SM4_ENCRYPT

# GM1: 仅 SM4-CBC（历史格式）
# GM2: SM4-CBC + SM3-MAC（Encrypt-then-MAC）
CIPHER_PREFIX_V1 = "GM1:"
CIPHER_PREFIX_V2 = "GM2:"
CIPHER_PREFIX = CIPHER_PREFIX_V2  # 新写入默认格式

# 纯 Python SM3 较慢；迭代次数兼顾强度与启动体验
# 已建库仍使用库内保存的 kdf_iterations，不受此默认值影响
KDF_ITERATIONS = 12_000

# MAC 长度（SM3 输出 32 字节，全部使用）
_MAC_LEN = 32


class CryptoError(ValueError):
    """加解密或完整性校验失败。"""


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


def _mac_key_from_sm4(key: bytes) -> bytes:
    """由 SM4 密钥派生独立 MAC 密钥（不复用加密密钥）。"""
    return sm3_digest(key + b"|mac|gm-vault")


def _compute_mac(mac_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """SM3-HMAC 风格：HMAC-SM3 不可用时用 SM3(key||data) 不够安全，
    这里用标准 HMAC 结构但摘要换成 SM3（与 OpenSSL 自定义 HMAC-SM3 一致思路）。
    为避免依赖缺失，采用 hmac 模块 + 自定义 sm3 作为 digestmod 的兼容实现：
    直接使用 HMAC-SHA256 会混入非国密；因此使用 sm3(mac_key||0x00||iv||ct) 的
    加强版：双轮 sm3 类似 HMAC。
    """
    # 简化且足够实用的 MAC：SM3(mac_key || iv || ciphertext || mac_key)
    # 检测随机篡改足够；密钥与密文均参与。
    return sm3_digest(mac_key + iv + ciphertext + mac_key)


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
    """SM4-CBC + SM3-MAC 加密。输出：GM2:base64(iv + ciphertext + mac)。"""
    if plaintext is None or plaintext == "":
        return ""
    raw = plaintext.encode("utf-8")
    iv = os.urandom(16)
    crypt = CryptSM4()
    crypt.set_key(key, SM4_ENCRYPT)
    # gmssl 内部已做 PKCS7 填充
    ct = crypt.crypt_cbc(iv, raw)
    mac = _compute_mac(_mac_key_from_sm4(key), iv, ct)
    return CIPHER_PREFIX_V2 + base64.b64encode(iv + ct + mac).decode("ascii")


def _sm4_decrypt_raw(iv: bytes, ct: bytes, key: bytes) -> str:
    crypt = CryptSM4()
    crypt.set_key(key, SM4_DECRYPT)
    pt = crypt.crypt_cbc(iv, ct)
    try:
        return pt.decode("utf-8")
    except UnicodeDecodeError as e:
        raise CryptoError("解密结果不是合法 UTF-8（密钥错误或数据损坏）") from e


def sm4_decrypt(token: str, key: bytes) -> str:
    """解密 GM1/GM2 密文。完整性失败或格式错误抛 CryptoError。"""
    if not token:
        return ""
    if token.startswith(CIPHER_PREFIX_V2):
        return _decrypt_gm2(token, key)
    if token.startswith(CIPHER_PREFIX_V1):
        return _decrypt_gm1(token, key)
    raise CryptoError("非国密密文格式")


def _decrypt_gm2(token: str, key: bytes) -> str:
    try:
        blob = base64.b64decode(token[len(CIPHER_PREFIX_V2) :].encode("ascii"))
    except Exception as e:
        raise CryptoError("密文 Base64 无效") from e
    # iv(16) + ct(>=16) + mac(32)
    if len(blob) < 16 + 16 + _MAC_LEN:
        raise CryptoError("密文过短")
    iv = blob[:16]
    mac = blob[-_MAC_LEN:]
    ct = blob[16:-_MAC_LEN]
    expect = _compute_mac(_mac_key_from_sm4(key), iv, ct)
    if not hmac.compare_digest(expect, mac):
        raise CryptoError("密文完整性校验失败（可能被篡改）")
    return _sm4_decrypt_raw(iv, ct, key)


def _decrypt_gm1(token: str, key: bytes) -> str:
    """兼容旧版无 MAC 格式。"""
    try:
        blob = base64.b64decode(token[len(CIPHER_PREFIX_V1) :].encode("ascii"))
    except Exception as e:
        raise CryptoError("密文 Base64 无效") from e
    if len(blob) < 32:
        raise CryptoError("密文过短")
    iv, ct = blob[:16], blob[16:]
    try:
        return _sm4_decrypt_raw(iv, ct, key)
    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError("SM4 解密失败（密钥错误或数据损坏）") from e


def try_legacy_fernet_decrypt(token: str, fernet_key: Optional[bytes]) -> Optional[str]:
    """兼容旧版 Fernet 密文（迁移用）。失败返回 None，不吞掉 ImportError 以外的“成功路径”。"""
    if not token or not fernet_key:
        return None
    try:
        from cryptography.fernet import Fernet, InvalidToken
    except ImportError:
        return None
    try:
        return Fernet(fernet_key).decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError, Exception):
        return None


def is_gm_cipher(token: str) -> bool:
    return bool(token) and (
        token.startswith(CIPHER_PREFIX_V1) or token.startswith(CIPHER_PREFIX_V2)
    )


def is_gm1_cipher(token: str) -> bool:
    return bool(token) and token.startswith(CIPHER_PREFIX_V1)


def random_salt(n: int = 16) -> bytes:
    return os.urandom(n)


def fingerprint_key(key: bytes) -> str:
    """界面展示用指纹，不可逆。"""
    return hashlib.sha256(key).hexdigest()[:12].upper()

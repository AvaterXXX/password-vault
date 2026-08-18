"""本地账户库：敏感字段使用国密 SM4 加密存储。"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, unquote, urlparse

from crypto_gm import (
    KDF_ITERATIONS,
    CryptoError,
    derive_sm4_key,
    fingerprint_key,
    is_gm1_cipher,
    is_gm_cipher,
    random_salt,
    sm4_decrypt,
    sm4_encrypt,
    try_legacy_fernet_decrypt,
    unlock_with_password,
    verifier_from_key,
)


def app_data_dir() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home() / ".account_vault")
    path = Path(base) / "AccountVault"
    path.mkdir(parents=True, exist_ok=True)
    return path


# 数据库位置来自仓库历史代码：Windows 使用 APPDATA，未设置 APPDATA 时使用
# home 下的回退目录。没有仓库证据的项目目录/EXE 同目录路径不在候选列表中，
# 避免误把无关的 vault.db 当成用户保险库。
_ACCOUNT_SCHEMA = (
    ("id", "TEXT PRIMARY KEY"),
    ("title", "TEXT NOT NULL DEFAULT '未命名'"),
    ("category", "TEXT NOT NULL DEFAULT '其他'"),
    ("username", "TEXT NOT NULL DEFAULT ''"),
    ("password_enc", "TEXT NOT NULL DEFAULT ''"),
    ("totp_secret_enc", "TEXT NOT NULL DEFAULT ''"),
    ("website", "TEXT NOT NULL DEFAULT ''"),
    ("notes", "TEXT NOT NULL DEFAULT ''"),
    ("created_at", "TEXT NOT NULL DEFAULT ''"),
    ("updated_at", "TEXT NOT NULL DEFAULT ''"),
)
_SITES_SCHEMA = (
    ("id", "TEXT PRIMARY KEY"),
    ("name", "TEXT NOT NULL DEFAULT ''"),
    ("url", "TEXT NOT NULL DEFAULT ''"),
    ("sort_order", "INTEGER NOT NULL DEFAULT 0"),
)
_META_SCHEMA = (("key", "TEXT PRIMARY KEY"), ("value", "TEXT NOT NULL DEFAULT ''"))
_TABLE_SCHEMAS = {
    "accounts": _ACCOUNT_SCHEMA,
    "sites": _SITES_SCHEMA,
    "vault_meta": _META_SCHEMA,
}


def _read_only_connection(path: Path) -> sqlite3.Connection:
    """以只读方式打开已有数据库，绝不因为探测而创建文件。"""
    uri = f"{path.resolve().as_uri()}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def _new_backup_path(path: Path, reason: str) -> Path:
    safe_reason = re.sub(r"[^\w\-]+", "_", reason)[:32] or "bak"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    for _ in range(20):
        suffix = secrets.token_hex(3)
        candidate = path.with_name(
            f"{path.stem}.{safe_reason}.{stamp}-{suffix}.bak"
        )
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"无法为数据库创建唯一备份文件：{path}")


def _backup_existing_file(path: Path, reason: str) -> Path:
    """在任何 schema/加密升级前生成可恢复副本。

    正常 SQLite 文件使用 backup API；损坏或尚未有 schema 的文件则退回到
    原始字节复制。目标文件名唯一，绝不覆盖已有备份。
    """
    backup_path = _new_backup_path(path, reason)
    source: sqlite3.Connection | None = None
    target: sqlite3.Connection | None = None
    try:
        try:
            source = _read_only_connection(path)
            target = sqlite3.connect(str(backup_path))
            source.backup(target)
            target.commit()
        except (OSError, sqlite3.DatabaseError):
            if target is not None:
                target.close()
                target = None
            try:
                backup_path.unlink(missing_ok=True)
            except OSError:
                pass
            shutil.copy2(path, backup_path)
    except Exception:
        try:
            backup_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    finally:
        if source is not None:
            source.close()
        if target is not None:
            target.close()
    return backup_path


def _database_needs_schema_backup(path: Path) -> bool:
    """判断初始化/补列是否会改写已有数据库。"""
    try:
        if not path.exists() or path.stat().st_size == 0:
            return False
    except OSError:
        return True
    conn: sqlite3.Connection | None = None
    try:
        conn = _read_only_connection(path)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if not set(_TABLE_SCHEMAS).issubset(tables):
            return True
        for table, columns in _TABLE_SCHEMAS.items():
            actual = {
                row[1] for row in conn.execute(f"PRAGMA table_info({table})")
            }
            if any(name not in actual for name, _definition in columns):
                return True
        return False
    except (OSError, sqlite3.DatabaseError):
        # 无法读取的旧文件也必须先做原始备份，再交给 SQLite 抛出明确错误。
        return True
    finally:
        if conn is not None:
            conn.close()


def _probe_database(path: Path) -> dict[str, Any]:
    """只读探测候选库是否为本项目库以及是否已设置主密码。"""
    result: dict[str, Any] = {
        "path": path,
        "exists": False,
        "schema_valid": False,
        "initialized": False,
        "error": None,
    }
    try:
        if not path.is_file():
            return result
        result["exists"] = True
    except OSError as exc:
        result["error"] = str(exc)
        return result
    conn: sqlite3.Connection | None = None
    try:
        conn = _read_only_connection(path)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if not set(_TABLE_SCHEMAS).issubset(tables):
            return result
        for table, columns in _TABLE_SCHEMAS.items():
            actual = {
                row[1] for row in conn.execute(f"PRAGMA table_info({table})")
            }
            if any(name not in actual for name, _definition in columns):
                return result
        result["schema_valid"] = True
        meta = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT key, value FROM vault_meta WHERE key IN "
                "('password_verifier', 'kdf_salt')"
            )
        }
        result["initialized"] = bool(
            meta.get("password_verifier") and meta.get("kdf_salt")
        )
    except (OSError, sqlite3.DatabaseError) as exc:
        result["error"] = str(exc)
    finally:
        if conn is not None:
            conn.close()
    return result


def discover_database_path(data_dir: Path) -> tuple[Path, str | None, list[dict[str, Any]]]:
    """发现旧库并返回 (选中路径, 提示, 候选探测结果)。

    优先级固定且可解释：当前 APPDATA 目录 > 未设置 APPDATA 时的历史回退目录；
    在同一优先级下优先已初始化且 schema 完整的库。只读探测，不复制、移动或
    覆盖任何候选文件。
    """
    current = data_dir / "vault.db"
    fallback = Path.home() / ".account_vault" / "AccountVault" / "vault.db"
    candidates: list[Path] = [current]
    if fallback != current:
        candidates.append(fallback)
    probes = [_probe_database(path) for path in candidates]
    existing = [probe for probe in probes if probe["exists"]]
    initialized = [
        probe for probe in existing if probe["schema_valid"] and probe["initialized"]
    ]
    schema_valid = [probe for probe in existing if probe["schema_valid"]]
    selected_probe = (initialized or schema_valid or existing or [probes[0]])[0]
    selected = selected_probe["path"]
    note: str | None = None
    if len(existing) > 1 or selected != current:
        names = ", ".join(str(probe["path"]) for probe in existing)
        if selected != current and selected_probe["initialized"]:
            note = (
                f"已发现旧保险库并继续使用：{selected}。"
                "未复制或覆盖原数据库；如需迁移请先保留备份。"
            )
        else:
            note = f"检测到多个数据库候选，按固定优先级使用：{selected}。候选：{names}"
    return selected, note, probes


class VaultLockedError(RuntimeError):
    pass


class VaultBusyError(RuntimeError):
    pass


class VaultStorage:
    MIN_PASSWORD_LEN = 8
    PIN_MIN_LEN = 4
    PIN_MAX_LEN = 12

    def __init__(self, db_path: Path | None = None) -> None:
        self.data_dir = app_data_dir()
        if db_path is None:
            (
                self.db_path,
                self.database_discovery_note,
                self.database_candidates,
            ) = discover_database_path(self.data_dir)
        else:
            self.db_path = Path(db_path)
            self.database_discovery_note = None
            self.database_candidates = [_probe_database(self.db_path)]
        # 旧版 Fernet 密钥历史上与 vault.db 位于同一数据目录。只有选中的
        # 路径就是当前数据目录时才使用该目录的 key，避免把另一候选库的
        # vault.key 错配给旧库。
        key_paths: list[Path] = [self.db_path.with_name("vault.key")]
        data_key = self.data_dir / "vault.key"
        if self.db_path == self.data_dir / "vault.db" and data_key not in key_paths:
            key_paths.append(data_key)
        self._legacy_key_paths = key_paths
        self.key_path = key_paths[0]
        self._sm4_key: Optional[bytes] = None
        self._account_cache: dict[str, dict[str, Any]] = {}
        # 锁定 PIN 只保存在当前进程内。程序重启仍必须输入主密码，避免把
        # 弱 PIN 对应的主密钥包装值写入磁盘后可被离线穷举。
        self._pin_salt: Optional[bytes] = None
        self._pin_verifier: Optional[str] = None
        self._pin_wrapped_key: Optional[str] = None
        self._lock = threading.RLock()
        self._current_op: Optional[str] = None
        self._schema_backup_path: Optional[Path] = None
        self._crypto_backup_path: Optional[Path] = None
        if _database_needs_schema_backup(self.db_path):
            self._schema_backup_path = _backup_existing_file(
                self.db_path, "before-schema"
            )
        try:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._init_db()
        except Exception:
            try:
                self._conn.close()
            except Exception:
                pass
            raise

    # ---------- 锁 / 忙状态 ----------
    def is_busy(self) -> bool:
        return self._current_op is not None

    def busy_op(self) -> Optional[str]:
        return self._current_op

    def _begin_op(self, name: str, *, block: bool = True) -> None:
        if block:
            self._lock.acquire()
        else:
            if not self._lock.acquire(blocking=False):
                raise VaultBusyError(
                    f"正在执行「{self._current_op or '其他操作'}」，请稍后再试"
                )
        self._current_op = name

    def _end_op(self) -> None:
        self._current_op = None
        self._lock.release()

    # ---------- 元数据 / 主密码 ----------
    def _init_db(self) -> None:
        # 不使用 executescript：它会隐式提交，无法在 schema 失败时回滚。
        try:
            self._conn.execute("BEGIN")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT '其他',
                    username TEXT NOT NULL DEFAULT '',
                    password_enc TEXT NOT NULL DEFAULT '',
                    totp_secret_enc TEXT NOT NULL DEFAULT '',
                    website TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sites (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    sort_order INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vault_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            self._ensure_schema_columns()
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

        # 仅首次（未打标）且站点表为空时写入默认网站；用户清空后不再复活。
        if not self._meta_get("defaults_sites_seeded"):
            try:
                self._conn.execute("BEGIN")
                if self.count_sites() == 0:
                    self._seed_default_sites(commit=False)
                self._meta_set("defaults_sites_seeded", "1", commit=False)
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def _ensure_schema_columns(self) -> None:
        """补齐可安全增加的旧列；主键缺失时拒绝猜测并保留备份。"""
        for table, columns in _TABLE_SCHEMAS.items():
            actual = {
                row[1] for row in self._conn.execute(f"PRAGMA table_info({table})")
            }
            for name, definition in columns:
                if name in actual:
                    continue
                if name in {"id", "key"}:
                    raise RuntimeError(
                        f"数据库表 {table} 缺少主键列 {name}，已保留原文件及升级前备份；"
                        "请使用原版本打开或从备份恢复。"
                    )
                self._conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {name} {definition}"
                )

    def _meta_get(self, key: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT value FROM vault_meta WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def _meta_set(self, key: str, value: str, *, commit: bool = True) -> None:
        self._conn.execute(
            "INSERT INTO vault_meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        if commit:
            self._conn.commit()

    def is_initialized(self) -> bool:
        """是否已设置主密码（国密保险库）。"""
        return bool(self._meta_get("password_verifier") and self._meta_get("kdf_salt"))

    def is_unlocked(self) -> bool:
        return self._sm4_key is not None

    def crypto_info(self) -> str:
        if not self.is_unlocked():
            return "未解锁"
        fp = fingerprint_key(self._sm4_key or b"")
        return f"国密 SM3/SM4-MAC · 密钥指纹 {fp}"

    def _find_legacy_key_path(self) -> Optional[Path]:
        for path in self._legacy_key_paths:
            try:
                if path.is_file():
                    return path
            except OSError:
                continue
        return None

    def _has_crypto_migration_pending(self) -> bool:
        """是否会在解锁后改写旧密文或移动旧版 vault.key。"""
        if self._find_legacy_key_path() is not None:
            return True
        try:
            row = self._conn.execute(
                "SELECT 1 FROM accounts WHERE "
                "(password_enc != '' AND password_enc NOT LIKE 'GM1:%' AND password_enc NOT LIKE 'GM2:%') OR "
                "(totp_secret_enc != '' AND totp_secret_enc NOT LIKE 'GM1:%' AND totp_secret_enc NOT LIKE 'GM2:%') OR "
                "(notes != '' AND notes NOT LIKE 'GM1:%' AND notes NOT LIKE 'GM2:%') OR "
                "password_enc LIKE 'GM1:%' OR totp_secret_enc LIKE 'GM1:%' OR notes LIKE 'GM1:%' "
                "LIMIT 1"
            ).fetchone()
            return row is not None
        except sqlite3.DatabaseError:
            return False

    def _prepare_crypto_backup_if_needed(self) -> Optional[Path]:
        if self._crypto_backup_path is not None or not self._has_crypto_migration_pending():
            return self._crypto_backup_path
        self._crypto_backup_path = self.backup_database("before-crypto-migration")
        return self._crypto_backup_path

    def setup_master_password(self, master_password: str) -> None:
        """首次设置主密码。"""
        self._begin_op("设置主密码")
        try:
            if len(master_password) < self.MIN_PASSWORD_LEN:
                raise ValueError(f"主密码至少 {self.MIN_PASSWORD_LEN} 位")
            if self.is_initialized():
                raise ValueError("主密码已设置，请使用解锁")

            salt = random_salt(16)
            iterations = KDF_ITERATIONS
            key = derive_sm4_key(master_password, salt, iterations)
            verifier = verifier_from_key(key, salt)
            # 旧库首次设置主密码时，先备份原始数据，再进入同一事务写入
            # 元数据和加密迁移；失败时 rollback 不会留下半初始化库。
            self._prepare_crypto_backup_if_needed()
            # 元数据单事务提交，避免半初始化
            self._meta_set("kdf_salt", base64.b64encode(salt).decode("ascii"), commit=False)
            self._meta_set("kdf_iterations", str(iterations), commit=False)
            self._meta_set("password_verifier", verifier, commit=False)
            self._meta_set("crypto_algo", "SM3-KDF+SM4-CBC-MAC", commit=False)
            self._meta_set("crypto_version", "2", commit=False)

            self._sm4_key = key
            self._account_cache.clear()
            self._migrate_legacy_if_needed()
            self._upgrade_gm1_to_gm2()
            self._conn.commit()
            self._finalize_legacy_key_move()
        except Exception:
            try:
                self._conn.rollback()
            except Exception:
                pass
            self._sm4_key = None
            self._account_cache.clear()
            raise
        finally:
            self._end_op()

    def unlock(self, master_password: str) -> None:
        self._begin_op("解锁")
        try:
            if not self.is_initialized():
                raise ValueError("尚未设置主密码")
            salt_b64 = self._meta_get("kdf_salt") or ""
            verifier = self._meta_get("password_verifier") or ""
            iterations = int(self._meta_get("kdf_iterations") or KDF_ITERATIONS)
            salt = base64.b64decode(salt_b64.encode("ascii"))
            self._sm4_key = unlock_with_password(master_password, salt, verifier, iterations)
            self._account_cache.clear()
            self._prepare_crypto_backup_if_needed()
            self._migrate_legacy_if_needed()
            self._upgrade_gm1_to_gm2()
            self._finalize_legacy_key_move()
        except Exception:
            self._sm4_key = None
            self._account_cache.clear()
            raise
        finally:
            self._end_op()

    # ---------- 当前会话 PIN（仅用于自动锁定后的快速解锁） ----------
    @classmethod
    def validate_pin(cls, pin: str) -> None:
        value = str(pin or "")
        if not value.isascii() or not value.isdigit():
            raise ValueError("PIN 必须只包含数字")
        if not (cls.PIN_MIN_LEN <= len(value) <= cls.PIN_MAX_LEN):
            raise ValueError(f"PIN 长度必须为 {cls.PIN_MIN_LEN}-{cls.PIN_MAX_LEN} 位")

    def is_pin_configured(self) -> bool:
        return bool(self._pin_salt and self._pin_verifier and self._pin_wrapped_key)

    def set_session_pin(self, pin: str) -> None:
        """设置当前进程有效的 PIN，并用 PIN 包装当前主密钥。

        PIN 不写入数据库；包装值也只在内存中保留。这样自动锁定时可以清除
        账户明文缓存，仍允许 PIN 恢复主密钥；程序退出后不会留下 PIN 后门。
        """
        self.validate_pin(pin)
        self._begin_op("设置锁定 PIN", block=False)
        try:
            key = self._require_unlock()
            salt = random_salt(16)
            pin_key = derive_sm4_key(pin, salt, KDF_ITERATIONS)
            self._pin_salt = salt
            self._pin_verifier = verifier_from_key(pin_key, salt)
            self._pin_wrapped_key = sm4_encrypt(base64.b64encode(key).decode("ascii"), pin_key)
        finally:
            self._end_op()

    def clear_session_pin(self) -> None:
        self._pin_salt = None
        self._pin_verifier = None
        self._pin_wrapped_key = None

    def unlock_with_pin(self, pin: str) -> None:
        """使用当前会话 PIN 恢复自动锁定前的主密钥。"""
        self.validate_pin(pin)
        self._begin_op("PIN 解锁", block=True)
        try:
            if not self.is_pin_configured():
                raise ValueError("尚未设置锁定 PIN，请输入主密码")
            salt = self._pin_salt
            verifier = self._pin_verifier
            wrapped = self._pin_wrapped_key
            if salt is None or verifier is None or not wrapped:
                raise ValueError("锁定 PIN 已失效，请输入主密码")
            pin_key = derive_sm4_key(pin, salt, KDF_ITERATIONS)
            if not secrets.compare_digest(verifier_from_key(pin_key, salt), verifier):
                raise ValueError("PIN 错误")
            try:
                raw_key = base64.b64decode(
                    sm4_decrypt(wrapped, pin_key).encode("ascii"), validate=True
                )
            except Exception as e:
                raise ValueError("PIN 包装数据无效，请输入主密码") from e
            if len(raw_key) != 16:
                raise ValueError("PIN 包装数据无效，请输入主密码")
            self._sm4_key = raw_key
            self._account_cache.clear()
        finally:
            self._end_op()

    def backup_database(self, reason: str = "manual") -> Path:
        """复制当前数据库为备份文件，返回备份路径。"""
        self._conn.commit()
        backup_path = _new_backup_path(self.db_path, reason)
        # 使用 SQLite backup API，比直接 copy 更安全
        dst: sqlite3.Connection | None = None
        try:
            dst = sqlite3.connect(str(backup_path))
            self._conn.backup(dst)
            dst.commit()
        except Exception:
            try:
                backup_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        finally:
            if dst is not None:
                dst.close()
        return backup_path

    def change_master_password(self, old_password: str, new_password: str) -> Path:
        """更换主密码：单事务重加密全部敏感字段；失败回滚。

        操作前自动备份数据库。返回备份路径。
        """
        self._begin_op("修改主密码", block=False)
        try:
            if len(new_password) < self.MIN_PASSWORD_LEN:
                raise ValueError(f"新主密码至少 {self.MIN_PASSWORD_LEN} 位")
            salt_b64 = self._meta_get("kdf_salt") or ""
            verifier = self._meta_get("password_verifier") or ""
            iterations = int(self._meta_get("kdf_iterations") or KDF_ITERATIONS)
            salt = base64.b64decode(salt_b64.encode("ascii"))
            old_key = unlock_with_password(old_password, salt, verifier, iterations)

            # 操作前备份
            backup_path = self.backup_database(reason="before-rekey")

            rows = self._conn.execute(
                "SELECT id, password_enc, totp_secret_enc, notes FROM accounts"
            ).fetchall()

            # 解密到明文（严格模式：失败则中止，避免用空串重加密）
            plain_rows: list[tuple[str, str, str, str]] = []
            for r in rows:
                try:
                    pwd = self._dec_with_key(r["password_enc"], old_key, strict=True)
                    totp = self._dec_with_key(r["totp_secret_enc"], old_key, strict=True)
                    if self._looks_encrypted(r["notes"] or ""):
                        notes = self._dec_with_key(r["notes"], old_key, strict=True)
                    else:
                        notes = r["notes"] or ""
                except CryptoError as e:
                    raise RuntimeError(
                        f"账户 {r['id']} 解密失败，已中止换密（数据库未改动）：{e}"
                    ) from e
                plain_rows.append((r["id"], pwd, totp, notes))

            new_salt = random_salt(16)
            # 换密时可采用当前默认迭代次数（提升旧库强度）
            new_iterations = KDF_ITERATIONS
            new_key = derive_sm4_key(new_password, new_salt, new_iterations)
            new_verifier = verifier_from_key(new_key, new_salt)

            try:
                for acc_id, pwd, totp, notes in plain_rows:
                    self._conn.execute(
                        "UPDATE accounts SET password_enc = ?, totp_secret_enc = ?, notes = ? WHERE id = ?",
                        (
                            sm4_encrypt(pwd, new_key) if pwd else "",
                            sm4_encrypt(totp, new_key) if totp else "",
                            sm4_encrypt(notes, new_key) if notes else "",
                            acc_id,
                        ),
                    )

                # 元数据与密文同一事务
                self._meta_set(
                    "kdf_salt",
                    base64.b64encode(new_salt).decode("ascii"),
                    commit=False,
                )
                self._meta_set("password_verifier", new_verifier, commit=False)
                self._meta_set("kdf_iterations", str(new_iterations), commit=False)
                self._meta_set("crypto_algo", "SM3-KDF+SM4-CBC-MAC", commit=False)
                self._meta_set("crypto_version", "2", commit=False)
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

            self._sm4_key = new_key
            self._account_cache.clear()
            # 主密钥已经改变，旧 PIN 包装值不可再用；下次需要重新设置 PIN。
            self.clear_session_pin()
            return backup_path
        finally:
            self._end_op()

    def lock(self) -> None:
        with self._lock:
            self._sm4_key = None
            self._account_cache.clear()

    def _require_unlock(self) -> bytes:
        if self._sm4_key is None:
            raise VaultLockedError("保险库未解锁")
        return self._sm4_key

    def invalidate_cache(self, account_id: str | None = None) -> None:
        if account_id is None:
            self._account_cache.clear()
        else:
            self._account_cache.pop(account_id, None)

    # ---------- 加解密 ----------
    def _looks_encrypted(self, value: str) -> bool:
        if not value:
            return False
        return is_gm_cipher(value) or value.startswith("gAAAA")  # Fernet 常见前缀

    def _enc(self, value: str) -> str:
        if not value:
            return ""
        key = self._require_unlock()
        return sm4_encrypt(value, key)

    def _dec(self, value: str, *, strict: bool = False) -> str:
        if not value:
            return ""
        key = self._require_unlock()
        return self._dec_with_key(value, key, strict=strict)

    def _dec_with_key(self, value: str, key: bytes, *, strict: bool = False) -> str:
        if not value:
            return ""
        if is_gm_cipher(value):
            try:
                return sm4_decrypt(value, key)
            except CryptoError:
                if strict:
                    raise
                return "【解密失败】"
            except Exception as e:
                if strict:
                    raise CryptoError(str(e)) from e
                return "【解密失败】"
        # 尝试旧 Fernet
        legacy = self._load_legacy_fernet_key()
        plain = try_legacy_fernet_decrypt(value, legacy)
        if plain is not None:
            return plain
        if strict and value.startswith("gAAAA"):
            raise CryptoError("旧版 Fernet 密文无法解密（密钥缺失或无效）")
        if value.startswith("gAAAA"):
            return "【解密失败】"
        # 非密文：原样返回（兼容历史明文 notes）
        return value if not strict else value

    def _load_legacy_fernet_key(self) -> Optional[bytes]:
        for path in self._legacy_key_paths:
            try:
                if path.exists():
                    return path.read_bytes().strip()
            except OSError:
                continue
        return None

    def _finalize_legacy_key_move(self) -> None:
        """迁移事务成功后才移动旧版密钥；移动失败则保留原密钥。"""
        key_path = self._find_legacy_key_path()
        if key_path is None:
            return
        still_legacy = self._conn.execute(
            "SELECT 1 FROM accounts WHERE "
            "(password_enc != '' AND password_enc NOT LIKE 'GM1:%' AND password_enc NOT LIKE 'GM2:%') OR "
            "(totp_secret_enc != '' AND totp_secret_enc NOT LIKE 'GM1:%' AND totp_secret_enc NOT LIKE 'GM2:%') OR "
            "(notes != '' AND notes NOT LIKE 'GM1:%' AND notes NOT LIKE 'GM2:%') LIMIT 1"
        ).fetchone()
        if still_legacy:
            return
        bak = key_path.with_suffix(
            key_path.suffix
            + f".migrated.{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}.bak"
        )
        try:
            shutil.move(str(key_path), str(bak))
        except OSError:
            # 移动失败不要 unlink，仍保留旧版解密能力。
            pass

    def _migrate_legacy_if_needed(self) -> None:
        """把旧 Fernet/明文密文重加密为国密，失败时保留原字段和密钥。"""
        key = self._require_unlock()
        legacy = self._load_legacy_fernet_key()
        # 无旧密钥且抽样已是国密，直接跳过（加速启动）
        if not legacy:
            row = self._conn.execute(
                "SELECT password_enc, notes FROM accounts LIMIT 5"
            ).fetchall()
            if not row or all(
                (not r["password_enc"] or is_gm_cipher(r["password_enc"]))
                and (not r["notes"] or is_gm_cipher(r["notes"]))
                for r in row
            ):
                need = self._conn.execute(
                    "SELECT 1 FROM accounts WHERE "
                    "(password_enc != '' AND password_enc NOT LIKE 'GM1:%' AND password_enc NOT LIKE 'GM2:%') OR "
                    "(totp_secret_enc != '' AND totp_secret_enc NOT LIKE 'GM1:%' AND totp_secret_enc NOT LIKE 'GM2:%') OR "
                    "(notes != '' AND notes NOT LIKE 'GM1:%' AND notes NOT LIKE 'GM2:%') LIMIT 1"
                ).fetchone()
                if not need:
                    return

        owns_transaction = not self._conn.in_transaction
        if owns_transaction:
            self._conn.execute("BEGIN")
        try:
            rows = self._conn.execute(
                "SELECT id, password_enc, totp_secret_enc, notes FROM accounts"
            ).fetchall()
            changed = False
            failed_fields = 0

            for r in rows:
                pid, pw, totp, notes = r["id"], r["password_enc"], r["totp_secret_enc"], r["notes"]
                new_pw, new_totp, new_notes = pw, totp, notes

                if pw and not is_gm_cipher(pw):
                    plain = try_legacy_fernet_decrypt(pw, legacy) if legacy else None
                    if plain is not None:
                        new_pw = sm4_encrypt(plain, key)
                        changed = True
                    else:
                        failed_fields += 1

                if totp and not is_gm_cipher(totp):
                    plain = try_legacy_fernet_decrypt(totp, legacy) if legacy else None
                    if plain is not None:
                        new_totp = sm4_encrypt(plain, key)
                        changed = True
                    else:
                        failed_fields += 1

                # 备注：旧版明文，新版改为加密存储
                if notes and not is_gm_cipher(notes):
                    if notes.startswith("gAAAA"):
                        plain = try_legacy_fernet_decrypt(notes, legacy) if legacy else None
                        if plain is None:
                            failed_fields += 1
                        else:
                            new_notes = sm4_encrypt(plain, key)
                            changed = True
                    else:
                        # 明文 notes 迁移不依赖 vault.key
                        new_notes = sm4_encrypt(notes, key)
                        changed = True

                if (new_pw, new_totp, new_notes) != (pw, totp, notes):
                    self._conn.execute(
                        "UPDATE accounts SET password_enc = ?, totp_secret_enc = ?, notes = ? WHERE id = ?",
                        (new_pw, new_totp, new_notes, pid),
                    )

            if failed_fields:
                # 不允许只迁移一部分字段：独立事务回滚后仍可用旧格式解密；
                # 首次设置主密码的外层事务则直接抛错并回滚元数据。
                if owns_transaction:
                    self._conn.rollback()
                    return
                raise RuntimeError(
                    "旧版密文迁移失败，数据库未改动；请检查旧版 vault.key 或使用备份恢复"
                )
            if owns_transaction:
                self._conn.commit()
            # 成功提交后由外层统一移动 vault.key。
        except Exception:
            if owns_transaction:
                self._conn.rollback()
            raise

    def _upgrade_gm1_to_gm2(self) -> None:
        """将仍为 GM1 的字段升级为带 MAC 的 GM2（同密钥重封装）。"""
        key = self._require_unlock()
        owns_transaction = not self._conn.in_transaction
        if owns_transaction:
            self._conn.execute("BEGIN")
        rows = self._conn.execute(
            "SELECT id, password_enc, totp_secret_enc, notes FROM accounts WHERE "
            "password_enc LIKE 'GM1:%' OR totp_secret_enc LIKE 'GM1:%' OR notes LIKE 'GM1:%'"
        ).fetchall()
        if not rows:
            if owns_transaction:
                self._conn.rollback()
            return
        changed = False
        try:
            for r in rows:
                pw, totp, notes = r["password_enc"], r["totp_secret_enc"], r["notes"]
                new_pw, new_totp, new_notes = pw, totp, notes
                try:
                    if is_gm1_cipher(pw or ""):
                        new_pw = sm4_encrypt(sm4_decrypt(pw, key), key)
                        changed = True
                    if is_gm1_cipher(totp or ""):
                        new_totp = sm4_encrypt(sm4_decrypt(totp, key), key)
                        changed = True
                    if is_gm1_cipher(notes or ""):
                        new_notes = sm4_encrypt(sm4_decrypt(notes, key), key)
                        changed = True
                except CryptoError:
                    # GM1 仍可被当前读取逻辑兼容；放弃本次整批升级，
                    # 不提交此前已生成的 GM2 更新。
                    if owns_transaction:
                        self._conn.rollback()
                        self._account_cache.clear()
                        return
                    raise RuntimeError(
                        f"GM1 密文升级失败（账户 {r['id']}），数据库未改动"
                    )
                if (new_pw, new_totp, new_notes) != (pw, totp, notes):
                    self._conn.execute(
                        "UPDATE accounts SET password_enc = ?, totp_secret_enc = ?, notes = ? WHERE id = ?",
                        (new_pw, new_totp, new_notes, r["id"]),
                    )
            if owns_transaction:
                if changed:
                    self._conn.commit()
                    self._account_cache.clear()
                else:
                    self._conn.rollback()
        except Exception:
            if owns_transaction:
                self._conn.rollback()
            raise

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ---- sites ----
    def count_sites(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS c FROM sites").fetchone()
        return int(row["c"])

    def count_accounts(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS c FROM accounts").fetchone()
        return int(row["c"])

    def _seed_default_sites(self, *, commit: bool = True) -> None:
        defaults = [
            ("ChatGPT 对话", "https://chatgpt.com"),
            ("OpenAI 平台", "https://platform.openai.com"),
            ("Claude 对话", "https://claude.ai"),
            ("Grok 对话", "https://grok.com"),
            ("Gemini 对话", "https://gemini.google.com"),
            ("DeepSeek 对话", "https://chat.deepseek.com"),
            ("GitHub 代码", "https://github.com"),
            ("Gmail 邮箱", "https://mail.google.com"),
            ("Outlook 邮箱", "https://outlook.live.com"),
            ("谷歌搜索", "https://www.google.com"),
            ("必应搜索", "https://www.bing.com"),
            ("百度搜索", "https://www.baidu.com"),
            ("Notion 笔记", "https://www.notion.so"),
        ]
        for i, (name, url) in enumerate(defaults):
            self._conn.execute(
                "INSERT INTO sites (id, name, url, sort_order) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), name, url, i),
            )
        if commit:
            self._conn.commit()

    def should_seed_sample_account(self) -> bool:
        """是否应写入一次性示例账户（仅首次）。"""
        return not bool(self._meta_get("sample_account_seeded"))

    def mark_sample_account_seeded(self) -> None:
        self._meta_set("sample_account_seeded", "1")

    def list_sites(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, name, url, sort_order FROM sites ORDER BY sort_order, name"
            ).fetchall()
            return [dict(r) for r in rows]

    def add_site(self, name: str, url: str) -> dict[str, Any]:
        self._begin_op("添加网站")
        try:
            site_id = str(uuid.uuid4())
            max_row = self._conn.execute(
                "SELECT COALESCE(MAX(sort_order), -1) AS m FROM sites"
            ).fetchone()
            order = int(max_row["m"]) + 1
            self._conn.execute(
                "INSERT INTO sites (id, name, url, sort_order) VALUES (?, ?, ?, ?)",
                (site_id, name.strip(), url.strip(), order),
            )
            self._conn.commit()
            return {"id": site_id, "name": name.strip(), "url": url.strip(), "sort_order": order}
        finally:
            self._end_op()

    def update_site(self, site_id: str, name: str, url: str) -> None:
        self._begin_op("更新网站")
        try:
            self._conn.execute(
                "UPDATE sites SET name = ?, url = ? WHERE id = ?",
                (name.strip(), url.strip(), site_id),
            )
            self._conn.commit()
        finally:
            self._end_op()

    def delete_site(self, site_id: str) -> None:
        self._begin_op("删除网站")
        try:
            self._conn.execute("DELETE FROM sites WHERE id = ?", (site_id,))
            self._conn.commit()
        finally:
            self._end_op()

    # ---- accounts ----
    def list_account_summaries(self, keyword: str = "", category: str = "") -> list[dict[str, Any]]:
        """列表用摘要：不解密密码/密钥，切换列表更快。"""
        with self._lock:
            self._require_unlock()
            sql = (
                "SELECT id, title, category, username, website, updated_at "
                "FROM accounts WHERE 1=1"
            )
            params: list[Any] = []
            if category and category != "全部":
                sql += " AND category = ?"
                params.append(category)
            if keyword.strip():
                sql += " AND (title LIKE ? OR username LIKE ? OR website LIKE ? OR category LIKE ?)"
                kw = f"%{keyword.strip()}%"
                params.extend([kw, kw, kw, kw])
            sql += " ORDER BY updated_at DESC"
            rows = self._conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def list_accounts(self, keyword: str = "", category: str = "") -> list[dict[str, Any]]:
        """完整账户（含解密字段），导出等场景使用。"""
        self._require_unlock()
        summaries = self.list_account_summaries(keyword=keyword, category=category)
        out: list[dict[str, Any]] = []
        for s in summaries:
            full = self.get_account(s["id"])
            if full:
                out.append(full)
        return out

    def get_account(self, account_id: str) -> dict[str, Any] | None:
        with self._lock:
            self._require_unlock()
            cached = self._account_cache.get(account_id)
            if cached is not None:
                return dict(cached)
            row = self._conn.execute(
                "SELECT * FROM accounts WHERE id = ?", (account_id,)
            ).fetchone()
            if not row:
                return None
            acc = self._row_to_account(row)
            self._account_cache[account_id] = acc
            return dict(acc)

    def _row_to_account(self, row: sqlite3.Row) -> dict[str, Any]:
        notes_raw = row["notes"] or ""
        if notes_raw and is_gm_cipher(notes_raw):
            notes = self._dec(notes_raw, strict=False)
        else:
            notes = notes_raw
        return {
            "id": row["id"],
            "title": row["title"],
            "category": row["category"],
            "username": row["username"],
            "password": self._dec(row["password_enc"], strict=False),
            "totp_secret": self._dec(row["totp_secret_enc"], strict=False),
            "website": row["website"],
            "notes": notes,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _normalize_totp(self, raw: str) -> str:
        """规范化 TOTP：保留 otpauth URI 的 algorithm/digits/period；纯密钥则清洗。"""
        s = (raw or "").strip()
        if not s:
            return ""
        if s.lower().startswith("otpauth://"):
            try:
                parsed = urlparse(s)
                qs = parse_qs(parsed.query)
                secret = unquote((qs.get("secret") or [""])[0]).replace(" ", "").upper()
                if not secret:
                    return s
                # 重建标准 URI，保留算法/位数/周期
                label = unquote(parsed.path.lstrip("/") or "Account")
                params = [f"secret={secret}"]
                algo = (qs.get("algorithm") or qs.get("algo") or [""])[0]
                digits = (qs.get("digits") or [""])[0]
                period = (qs.get("period") or qs.get("interval") or [""])[0]
                issuer = (qs.get("issuer") or [""])[0]
                if algo:
                    params.append(f"algorithm={algo.upper()}")
                if digits:
                    params.append(f"digits={digits}")
                if period:
                    params.append(f"period={period}")
                if issuer:
                    params.append(f"issuer={issuer}")
                return f"otpauth://totp/{label}?{'&'.join(params)}"
            except Exception:
                m = re.search(r"[?&]secret=([^&]+)", s, re.I)
                if m:
                    return unquote(m.group(1)).replace(" ", "").upper()
                return s
        return "".join(s.split()).replace("-", "").upper()

    def add_account(self, data: dict[str, Any]) -> dict[str, Any]:
        self._begin_op("添加账户")
        try:
            self._require_unlock()
            account_id = str(uuid.uuid4())
            now = self._now()
            notes = (data.get("notes") or "").strip()
            self._conn.execute(
                """
                INSERT INTO accounts (
                    id, title, category, username, password_enc, totp_secret_enc,
                    website, notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    account_id,
                    data.get("title", "").strip() or "未命名",
                    data.get("category", "其他").strip() or "其他",
                    data.get("username", "").strip(),
                    self._enc(data.get("password", "")),
                    self._enc(self._normalize_totp(data.get("totp_secret", ""))),
                    data.get("website", "").strip(),
                    self._enc(notes) if notes else "",
                    now,
                    now,
                ),
            )
            self._conn.commit()
            self.invalidate_cache()
            return self.get_account(account_id)  # type: ignore[return-value]
        finally:
            self._end_op()

    def add_accounts_batch(self, items: list[dict[str, Any]]) -> int:
        """批量新增，单事务提交，返回成功条数。与换密/关库互斥。"""
        self._begin_op("批量导入", block=False)
        try:
            self._require_unlock()
            if not items:
                return 0
            now = self._now()
            rows = []
            for data in items:
                notes = (data.get("notes") or "").strip()
                rows.append(
                    (
                        str(uuid.uuid4()),
                        data.get("title", "").strip() or "未命名",
                        data.get("category", "其他").strip() or "其他",
                        data.get("username", "").strip(),
                        self._enc(data.get("password", "")),
                        self._enc(self._normalize_totp(data.get("totp_secret", ""))),
                        data.get("website", "").strip(),
                        self._enc(notes) if notes else "",
                        now,
                        now,
                    )
                )
            self._conn.executemany(
                """
                INSERT INTO accounts (
                    id, title, category, username, password_enc, totp_secret_enc,
                    website, notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            self._conn.commit()
            self.invalidate_cache()
            return len(rows)
        except Exception:
            self._conn.rollback()
            raise
        finally:
            self._end_op()

    def update_account(self, account_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        self._begin_op("更新账户")
        try:
            self._require_unlock()
            now = self._now()
            notes = (data.get("notes") or "").strip()
            self._conn.execute(
                """
                UPDATE accounts SET
                    title = ?, category = ?, username = ?, password_enc = ?,
                    totp_secret_enc = ?, website = ?, notes = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    data.get("title", "").strip() or "未命名",
                    data.get("category", "其他").strip() or "其他",
                    data.get("username", "").strip(),
                    self._enc(data.get("password", "")),
                    self._enc(self._normalize_totp(data.get("totp_secret", ""))),
                    data.get("website", "").strip(),
                    self._enc(notes) if notes else "",
                    now,
                    account_id,
                ),
            )
            self._conn.commit()
            self.invalidate_cache(account_id)
            return self.get_account(account_id)
        finally:
            self._end_op()

    def delete_account(self, account_id: str) -> None:
        self._begin_op("删除账户")
        try:
            self._require_unlock()
            self._conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
            self._conn.commit()
            self.invalidate_cache(account_id)
        finally:
            self._end_op()

    def categories(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT category FROM accounts ORDER BY category"
            ).fetchall()
            cats = [r["category"] for r in rows if r["category"]]
            defaults = ["人工智能", "SSH", "RDP", "网站", "邮箱", "社交", "工作", "开发", "其他"]
            merged = []
            for c in defaults + cats:
                if c not in merged:
                    merged.append(c)
            return merged

    def export_json(self, path: Path) -> None:
        """导出为明文 JSON（需已解锁），请妥善保管导出文件。"""
        self._begin_op("导出")
        try:
            self._require_unlock()
            payload = {
                "accounts": self.list_accounts(),
                "sites": self.list_sites(),
                "exported_at": self._now(),
                "warning": "此文件含明文密码，请加密保存或用后删除",
            }
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        finally:
            self._end_op()

    def close(self) -> None:
        self._begin_op("关闭", block=False)
        try:
            self._sm4_key = None
            self._account_cache.clear()
            self.clear_session_pin()
            self._conn.close()
        finally:
            # 连接已关，仍释放锁标记
            self._current_op = None
            try:
                self._lock.release()
            except RuntimeError:
                pass

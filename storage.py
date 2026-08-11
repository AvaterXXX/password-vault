"""本地账户库：敏感字段使用国密 SM4 加密存储。"""
from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from crypto_gm import (
    KDF_ITERATIONS,
    derive_sm4_key,
    fingerprint_key,
    is_gm_cipher,
    make_password_verifier,
    random_salt,
    sm4_decrypt,
    sm4_encrypt,
    try_legacy_fernet_decrypt,
    unlock_with_password,
    verifier_from_key,
    verify_master_password,
)


def app_data_dir() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home() / ".account_vault")
    path = Path(base) / "AccountVault"
    path.mkdir(parents=True, exist_ok=True)
    return path


class VaultLockedError(RuntimeError):
    pass


class VaultStorage:
    def __init__(self, db_path: Path | None = None) -> None:
        self.data_dir = app_data_dir()
        self.db_path = db_path or (self.data_dir / "vault.db")
        self.key_path = self.data_dir / "vault.key"  # 旧版 Fernet 密钥，迁移后删除
        self._sm4_key: Optional[bytes] = None
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    # ---------- 元数据 / 主密码 ----------
    def _init_db(self) -> None:
        self._conn.executescript(
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
            );
            CREATE TABLE IF NOT EXISTS sites (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                sort_order INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        self._conn.commit()
        if self.count_sites() == 0:
            self._seed_default_sites()

    def _meta_get(self, key: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT value FROM vault_meta WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def _meta_set(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO vault_meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
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
        return f"国密 SM3/SM4 · 密钥指纹 {fp}"

    def setup_master_password(self, master_password: str) -> None:
        """首次设置主密码。"""
        if len(master_password) < 6:
            raise ValueError("主密码至少 6 位")
        if self.is_initialized():
            raise ValueError("主密码已设置，请使用解锁")

        salt = random_salt(16)
        iterations = KDF_ITERATIONS
        key = derive_sm4_key(master_password, salt, iterations)
        verifier = verifier_from_key(key, salt)
        self._meta_set("kdf_salt", base64.b64encode(salt).decode("ascii"))
        self._meta_set("kdf_iterations", str(iterations))
        self._meta_set("password_verifier", verifier)
        self._meta_set("crypto_algo", "SM3-KDF+SM4-CBC")
        self._meta_set("crypto_version", "1")

        self._sm4_key = key
        # 迁移旧 Fernet 数据（若有）
        self._migrate_legacy_if_needed()

    def unlock(self, master_password: str) -> None:
        if not self.is_initialized():
            raise ValueError("尚未设置主密码")
        salt_b64 = self._meta_get("kdf_salt") or ""
        verifier = self._meta_get("password_verifier") or ""
        iterations = int(self._meta_get("kdf_iterations") or KDF_ITERATIONS)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        # 一次派生完成校验 + 得到密钥
        self._sm4_key = unlock_with_password(master_password, salt, verifier, iterations)
        self._migrate_legacy_if_needed()

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """更换主密码：先用旧密钥解密，再用新密钥重加密所有敏感字段。"""
        if len(new_password) < 6:
            raise ValueError("新主密码至少 6 位")
        salt_b64 = self._meta_get("kdf_salt") or ""
        verifier = self._meta_get("password_verifier") or ""
        iterations = int(self._meta_get("kdf_iterations") or KDF_ITERATIONS)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        old_key = unlock_with_password(old_password, salt, verifier, iterations)

        rows = self._conn.execute(
            "SELECT id, password_enc, totp_secret_enc, notes FROM accounts"
        ).fetchall()

        # 解密到明文
        plain_rows: list[tuple[str, str, str, str]] = []
        for r in rows:
            pwd = self._dec_with_key(r["password_enc"], old_key)
            totp = self._dec_with_key(r["totp_secret_enc"], old_key)
            notes = self._dec_with_key(r["notes"], old_key) if self._looks_encrypted(r["notes"]) else (r["notes"] or "")
            plain_rows.append((r["id"], pwd, totp, notes))

        # 新盐 + 新密钥
        new_salt = random_salt(16)
        new_key = derive_sm4_key(new_password, new_salt, iterations)
        new_verifier = verifier_from_key(new_key, new_salt)

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

        self._meta_set("kdf_salt", base64.b64encode(new_salt).decode("ascii"))
        self._meta_set("password_verifier", new_verifier)
        self._meta_set("kdf_iterations", str(iterations))
        self._conn.commit()
        self._sm4_key = new_key

    def lock(self) -> None:
        self._sm4_key = None

    def _require_unlock(self) -> bytes:
        if self._sm4_key is None:
            raise VaultLockedError("保险库未解锁")
        return self._sm4_key

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

    def _dec(self, value: str) -> str:
        if not value:
            return ""
        key = self._require_unlock()
        return self._dec_with_key(value, key)

    def _dec_with_key(self, value: str, key: bytes) -> str:
        if not value:
            return ""
        if is_gm_cipher(value):
            try:
                return sm4_decrypt(value, key)
            except Exception:
                return ""
        # 尝试旧 Fernet
        legacy = self._load_legacy_fernet_key()
        plain = try_legacy_fernet_decrypt(value, legacy)
        return plain if plain is not None else ""

    def _load_legacy_fernet_key(self) -> Optional[bytes]:
        if not self.key_path.exists():
            return None
        try:
            return self.key_path.read_bytes().strip()
        except OSError:
            return None

    def _migrate_legacy_if_needed(self) -> None:
        """把旧 Fernet 密文重加密为国密 SM4，并删除 vault.key。"""
        key = self._require_unlock()
        legacy = self._load_legacy_fernet_key()
        rows = self._conn.execute(
            "SELECT id, password_enc, totp_secret_enc, notes FROM accounts"
        ).fetchall()
        changed = False
        for r in rows:
            pid, pw, totp, notes = r["id"], r["password_enc"], r["totp_secret_enc"], r["notes"]
            new_pw, new_totp, new_notes = pw, totp, notes

            if pw and not is_gm_cipher(pw):
                plain = try_legacy_fernet_decrypt(pw, legacy) if legacy else None
                if plain is not None:
                    new_pw = sm4_encrypt(plain, key)
                    changed = True
            if totp and not is_gm_cipher(totp):
                plain = try_legacy_fernet_decrypt(totp, legacy) if legacy else None
                if plain is not None:
                    new_totp = sm4_encrypt(plain, key)
                    changed = True
            # 备注：旧版明文，新版改为加密存储
            if notes and not is_gm_cipher(notes):
                # 若像 Fernet 再尝试；否则当明文迁移
                plain = try_legacy_fernet_decrypt(notes, legacy) if legacy else None
                if plain is None:
                    plain = notes
                new_notes = sm4_encrypt(plain, key)
                changed = True

            if (new_pw, new_totp, new_notes) != (pw, totp, notes):
                self._conn.execute(
                    "UPDATE accounts SET password_enc = ?, totp_secret_enc = ?, notes = ? WHERE id = ?",
                    (new_pw, new_totp, new_notes, pid),
                )

        if changed:
            self._conn.commit()
        # 迁移完成后删除旧密钥文件，避免旁路解密
        if self.key_path.exists():
            try:
                self.key_path.unlink()
            except OSError:
                pass

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ---- sites ----
    def count_sites(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS c FROM sites").fetchone()
        return int(row["c"])

    def _seed_default_sites(self) -> None:
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
        self._conn.commit()

    def list_sites(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id, name, url, sort_order FROM sites ORDER BY sort_order, name"
        ).fetchall()
        return [dict(r) for r in rows]

    def add_site(self, name: str, url: str) -> dict[str, Any]:
        site_id = str(uuid.uuid4())
        max_row = self._conn.execute("SELECT COALESCE(MAX(sort_order), -1) AS m FROM sites").fetchone()
        order = int(max_row["m"]) + 1
        self._conn.execute(
            "INSERT INTO sites (id, name, url, sort_order) VALUES (?, ?, ?, ?)",
            (site_id, name.strip(), url.strip(), order),
        )
        self._conn.commit()
        return {"id": site_id, "name": name.strip(), "url": url.strip(), "sort_order": order}

    def update_site(self, site_id: str, name: str, url: str) -> None:
        self._conn.execute(
            "UPDATE sites SET name = ?, url = ? WHERE id = ?",
            (name.strip(), url.strip(), site_id),
        )
        self._conn.commit()

    def delete_site(self, site_id: str) -> None:
        self._conn.execute("DELETE FROM sites WHERE id = ?", (site_id,))
        self._conn.commit()

    # ---- accounts ----
    def list_account_summaries(self, keyword: str = "", category: str = "") -> list[dict[str, Any]]:
        """列表用摘要：不解密密码/密钥，切换列表更快。"""
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
        self._require_unlock()
        row = self._conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        return self._row_to_account(row) if row else None

    def _row_to_account(self, row: sqlite3.Row) -> dict[str, Any]:
        notes_raw = row["notes"] or ""
        if notes_raw and is_gm_cipher(notes_raw):
            notes = self._dec(notes_raw)
        else:
            notes = notes_raw
        return {
            "id": row["id"],
            "title": row["title"],
            "category": row["category"],
            "username": row["username"],
            "password": self._dec(row["password_enc"]),
            "totp_secret": self._dec(row["totp_secret_enc"]),
            "website": row["website"],
            "notes": notes,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _normalize_totp(self, raw: str) -> str:
        s = (raw or "").strip()
        if s.lower().startswith("otpauth://"):
            m = re.search(r"[?&]secret=([^&]+)", s, re.I)
            if m:
                s = m.group(1)
        return "".join(s.split()).replace("-", "").upper()

    def add_account(self, data: dict[str, Any]) -> dict[str, Any]:
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
        return self.get_account(account_id)  # type: ignore[return-value]

    def update_account(self, account_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
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
        return self.get_account(account_id)

    def delete_account(self, account_id: str) -> None:
        self._require_unlock()
        self._conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        self._conn.commit()

    def categories(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT category FROM accounts ORDER BY category"
        ).fetchall()
        cats = [r["category"] for r in rows if r["category"]]
        defaults = ["人工智能", "邮箱", "社交", "工作", "开发", "其他"]
        merged = []
        for c in defaults + cats:
            if c not in merged:
                merged.append(c)
        return merged

    def export_json(self, path: Path) -> None:
        """导出为明文 JSON（需已解锁），请妥善保管导出文件。"""
        self._require_unlock()
        payload = {
            "accounts": self.list_accounts(),
            "sites": self.list_sites(),
            "exported_at": self._now(),
            "warning": "此文件含明文密码，请加密保存或用后删除",
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def close(self) -> None:
        self.lock()
        self._conn.close()

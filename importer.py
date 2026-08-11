"""批量导入解析：自动识别多种账户格式。"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Any
from urllib.parse import unquote, urlparse


def _blank() -> dict[str, str]:
    return {
        "title": "",
        "category": "其他",
        "username": "",
        "password": "",
        "totp_secret": "",
        "website": "",
        "notes": "",
    }


def _clean_totp(s: str) -> str:
    s = (s or "").strip()
    if s.lower().startswith("otpauth://"):
        m = re.search(r"[?&]secret=([^&]+)", s, re.I)
        if m:
            s = unquote(m.group(1))
    return re.sub(r"[\s\-]+", "", s).upper()


def _norm_account(raw: dict[str, Any]) -> dict[str, str] | None:
    """规范化一条账户；账号或密码或标题至少有一个有效值。"""
    a = _blank()
    for k in a:
        if k in raw and raw[k] is not None:
            a[k] = str(raw[k]).strip()

    # 兼容英文键
    mapping = {
        "name": "title",
        "user": "username",
        "email": "username",
        "login": "username",
        "pass": "password",
        "passwd": "password",
        "pwd": "password",
        "url": "website",
        "host": "website",
        "secret": "totp_secret",
        "totp": "totp_secret",
        "2fa": "totp_secret",
        "otp": "totp_secret",
        "note": "notes",
        "remark": "notes",
        "type": "category",
        "kind": "category",
    }
    for src, dst in mapping.items():
        if src in raw and raw[src] and not a[dst]:
            a[dst] = str(raw[src]).strip()

    if a["totp_secret"]:
        a["totp_secret"] = _clean_totp(a["totp_secret"])

    # 分类中文化
    cat_map = {
        "ai": "人工智能",
        "gpt": "人工智能",
        "chatgpt": "人工智能",
        "openai": "人工智能",
        "ssh": "SSH",
        "rdp": "RDP",
        "web": "网站",
        "website": "网站",
        "url": "网站",
        "mail": "邮箱",
        "email": "邮箱",
        "other": "其他",
    }
    cl = a["category"].strip().lower()
    if cl in cat_map:
        a["category"] = cat_map[cl]
    if not a["category"]:
        a["category"] = "其他"

    if not any([a["title"], a["username"], a["password"], a["website"]]):
        return None
    if not a["title"]:
        a["title"] = a["username"] or a["website"] or "导入账户"
    return a


# ---------- JSON ----------
def parse_json(text: str) -> list[dict[str, str]]:
    data = json.loads(text)
    rows: list[Any]
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = data.get("accounts") or data.get("items") or data.get("data") or []
        if isinstance(rows, dict):
            rows = list(rows.values())
    else:
        return []
    out = []
    for r in rows:
        if isinstance(r, dict):
            n = _norm_account(r)
            if n:
                out.append(n)
    return out


# ---------- CSV / TSV / Chrome ----------
def parse_table(text: str) -> list[dict[str, str]]:
    sample = text.lstrip("\ufeff")
    # 侦测分隔符
    first = sample.splitlines()[0] if sample.splitlines() else ""
    if "\t" in first:
        delim = "\t"
    elif first.count(";") >= 2 and first.count(",") < 2:
        delim = ";"
    else:
        delim = ","

    reader = csv.DictReader(io.StringIO(sample), delimiter=delim)
    if not reader.fieldnames:
        return []

    # 字段名归一
    def key_map(h: str) -> str:
        h0 = (h or "").strip().lower()
        aliases = {
            "title": "title",
            "name": "title",
            "标题": "title",
            "名称": "title",
            "category": "category",
            "分类": "category",
            "type": "category",
            "类型": "category",
            "username": "username",
            "user": "username",
            "email": "username",
            "账号": "username",
            "用户名": "username",
            "邮箱": "username",
            "password": "password",
            "pass": "password",
            "密码": "password",
            "totp_secret": "totp_secret",
            "totp": "totp_secret",
            "2fa": "totp_secret",
            "otp": "totp_secret",
            "secret": "totp_secret",
            "二次验证": "totp_secret",
            "密钥": "totp_secret",
            "website": "website",
            "url": "website",
            "网址": "website",
            "地址": "website",
            "host": "website",
            "notes": "notes",
            "note": "notes",
            "备注": "notes",
            "说明": "notes",
        }
        return aliases.get(h0, h0)

    out = []
    for row in reader:
        mapped: dict[str, Any] = {}
        for k, v in row.items():
            mk = key_map(k or "")
            if mk in ("title", "category", "username", "password", "totp_secret", "website", "notes"):
                mapped[mk] = (v or "").strip()
        # Chrome 导出：name + url
        if "name" in { (k or "").strip().lower() for k in row.keys() } and not mapped.get("title"):
            for k, v in row.items():
                if (k or "").strip().lower() in ("name", "名称"):
                    mapped["title"] = (v or "").strip()
        n = _norm_account(mapped)
        if n:
            # 浏览器导出默认网站分类
            if n["category"] == "其他" and n["website"].startswith("http"):
                n["category"] = "网站"
            out.append(n)
    return out


# ---------- GPT / 通用分隔账号 ----------
_SEP_LINE = re.compile(
    r"^\s*(?P<user>[^\s:|,\-]+(?:@[^\s:|,\-]+)?)\s*"
    r"(?:----|---|--|::|//|\||,|:)\s*"
    r"(?P<pwd>[^\s|]+)"
    r"(?:\s*(?:----|---|--|::|\||,|:)\s*(?P<totp>[A-Za-z2-7= \-]{8,}))?\s*$"
)


def parse_delimited_accounts(text: str, default_category: str = "人工智能") -> list[dict[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        parsed = None
        # 优先按多字符分隔符切分（避免密码吞掉 2FA）
        for sep in ("----", "---", "|", "\t"):
            if sep in line:
                parts = [p.strip() for p in line.split(sep) if p.strip()]
                if len(parts) >= 2:
                    parsed = parts
                break
        if parsed is None and (":" in line or "," in line):
            # email:password 或 email,password（仅两段时）
            for sep in (":", ","):
                if sep in line:
                    parts = [p.strip() for p in line.split(sep, 2)]
                    if len(parts) >= 2 and ("@" in parts[0] or parts[0].isalnum()):
                        parsed = parts
                        break
        if parsed is None:
            m = _SEP_LINE.match(line)
            if m:
                parsed = [m.group("user"), m.group("pwd")]
                if m.group("totp"):
                    parsed.append(m.group("totp"))
        if not parsed or len(parsed) < 2:
            continue
        a = _blank()
        a["username"] = parsed[0]
        a["password"] = parsed[1]
        if len(parsed) >= 3:
            a["totp_secret"] = _clean_totp(parsed[2])
        a["category"] = default_category
        a["title"] = a["username"].split("@")[0] if "@" in a["username"] else a["username"]
        if default_category == "人工智能":
            a["website"] = "https://chatgpt.com"
        n = _norm_account(a)
        if n:
            out.append(n)
    return out


# ---------- SSH ----------
_SSH_URL = re.compile(
    r"^(?:ssh://)?(?:(?P<user>[^:@/\s]+)(?::(?P<pwd>[^@/\s]*))?@)?(?P<host>[^:/\s]+)(?::(?P<port>\d+))?/?$",
    re.I,
)
_SSH_LINE = re.compile(
    r"^(?:ssh\s+)?(?P<user>[^\s@]+)@(?P<host>[^\s:]+)(?::(?P<port>\d+))?(?:\s+(?P<pwd>\S+))?$",
    re.I,
)


def parse_ssh(text: str) -> list[dict[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        a = _blank()
        a["category"] = "SSH"
        # host|port|user|password
        if "|" in line and line.count("|") >= 2:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 3:
                # host|user|pass or host|port|user|pass
                if parts[1].isdigit() and len(parts) >= 4:
                    host, port, user, pwd = parts[0], parts[1], parts[2], parts[3]
                else:
                    host, user, pwd = parts[0], parts[1], parts[2]
                    port = parts[3] if len(parts) > 3 and parts[3].isdigit() else "22"
                a["username"] = user
                a["password"] = pwd
                a["website"] = f"ssh://{user}@{host}:{port}"
                a["title"] = f"SSH {host}"
                a["notes"] = f"主机 {host}\n端口 {port}\n用户 {user}"
                n = _norm_account(a)
                if n:
                    out.append(n)
                continue
        m = _SSH_URL.match(line) or _SSH_LINE.match(line)
        if not m:
            continue
        gd = m.groupdict()
        user = gd.get("user") or ""
        host = gd.get("host") or ""
        port = gd.get("port") or "22"
        pwd = gd.get("pwd") or ""
        a["username"] = user
        a["password"] = pwd
        a["website"] = f"ssh://{user}@{host}:{port}" if user else f"ssh://{host}:{port}"
        a["title"] = f"SSH {host}"
        a["notes"] = f"主机 {host}\n端口 {port}\n用户 {user}"
        n = _norm_account(a)
        if n:
            out.append(n)
    return out


# ---------- RDP ----------
def parse_rdp(text: str) -> list[dict[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        a = _blank()
        a["category"] = "RDP"
        if line.lower().startswith("rdp://"):
            u = urlparse(line)
            user = unquote(u.username or "")
            pwd = unquote(u.password or "")
            host = u.hostname or ""
            port = str(u.port or 3389)
            a["username"] = user
            a["password"] = pwd
            a["website"] = f"rdp://{user}@{host}:{port}" if user else f"rdp://{host}:{port}"
            a["title"] = f"RDP {host}"
            a["notes"] = f"主机 {host}\n端口 {port}\n用户 {user}"
            n = _norm_account(a)
            if n:
                out.append(n)
            continue
        if "|" in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 3:
                if parts[1].isdigit() and len(parts) >= 4:
                    host, port, user, pwd = parts[0], parts[1], parts[2], parts[3]
                else:
                    host, user, pwd = parts[0], parts[1], parts[2]
                    port = "3389"
                a["username"] = user
                a["password"] = pwd
                a["website"] = f"rdp://{user}@{host}:{port}"
                a["title"] = f"RDP {host}"
                a["notes"] = f"主机 {host}\n端口 {port}\n用户 {user}"
                n = _norm_account(a)
                if n:
                    out.append(n)
                continue
        m = re.match(
            r"^(?:rdp\s+)?(?P<user>[^\s@]+)@(?P<host>[^\s:]+)(?::(?P<port>\d+))?(?:\s+(?P<pwd>\S+))?$",
            line,
            re.I,
        )
        if m:
            user, host = m.group("user"), m.group("host")
            port = m.group("port") or "3389"
            pwd = m.group("pwd") or ""
            a["username"] = user
            a["password"] = pwd
            a["website"] = f"rdp://{user}@{host}:{port}"
            a["title"] = f"RDP {host}"
            a["notes"] = f"主机 {host}\n端口 {port}\n用户 {user}"
            n = _norm_account(a)
            if n:
                out.append(n)
    return out


# ---------- 块文本 ----------
_BLOCK_HEAD = re.compile(r"^[=#\-]{2,}\s*(.+?)\s*[=#\-]{2,}$|^【(.+?)】$")


def parse_blocks(text: str) -> list[dict[str, str]]:
    blocks = re.split(r"\n\s*\n", text.strip())
    out = []
    for block in blocks:
        lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
        if len(lines) < 2:
            continue
        a = _blank()
        m0 = _BLOCK_HEAD.match(lines[0])
        if m0:
            a["title"] = (m0.group(1) or m0.group(2) or "").strip()
            body = lines[1:]
        else:
            body = lines
        kv = {
            "账号": "username",
            "用户名": "username",
            "邮箱": "username",
            "user": "username",
            "email": "username",
            "密码": "password",
            "password": "password",
            "pass": "password",
            "2fa": "totp_secret",
            "二次验证": "totp_secret",
            "密钥": "totp_secret",
            "totp": "totp_secret",
            "网址": "website",
            "地址": "website",
            "url": "website",
            "网站": "website",
            "备注": "notes",
            "说明": "notes",
            "分类": "category",
            "类型": "category",
            "标题": "title",
            "名称": "title",
            "主机": "website",
            "host": "website",
        }
        for ln in body:
            if ":" in ln or "：" in ln:
                sep = "：" if "：" in ln else ":"
                k, v = ln.split(sep, 1)
                k, v = k.strip().lower(), v.strip()
                # map chinese keys lowercased poorly — use original
                k_raw = ln.split(sep, 1)[0].strip()
                field = kv.get(k_raw) or kv.get(k)
                if field:
                    a[field] = v
        n = _norm_account(a)
        if n:
            out.append(n)
    return out


def detect_and_parse(text: str, force_format: str = "auto") -> tuple[str, list[dict[str, str]]]:
    """
    返回 (识别到的格式名, 账户列表)。
    force_format: auto|json|csv|gpt|ssh|rdp|block
    """
    text = (text or "").strip().lstrip("\ufeff")
    if not text:
        return ("空", [])

    fmt = force_format.lower().strip()
    if fmt == "auto":
        # 启发式
        if text[0] in "{[":
            fmt = "json"
        elif re.search(r"(?i)^(title|name|username|url|password|账号|标题|名称)\s*[,;\t]", text):
            fmt = "csv"
        elif re.search(r"(?i)^\s*ssh(\s|:|/)", text, re.M) or re.search(
            r"(?m)^\s*[^|\s]+@[^|\s]+(?::\d+)?(?:\s+\S+)?\s*$", text
        ) and "ssh" in text.lower():
            fmt = "ssh"
        elif re.search(r"(?i)^\s*rdp(\s|:|/)", text, re.M) or "rdp://" in text.lower():
            fmt = "rdp"
        elif "----" in text or re.search(r"\S+@\S+\s*(\||----|:)\s*\S+", text):
            fmt = "gpt"
        elif re.search(r"(账号|用户名|密码)\s*[:：]", text):
            fmt = "block"
        elif "," in text.splitlines()[0] and text.count("\n") >= 1:
            fmt = "csv"
        else:
            fmt = "gpt"

    parsers = {
        "json": ("JSON", parse_json),
        "csv": ("CSV/表格", parse_table),
        "tsv": ("CSV/表格", parse_table),
        "chrome": ("浏览器CSV", parse_table),
        "gpt": ("GPT/分隔账号", lambda t: parse_delimited_accounts(t, "人工智能")),
        "ai": ("GPT/分隔账号", lambda t: parse_delimited_accounts(t, "人工智能")),
        "web": ("网站分隔账号", lambda t: parse_delimited_accounts(t, "网站")),
        "ssh": ("SSH", parse_ssh),
        "rdp": ("RDP", parse_rdp),
        "block": ("文本块", parse_blocks),
    }
    if fmt not in parsers:
        fmt = "gpt"
    name, fn = parsers[fmt]
    try:
        items = fn(text)
    except Exception:
        # 回退尝试
        items = []
        for alt in ("json", "csv", "gpt", "ssh", "rdp", "block"):
            if alt == fmt:
                continue
            try:
                items = parsers[alt][1](text)
                if items:
                    name = parsers[alt][0] + "（回退）"
                    break
            except Exception:
                continue
    # 去重：username+password+website
    seen = set()
    uniq = []
    for it in items:
        key = (it.get("username", ""), it.get("password", ""), it.get("website", ""), it.get("title", ""))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(it)
    return name, uniq


FORMAT_HELP = """支持格式（可自动识别）：

1) JSON
{"accounts":[{"title":"…","username":"…","password":"…","totp_secret":"…","website":"…","category":"人工智能"}]}

2) CSV / 浏览器导出（含表头）
title,username,password,totp_secret,website,category,notes
name,url,username,password

3) GPT / AI 账号（每行一条）
邮箱----密码
邮箱----密码----2FA密钥
邮箱|密码|2FA

4) SSH
user@192.168.1.10:22 mypassword
ssh://user:pass@host:22
host|22|user|password

5) RDP
user@192.168.1.20:3389 mypassword
rdp://user:pass@host:3389
host|3389|user|password

6) 文本块（空行分隔）
【公司邮箱】
账号: a@b.com
密码: xxx
网址: https://mail.example.com
"""

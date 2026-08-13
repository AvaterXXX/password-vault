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
    """清洗 TOTP：otpauth URI 保留完整参数；纯密钥则去空白并大写。"""
    s = (s or "").strip()
    if not s:
        return ""
    if s.lower().startswith("otpauth://"):
        # 保留完整 URI，供 pyotp.parse_uri 使用
        return s
    return re.sub(r"[\s\-]+", "", s).upper()


def looks_like_totp_secret(s: str) -> bool:
    """判断字符串是否像 TOTP 密钥或 otpauth URI（避免把密码片段误当 2FA）。"""
    s = (s or "").strip()
    if not s:
        return False
    if s.lower().startswith("otpauth://"):
        return "secret=" in s.lower()
    cleaned = re.sub(r"[\s\-]+", "", s).upper()
    # Base32 字母表 + 可选 padding；常见密钥长度 ≥ 16
    if len(cleaned) < 16:
        return False
    if not re.fullmatch(r"[A-Z2-7]+=*", cleaned):
        return False
    # 去掉 padding 后长度至少 16
    core = cleaned.rstrip("=")
    return len(core) >= 16


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


def _split_user_pass_totp(line: str) -> list[str] | None:
    """将一行解析为 [user, password] 或 [user, password, totp]。

    对冒号分隔：仅当最后一段像 TOTP 密钥时才拆出 2FA，否则把第一段之后全部当作密码
    （避免 alice@x.com:p@ss:word 被截成密码 p@ss）。
    """
    line = line.strip()
    if not line:
        return None

    # 优先按多字符分隔符切分（避免密码吞掉 2FA）
    for sep in ("----", "---", "|", "\t"):
        if sep in line:
            parts = [p.strip() for p in line.split(sep) if p.strip()]
            if len(parts) >= 2:
                if len(parts) >= 3 and not looks_like_totp_secret(parts[-1]):
                    # 末段不像 TOTP：合并为密码
                    return [parts[0], sep.join(parts[1:])]
                return parts[:3] if len(parts) >= 3 else parts[:2]
            break

    # email:password[:totp?] 或 email,password
    for sep in (":", ","):
        if sep not in line:
            continue
        # 用户名取第一段；需含 @ 或看起来像账号
        first, rest = line.split(sep, 1)
        first, rest = first.strip(), rest.strip()
        if not rest or not ("@" in first or first.replace("_", "").isalnum()):
            continue
        if sep == ":":
            # rest 可能是 password 或 password:totp 或 p@ss:word（密码含冒号）
            if ":" in rest:
                # 从右侧尝试：最后一段若像 TOTP 则拆出
                left, maybe_totp = rest.rsplit(":", 1)
                left, maybe_totp = left.strip(), maybe_totp.strip()
                if left and looks_like_totp_secret(maybe_totp):
                    return [first, left, maybe_totp]
                # 否则整段 rest 都是密码
                return [first, rest]
            return [first, rest]
        # 逗号：最多拆三段
        parts = [first] + [p.strip() for p in rest.split(",", 1)]
        parts = [p for p in parts if p]
        if len(parts) >= 3 and not looks_like_totp_secret(parts[2]):
            return [parts[0], ",".join(parts[1:])]
        return parts[:3] if len(parts) >= 3 else parts[:2]

    m = _SEP_LINE.match(line)
    if m:
        parsed = [m.group("user"), m.group("pwd")]
        if m.group("totp") and looks_like_totp_secret(m.group("totp")):
            parsed.append(m.group("totp"))
        return parsed
    return None


def parse_delimited_accounts(text: str, default_category: str = "人工智能") -> list[dict[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        parsed = _split_user_pass_totp(line)
        if not parsed or len(parsed) < 2:
            continue
        a = _blank()
        a["username"] = parsed[0]
        a["password"] = parsed[1]
        if len(parsed) >= 3 and looks_like_totp_secret(parsed[2]):
            a["totp_secret"] = _clean_totp(parsed[2])
        a["category"] = default_category
        a["title"] = a["username"].split("@")[0] if "@" in a["username"] else a["username"]
        if default_category == "人工智能":
            a["website"] = "https://chatgpt.com"
        n = _norm_account(a)
        if n:
            out.append(n)
    return out


# user@host:port password （SSH/RDP 文档格式）
_HOST_PORT_PASS = re.compile(
    r"^(?P<user>[^\s@]+)@(?P<host>[^\s:]+):(?P<port>\d+)\s+(?P<pwd>\S+)\s*$",
    re.I,
)


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


def _looks_like_ssh_line(line: str) -> bool:
    s = line.strip()
    if not s:
        return False
    if s.lower().startswith("ssh://") or s.lower().startswith("ssh "):
        return True
    m = _HOST_PORT_PASS.match(s)
    if m and m.group("port") not in ("3389", "3390"):
        # 22 等常见 SSH 端口，或非 3389
        return True
    if "|" in s and s.count("|") >= 2:
        parts = [p.strip() for p in s.split("|")]
        if len(parts) >= 4 and parts[1].isdigit() and parts[1] not in ("3389", "3390"):
            return True
    return False


def _looks_like_rdp_line(line: str) -> bool:
    s = line.strip()
    if not s:
        return False
    if s.lower().startswith("rdp://") or s.lower().startswith("rdp "):
        return True
    m = _HOST_PORT_PASS.match(s)
    if m and m.group("port") in ("3389", "3390"):
        return True
    if "|" in s and s.count("|") >= 2:
        parts = [p.strip() for p in s.split("|")]
        if len(parts) >= 4 and parts[1] in ("3389", "3390"):
            return True
    return False


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
        lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        # 启发式（SSH/RDP 优先于 GPT，避免 user@host:22 pass 被当成邮箱账号）
        if text[0] in "{[":
            fmt = "json"
        elif re.search(r"(?i)^(title|name|username|url|password|账号|标题|名称)\s*[,;\t]", text):
            fmt = "csv"
        elif (
            re.search(r"(?i)^\s*ssh(\s|:|/)", text, re.M)
            or "ssh://" in text.lower()
            or (lines and all(_looks_like_ssh_line(ln) or _looks_like_rdp_line(ln) for ln in lines)
                and any(_looks_like_ssh_line(ln) for ln in lines)
                and not any(_looks_like_rdp_line(ln) for ln in lines))
            or (lines and all(_looks_like_ssh_line(ln) for ln in lines))
        ):
            fmt = "ssh"
        elif (
            re.search(r"(?i)^\s*rdp(\s|:|/)", text, re.M)
            or "rdp://" in text.lower()
            or (lines and all(_looks_like_rdp_line(ln) for ln in lines))
        ):
            fmt = "rdp"
        elif lines and all(_looks_like_ssh_line(ln) or _looks_like_rdp_line(ln) for ln in lines):
            # 混合：按多数
            ssh_n = sum(1 for ln in lines if _looks_like_ssh_line(ln))
            rdp_n = sum(1 for ln in lines if _looks_like_rdp_line(ln))
            fmt = "rdp" if rdp_n > ssh_n else "ssh"
        elif "----" in text or re.search(r"\S+@\S+\s*(\||----)\s*\S+", text):
            fmt = "gpt"
        elif re.search(r"(账号|用户名|密码)\s*[:：]", text):
            fmt = "block"
        elif "," in text.splitlines()[0] and text.count("\n") >= 1:
            fmt = "csv"
        elif re.search(r"\S+@\S+:\S+", text):
            # email:password — 仅当不像 host:port 时
            if lines and all(_HOST_PORT_PASS.match(ln) for ln in lines):
                # 再保险：端口 3389 → rdp，否则 ssh
                if all((_HOST_PORT_PASS.match(ln).group("port") in ("3389", "3390")) for ln in lines):  # type: ignore
                    fmt = "rdp"
                else:
                    fmt = "ssh"
            else:
                fmt = "gpt"
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

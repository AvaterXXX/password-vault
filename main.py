#!/usr/bin/env python3
"""密码保险柜 — 本地账户密码 / 二次验证管理（白色界面 · 国密加密）。"""
from __future__ import annotations

import re
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any

import customtkinter as ctk
import pyotp
from tkinter import messagebox

from storage import VaultStorage


def app_base_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent


def apply_window_icon(win: Any) -> None:
    """设置窗口/任务栏图标（钥匙）。"""
    candidates = [
        app_base_dir() / "assets" / "app.ico",
        app_base_dir() / "app.ico",
        Path(__file__).resolve().parent / "assets" / "app.ico",
    ]
    for ico in candidates:
        if ico.exists():
            try:
                win.iconbitmap(default=str(ico))
            except Exception:
                try:
                    win.iconbitmap(str(ico))
                except Exception:
                    pass
            return

# ---- 白色主题 ----
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

BG = "#FFFFFF"
BG_SOFT = "#F7F8FA"
BG_SIDE = "#F3F4F6"
BORDER = "#E5E7EB"
TEXT = "#111827"
TEXT_MUTED = "#6B7280"
PRIMARY = "#2563EB"
PRIMARY_HOVER = "#1D4ED8"
DANGER = "#DC2626"
DANGER_SOFT = "#FEF2F2"
SUCCESS = "#059669"
CARD = "#FFFFFF"
ACCENT_LINE = "#DBEAFE"
DROPDOWN_HOVER = "#EFF6FF"
MENU_SHADOW = "#E8EAF0"


def make_combo(master: Any, values: list[str], command: Any = None, soft: bool = False) -> ctk.CTkComboBox:
    """统一白色风格下拉框。"""
    return ctk.CTkComboBox(
        master,
        values=values,
        command=command,
        height=34,
        corner_radius=8,
        border_width=1,
        border_color=BORDER,
        fg_color=BG_SOFT if soft else BG,
        button_color="#EEF2FF",
        button_hover_color="#DBEAFE",
        text_color=TEXT,
        text_color_disabled=TEXT_MUTED,
        dropdown_fg_color=BG,
        dropdown_hover_color=DROPDOWN_HOVER,
        dropdown_text_color=TEXT,
        dropdown_font=ctk.CTkFont(size=13),
        font=ctk.CTkFont(size=13),
    )


class PrettyPopupMenu:
    """白色卡片式右键菜单（替代系统 Menu）。"""

    def __init__(self, master: ctk.CTk) -> None:
        self.master = master
        self._win: ctk.CTkToplevel | None = None
        self._outside_id: str | None = None

    def close(self) -> None:
        if self._outside_id is not None:
            try:
                self.master.unbind("<Button-1>", self._outside_id)
            except Exception:
                try:
                    self.master.unbind("<Button-1>")
                except Exception:
                    pass
            self._outside_id = None
        if self._win is not None:
            try:
                self._win.destroy()
            except Exception:
                pass
            self._win = None

    def show(self, x: int, y: int, items: list[dict[str, Any]]) -> None:
        self.close()
        win = ctk.CTkToplevel(self.master)
        self._win = win
        win.withdraw()
        win.overrideredirect(True)
        win.configure(fg_color=BORDER)
        try:
            win.attributes("-topmost", True)
        except Exception:
            pass

        card = ctk.CTkFrame(
            win,
            fg_color=BG,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
        )
        card.pack(fill="both", expand=True, padx=1, pady=1)

        # 小标题
        ctk.CTkLabel(
            card,
            text="快捷操作",
            font=ctk.CTkFont(size=11),
            text_color=TEXT_MUTED,
            anchor="w",
        ).pack(fill="x", padx=14, pady=(10, 4))

        def run_and_close(fn: Any) -> None:
            self.close()
            if fn:
                self.master.after(10, fn)

        for it in items:
            kind = it.get("kind", "item")
            if kind == "sep":
                ctk.CTkFrame(card, fg_color=BORDER, height=1).pack(fill="x", padx=12, pady=5)
                continue
            danger = kind == "danger"
            ctk.CTkButton(
                card,
                text=it.get("text", ""),
                anchor="w",
                height=38,
                corner_radius=8,
                fg_color="transparent",
                hover_color=DANGER_SOFT if danger else DROPDOWN_HOVER,
                text_color=DANGER if danger else TEXT,
                font=ctk.CTkFont(size=13),
                border_width=0,
                command=lambda f=it.get("command"): run_and_close(f),
            ).pack(fill="x", padx=8, pady=2)

        # 底部留白
        ctk.CTkFrame(card, fg_color="transparent", height=6).pack()

        win.update_idletasks()
        w = max(172, win.winfo_reqwidth())
        h = win.winfo_reqheight()
        try:
            sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
            x = min(max(0, x), sw - w - 8)
            y = min(max(0, y), sh - h - 8)
        except Exception:
            pass
        win.geometry(f"{w}x{h}+{x}+{y}")
        win.deiconify()
        try:
            win.focus_force()
        except Exception:
            pass

        win.bind("<Escape>", lambda _e: self.close())
        win.bind("<FocusOut>", lambda _e: win.after(150, self._maybe_close))

        def on_root_click(e: Any) -> None:
            if self._win is None:
                return
            try:
                wx, wy = self._win.winfo_rootx(), self._win.winfo_rooty()
                ww, wh = self._win.winfo_width(), self._win.winfo_height()
                if not (wx <= e.x_root <= wx + ww and wy <= e.y_root <= wy + wh):
                    self.close()
            except Exception:
                self.close()

        self._outside_id = self.master.bind("<Button-1>", on_root_click, add="+")

    def _maybe_close(self) -> None:
        if self._win is None:
            return
        try:
            focused = self._win.focus_displayof()
            if focused is None:
                self.close()
        except Exception:
            self.close()


def pretty_confirm(master: Any, title: str, message: str) -> bool:
    """白色风格确认框，替代系统 messagebox。"""
    result = {"ok": False}
    dlg = ctk.CTkToplevel(master)
    dlg.title(title)
    dlg.geometry("380x200")
    dlg.resizable(False, False)
    dlg.configure(fg_color=BG)
    dlg.transient(master)
    dlg.grab_set()
    dlg.update_idletasks()
    try:
        sw, sh = dlg.winfo_screenwidth(), dlg.winfo_screenheight()
        dlg.geometry(f"380x200+{(sw - 380) // 2}+{(sh - 200) // 2}")
    except Exception:
        pass

    ctk.CTkLabel(
        dlg,
        text=title,
        font=ctk.CTkFont(size=16, weight="bold"),
        text_color=TEXT,
    ).pack(anchor="w", padx=24, pady=(22, 8))
    ctk.CTkLabel(
        dlg,
        text=message,
        font=ctk.CTkFont(size=13),
        text_color=TEXT_MUTED,
        wraplength=320,
        justify="left",
    ).pack(anchor="w", padx=24, pady=(0, 16))

    row = ctk.CTkFrame(dlg, fg_color="transparent")
    row.pack(fill="x", padx=24, pady=(0, 20))

    def yes() -> None:
        result["ok"] = True
        dlg.destroy()

    def no() -> None:
        result["ok"] = False
        dlg.destroy()

    ctk.CTkButton(
        row,
        text="取消",
        width=100,
        height=36,
        corner_radius=8,
        fg_color="#F3F4F6",
        hover_color="#E5E7EB",
        text_color=TEXT,
        command=no,
    ).pack(side="right", padx=(8, 0))
    ctk.CTkButton(
        row,
        text="确定",
        width=100,
        height=36,
        corner_radius=8,
        fg_color=DANGER,
        hover_color="#B91C1C",
        command=yes,
    ).pack(side="right")

    dlg.protocol("WM_DELETE_WINDOW", no)
    master.wait_window(dlg)
    return result["ok"]


class UnlockDialog(ctk.CTkToplevel):
    """主密码解锁 / 首次设置（国密 SM3+SM4）。"""

    def __init__(self, storage: VaultStorage) -> None:
        super().__init__()
        self.storage = storage
        self.result_ok = False
        self.title("密码保险柜 · 国密加密解锁")
        self.geometry("440x420")
        self.resizable(False, False)
        self.configure(fg_color=BG)
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        apply_window_icon(self)

        first = not storage.is_initialized()
        title = "设置主密码（首次使用）" if first else "输入主密码解锁"
        tip = (
            "主密码用于派生国密 SM4 密钥，加密本地密码与二次验证密钥。\n"
            "主密码不会保存到磁盘；忘记后无法找回密文内容。\n"
            "请使用至少 6 位、尽量复杂的主密码。"
            if first
            else "数据已用国密 SM3/SM4 加密存储。\n请输入主密码解锁保险库。"
        )

        ctk.CTkLabel(
            self,
            text=title,
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=TEXT,
        ).pack(anchor="w", padx=28, pady=(28, 8))
        ctk.CTkLabel(
            self,
            text=tip,
            font=ctk.CTkFont(size=12),
            text_color=TEXT_MUTED,
            justify="left",
            wraplength=380,
        ).pack(anchor="w", padx=28, pady=(0, 14))

        ctk.CTkLabel(self, text="主密码", text_color=TEXT_MUTED).pack(anchor="w", padx=28)
        self.pw1 = ctk.CTkEntry(
            self, show="•", height=36, fg_color=BG_SOFT, border_color=BORDER, text_color=TEXT
        )
        self.pw1.pack(fill="x", padx=28, pady=(4, 10))
        self.pw1.bind("<Return>", lambda _e: self._submit())

        self.pw2: ctk.CTkEntry | None = None
        if first:
            ctk.CTkLabel(self, text="确认主密码", text_color=TEXT_MUTED).pack(anchor="w", padx=28)
            self.pw2 = ctk.CTkEntry(
                self, show="•", height=36, fg_color=BG_SOFT, border_color=BORDER, text_color=TEXT
            )
            self.pw2.pack(fill="x", padx=28, pady=(4, 10))
            self.pw2.bind("<Return>", lambda _e: self._submit())

        self.err = ctk.CTkLabel(self, text="", text_color=DANGER)
        self.err.pack(anchor="w", padx=28, pady=(0, 8))

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=28, pady=(8, 20))
        ctk.CTkButton(
            btn_row,
            text="确定" if not first else "创建保险库",
            height=38,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            command=self._submit,
        ).pack(side="left", expand=True, fill="x", padx=(0, 8))
        ctk.CTkButton(
            btn_row,
            text="退出",
            height=38,
            width=90,
            fg_color="#E5E7EB",
            hover_color="#D1D5DB",
            text_color=TEXT,
            command=self._cancel,
        ).pack(side="right")

        self._first = first
        self.after(100, self.pw1.focus_set)
        self.update_idletasks()
        try:
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            w, h = 440, 420
            self.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")
        except Exception:
            pass

    def _cancel(self) -> None:
        self.result_ok = False
        self.destroy()

    def _submit(self) -> None:
        p1 = self.pw1.get()
        if self._first:
            p2 = self.pw2.get() if self.pw2 else ""
            if len(p1) < 6:
                self.err.configure(text="主密码至少 6 位")
                return
            if p1 != p2:
                self.err.configure(text="两次输入的主密码不一致")
                return
            try:
                self.storage.setup_master_password(p1)
            except Exception as e:
                self.err.configure(text=str(e))
                return
        else:
            try:
                self.storage.unlock(p1)
            except Exception as e:
                self.err.configure(text=str(e))
                return
        self.result_ok = True
        self.destroy()

# 复制提示用中文名称
FIELD_CN = {
    "title": "标题",
    "category": "分类",
    "username": "账号",
    "password": "密码",
    "totp_secret": "二次验证密钥",
    "website": "网站地址",
    "notes": "备注",
}


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not re.match(r"^https?://", url, re.I):
        return "https://" + url
    return url


def normalize_totp_secret(raw: str) -> str:
    """支持密钥或 otpauth 链接，返回清洗后的密钥。"""
    raw = (raw or "").strip()
    if not raw:
        return ""
    if raw.lower().startswith("otpauth://"):
        m = re.search(r"[?&]secret=([^&]+)", raw, re.I)
        if m:
            raw = m.group(1)
    secret = re.sub(r"[\s\-]+", "", raw).upper()
    pad = (-len(secret)) % 8
    if pad:
        secret += "=" * pad
    return secret


def totp_code(secret: str) -> tuple[str, int]:
    secret = normalize_totp_secret(secret)
    if not secret:
        return ("", 0)
    try:
        totp = pyotp.TOTP(secret)
        code = totp.now()
        remaining = 30 - (int(time.time()) % 30)
        return (code, remaining)
    except Exception:
        return ("无效密钥", 0)


class AccountVaultApp(ctk.CTk):
    def __init__(self, storage: VaultStorage) -> None:
        super().__init__()
        self.title("密码保险柜 · 账户密码 / 二次验证管理")
        self.geometry("1220x740")
        self.minsize(1000, 640)
        self.configure(fg_color=BG)
        apply_window_icon(self)

        self.storage = storage
        self.selected_id: str | None = None
        self._show_password = False
        # 列表项：id -> {frame, title_lbl, sub_lbl}
        self._account_items: dict[str, dict[str, Any]] = {}
        self._site_menu_target: dict[str, Any] | None = None
        self._search_after_id: str | None = None
        self._list_version = 0

        self._build_ui()
        self._build_site_context_menu()
        self.refresh_sites()
        self.refresh_accounts()
        self._tick_totp()
        self._update_crypto_label()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------- 界面 ----------------
    def _build_ui(self) -> None:
        # 三列：账户列表 | 详情 | 常用网站
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        root = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        root.grid(row=0, column=0, sticky="nsew")
        # 列表稍宽，减少账号被截断
        root.grid_columnconfigure(0, weight=4, minsize=260)
        root.grid_columnconfigure(1, weight=5)
        root.grid_columnconfigure(2, weight=0)
        root.grid_rowconfigure(1, weight=1)

        # ---- 顶栏 ----
        top = ctk.CTkFrame(root, fg_color=BG, corner_radius=0)
        top.grid(row=0, column=0, columnspan=3, sticky="ew", padx=16, pady=(14, 8))
        top.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            top,
            text="密码保险柜",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=TEXT,
        ).grid(row=0, column=0, sticky="w")

        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._schedule_search_refresh())
        ctk.CTkEntry(
            top,
            textvariable=self.search_var,
            placeholder_text="搜索标题 / 账号 / 网站…",
            height=36,
            fg_color=BG_SOFT,
            border_color=BORDER,
            text_color=TEXT,
        ).grid(row=0, column=1, sticky="ew", padx=16)

        ctk.CTkButton(
            top,
            text="修改主密码",
            width=100,
            height=36,
            fg_color="#E5E7EB",
            hover_color="#D1D5DB",
            text_color=TEXT,
            command=self._change_master_password_dialog,
        ).grid(row=0, column=2, sticky="e", padx=(0, 8))

        ctk.CTkButton(
            top,
            text="+ 新建账户",
            width=120,
            height=36,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            command=self._new_account,
        ).grid(row=0, column=3, sticky="e")

        # ---- 左：账户列表 ----
        left = ctk.CTkFrame(root, fg_color=BG_SOFT, corner_radius=12, border_width=1, border_color=BORDER)
        left.grid(row=1, column=0, sticky="nsew", padx=(16, 8), pady=(0, 16))
        left.grid_rowconfigure(2, weight=1)
        left.grid_columnconfigure(0, weight=1)

        filter_row = ctk.CTkFrame(left, fg_color="transparent")
        filter_row.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        filter_row.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(filter_row, text="分类", text_color=TEXT_MUTED).grid(row=0, column=0, sticky="w")
        self.category_filter = make_combo(
            filter_row,
            values=["全部"],
            command=lambda _=None: self.refresh_accounts(),
            soft=False,
        )
        self.category_filter.set("全部")
        self.category_filter.grid(row=0, column=1, sticky="ew", padx=(6, 0))

        ctk.CTkLabel(
            left,
            text="账户列表",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=TEXT,
        ).grid(row=1, column=0, sticky="w", padx=8, pady=(0, 2))

        # 列表贴边，少占空白
        self.account_list = ctk.CTkScrollableFrame(left, fg_color="transparent")
        self.account_list.grid(row=2, column=0, sticky="nsew", padx=4, pady=(0, 6))
        self.account_list.grid_columnconfigure(0, weight=1)
        try:
            self.account_list._scrollbar.configure(width=10)  # type: ignore[attr-defined]
        except Exception:
            pass

        # ---- 中：账户详情 ----
        mid = ctk.CTkFrame(root, fg_color=CARD, corner_radius=12, border_width=1, border_color=BORDER)
        mid.grid(row=1, column=1, sticky="nsew", padx=8, pady=(0, 16))
        mid.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            mid,
            text="账户详情",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=TEXT,
        ).grid(row=0, column=0, columnspan=3, sticky="w", padx=18, pady=(16, 10))

        self.fields: dict[str, ctk.CTkEntry | ctk.CTkTextbox | ctk.CTkComboBox] = {}
        labels = [
            ("title", "标题 / 用途"),
            ("category", "分类"),
            ("username", "账号 / 邮箱"),
            ("password", "密码"),
            ("totp_secret", "二次验证密钥"),
            ("website", "网站地址"),
            ("notes", "备注"),
        ]
        row = 1
        for key, label in labels:
            ctk.CTkLabel(mid, text=label, text_color=TEXT_MUTED, anchor="w").grid(
                row=row, column=0, sticky="w", padx=(18, 8), pady=6
            )
            if key == "notes":
                widget: Any = ctk.CTkTextbox(
                    mid,
                    height=70,
                    fg_color=BG_SOFT,
                    border_width=1,
                    border_color=BORDER,
                    text_color=TEXT,
                )
                widget.grid(row=row, column=1, columnspan=2, sticky="ew", padx=(0, 18), pady=6)
            elif key == "category":
                widget = make_combo(
                    mid,
                    values=self.storage.categories(),
                    soft=True,
                )
                widget.set("其他")
                widget.grid(row=row, column=1, columnspan=2, sticky="ew", padx=(0, 18), pady=6)
            elif key == "password":
                pw_frame = ctk.CTkFrame(mid, fg_color="transparent")
                pw_frame.grid(row=row, column=1, columnspan=2, sticky="ew", padx=(0, 18), pady=6)
                pw_frame.grid_columnconfigure(0, weight=1)
                widget = ctk.CTkEntry(
                    pw_frame,
                    show="•",
                    fg_color=BG_SOFT,
                    border_color=BORDER,
                    text_color=TEXT,
                    height=34,
                )
                widget.grid(row=0, column=0, sticky="ew")
                ctk.CTkButton(
                    pw_frame,
                    text="显示",
                    width=56,
                    height=34,
                    fg_color="#E5E7EB",
                    hover_color="#D1D5DB",
                    text_color=TEXT,
                    command=self._toggle_password,
                ).grid(row=0, column=1, padx=(6, 0))
                ctk.CTkButton(
                    pw_frame,
                    text="复制",
                    width=56,
                    height=34,
                    fg_color=ACCENT_LINE,
                    hover_color="#BFDBFE",
                    text_color=PRIMARY,
                    command=lambda: self._copy_field("password"),
                ).grid(row=0, column=2, padx=(6, 0))
            elif key == "totp_secret":
                t_frame = ctk.CTkFrame(mid, fg_color="transparent")
                t_frame.grid(row=row, column=1, columnspan=2, sticky="ew", padx=(0, 18), pady=6)
                t_frame.grid_columnconfigure(0, weight=1)
                widget = ctk.CTkEntry(
                    t_frame,
                    fg_color=BG_SOFT,
                    border_color=BORDER,
                    text_color=TEXT,
                    height=34,
                    placeholder_text="粘贴密钥后下方自动显示验证码",
                )
                widget.grid(row=0, column=0, sticky="ew")
                widget.bind("<KeyRelease>", lambda _e: self._refresh_totp_display())
                widget.bind("<<Paste>>", lambda _e: self.after(10, self._refresh_totp_display))
                widget.bind("<FocusOut>", lambda _e: self._refresh_totp_display())
                ctk.CTkButton(
                    t_frame,
                    text="复制密钥",
                    width=72,
                    height=34,
                    fg_color=ACCENT_LINE,
                    hover_color="#BFDBFE",
                    text_color=PRIMARY,
                    command=lambda: self._copy_field("totp_secret"),
                ).grid(row=0, column=1, padx=(6, 0))
            elif key == "username":
                u_frame = ctk.CTkFrame(mid, fg_color="transparent")
                u_frame.grid(row=row, column=1, columnspan=2, sticky="ew", padx=(0, 18), pady=6)
                u_frame.grid_columnconfigure(0, weight=1)
                widget = ctk.CTkEntry(
                    u_frame,
                    fg_color=BG_SOFT,
                    border_color=BORDER,
                    text_color=TEXT,
                    height=34,
                )
                widget.grid(row=0, column=0, sticky="ew")
                ctk.CTkButton(
                    u_frame,
                    text="复制",
                    width=56,
                    height=34,
                    fg_color=ACCENT_LINE,
                    hover_color="#BFDBFE",
                    text_color=PRIMARY,
                    command=lambda: self._copy_field("username"),
                ).grid(row=0, column=1, padx=(6, 0))
            elif key == "website":
                w_frame = ctk.CTkFrame(mid, fg_color="transparent")
                w_frame.grid(row=row, column=1, columnspan=2, sticky="ew", padx=(0, 18), pady=6)
                w_frame.grid_columnconfigure(0, weight=1)
                widget = ctk.CTkEntry(
                    w_frame,
                    fg_color=BG_SOFT,
                    border_color=BORDER,
                    text_color=TEXT,
                    height=34,
                    placeholder_text="例如 https://chatgpt.com",
                )
                widget.grid(row=0, column=0, sticky="ew")
                ctk.CTkButton(
                    w_frame,
                    text="打开",
                    width=56,
                    height=34,
                    fg_color=PRIMARY,
                    hover_color=PRIMARY_HOVER,
                    command=self._open_website,
                ).grid(row=0, column=1, padx=(6, 0))
                ctk.CTkButton(
                    w_frame,
                    text="复制",
                    width=56,
                    height=34,
                    fg_color=ACCENT_LINE,
                    hover_color="#BFDBFE",
                    text_color=PRIMARY,
                    command=lambda: self._copy_field("website"),
                ).grid(row=0, column=2, padx=(6, 0))
            else:
                widget = ctk.CTkEntry(
                    mid,
                    fg_color=BG_SOFT,
                    border_color=BORDER,
                    text_color=TEXT,
                    height=34,
                )
                widget.grid(row=row, column=1, columnspan=2, sticky="ew", padx=(0, 18), pady=6)
            self.fields[key] = widget
            row += 1

        # 二次验证码面板
        totp_panel = ctk.CTkFrame(mid, fg_color="#EFF6FF", corner_radius=10, border_width=1, border_color=ACCENT_LINE)
        totp_panel.grid(row=row, column=0, columnspan=3, sticky="ew", padx=18, pady=(10, 6))
        totp_panel.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            totp_panel,
            text="当前验证码\n（输入密钥后自动生成）",
            text_color=TEXT_MUTED,
            justify="left",
        ).grid(row=0, column=0, padx=14, pady=12, sticky="w")
        self.totp_code_label = ctk.CTkLabel(
            totp_panel,
            text="—— ——",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=PRIMARY,
        )
        self.totp_code_label.grid(row=0, column=1, padx=8, pady=12)
        self.totp_remain_label = ctk.CTkLabel(totp_panel, text="", text_color=TEXT_MUTED)
        self.totp_remain_label.grid(row=0, column=2, padx=8, pady=12)
        ctk.CTkButton(
            totp_panel,
            text="复制验证码",
            width=100,
            height=34,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            command=self._copy_totp_code,
        ).grid(row=0, column=3, padx=14, pady=12)
        row += 1

        actions = ctk.CTkFrame(mid, fg_color="transparent")
        actions.grid(row=row, column=0, columnspan=3, sticky="ew", padx=18, pady=(12, 18))
        actions.grid_columnconfigure(4, weight=1)

        ctk.CTkButton(
            actions,
            text="保存",
            width=100,
            height=36,
            fg_color=SUCCESS,
            hover_color="#047857",
            command=self._save_account,
        ).grid(row=0, column=0, padx=(0, 8))

        ctk.CTkButton(
            actions,
            text="清空表单",
            width=100,
            height=36,
            fg_color="#E5E7EB",
            hover_color="#D1D5DB",
            text_color=TEXT,
            command=self._clear_form,
        ).grid(row=0, column=1, padx=(0, 8))

        ctk.CTkButton(
            actions,
            text="删除账户",
            width=100,
            height=36,
            fg_color=DANGER,
            hover_color="#B91C1C",
            command=self._delete_account,
        ).grid(row=0, column=2, padx=(0, 8))

        self.status_label = ctk.CTkLabel(actions, text="", text_color=TEXT_MUTED)
        self.status_label.grid(row=0, column=4, sticky="e")

        # ---- 右：常用网站 ----
        side = ctk.CTkFrame(root, fg_color=BG_SIDE, corner_radius=0, width=210)
        side.grid(row=1, column=2, sticky="nsew", pady=(0, 0))
        side.grid_propagate(False)
        side.grid_rowconfigure(3, weight=1)
        side.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            side,
            text="常用网站",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=TEXT,
        ).grid(row=0, column=0, padx=14, pady=(8, 2), sticky="w")

        ctk.CTkLabel(
            side,
            text="左键打开 · 右键删除",
            font=ctk.CTkFont(size=11),
            text_color=TEXT_MUTED,
        ).grid(row=1, column=0, padx=14, pady=(0, 8), sticky="w")

        ctk.CTkButton(
            side,
            text="+ 添加网站",
            height=32,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            command=self._add_site_dialog,
        ).grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 8))

        self.site_list = ctk.CTkScrollableFrame(side, fg_color="transparent")
        self.site_list.grid(row=3, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self.site_list.grid_columnconfigure(0, weight=1)

        self.crypto_label = ctk.CTkLabel(
            side,
            text="国密 SM3/SM4 加密",
            font=ctk.CTkFont(size=11),
            text_color=SUCCESS,
            wraplength=180,
            justify="left",
        )
        self.crypto_label.grid(row=4, column=0, padx=14, pady=(0, 14), sticky="w")

    def _build_site_context_menu(self) -> None:
        self.site_popup = PrettyPopupMenu(self)

    # ---------------- 数据刷新 ----------------
    def refresh_sites(self) -> None:
        for w in self.site_list.winfo_children():
            w.destroy()
        for site in self.storage.list_sites():
            btn = ctk.CTkButton(
                self.site_list,
                text=site["name"],
                anchor="w",
                height=36,
                corner_radius=8,
                fg_color=BG,
                hover_color=DROPDOWN_HOVER,
                text_color=TEXT,
                border_width=1,
                border_color=BORDER,
                font=ctk.CTkFont(size=13),
                command=lambda u=site["url"]: self._open_url(u),
            )
            btn.grid(sticky="ew", pady=3, padx=4)
            # 右键菜单（Windows: Button-3）
            btn.bind(
                "<Button-3>",
                lambda e, s=site: self._show_site_menu(e, s),
            )
            # 部分触控板/环境
            btn.bind(
                "<Button-2>",
                lambda e, s=site: self._show_site_menu(e, s),
            )

    def _show_site_menu(self, event: Any, site: dict[str, Any]) -> None:
        self._site_menu_target = site
        self.site_popup.show(
            event.x_root,
            event.y_root,
            [
                {"text": "  打开网站", "command": self._ctx_open_site},
                {"text": "  复制网址", "command": self._ctx_copy_site_url},
                {"kind": "sep"},
                {"text": "  删除网站", "command": self._ctx_delete_site, "kind": "danger"},
            ],
        )

    def _ctx_open_site(self) -> None:
        if self._site_menu_target:
            self._open_url(self._site_menu_target.get("url", ""))

    def _ctx_copy_site_url(self) -> None:
        if not self._site_menu_target:
            return
        url = self._site_menu_target.get("url", "")
        if not url:
            self.status_label.configure(text="网址为空")
            return
        self.clipboard_clear()
        self.clipboard_append(url)
        self.status_label.configure(text="已复制网址")

    def _ctx_delete_site(self) -> None:
        if not self._site_menu_target:
            return
        name = self._site_menu_target.get("name", "该网站")
        sid = self._site_menu_target.get("id")
        if not sid:
            return
        if not pretty_confirm(self, "确认删除", f"确定从常用网站中删除「{name}」吗？"):
            return
        self.storage.delete_site(sid)
        self._site_menu_target = None
        self.refresh_sites()
        self.status_label.configure(text=f"已删除网站：{name}")

    def _schedule_search_refresh(self) -> None:
        """搜索防抖，避免每敲一键整表重建。"""
        if self._search_after_id is not None:
            try:
                self.after_cancel(self._search_after_id)
            except Exception:
                pass
        self._search_after_id = self.after(180, self.refresh_accounts)

    def _list_item_text(self, acc: dict[str, Any]) -> str:
        """单行展示：账号完整优先，标题挤在后面（很短）。"""
        account = (acc.get("username") or acc.get("website") or "未填写账号").strip()
        title = (acc.get("title") or "").strip()
        if title and title not in ("未命名", account):
            # 标题只保留很短提示，把宽度留给账号
            if len(title) > 10:
                title = title[:9] + "…"
            return f"{account}  ·  {title}"
        return account

    def _style_list_item(self, item: dict[str, Any], selected: bool) -> None:
        btn: ctk.CTkButton = item["btn"]
        if selected:
            btn.configure(
                fg_color=PRIMARY,
                hover_color=PRIMARY_HOVER,
                text_color="#FFFFFF",
                border_color=PRIMARY,
                border_width=1,
            )
        else:
            btn.configure(
                fg_color=BG,
                hover_color=DROPDOWN_HOVER,
                text_color=TEXT,
                border_color=BORDER,
                border_width=1,
            )

    def _update_list_selection(self) -> None:
        """只更新选中高亮，不重建列表。"""
        for aid, item in self._account_items.items():
            self._style_list_item(item, aid == self.selected_id)

    def refresh_accounts(self) -> None:
        self._list_version += 1
        cats = ["全部"] + self.storage.categories()
        current = self.category_filter.get() or "全部"
        # 避免 set 触发多余刷新闪烁：仅值变化时更新
        self.category_filter.configure(values=cats)
        if current not in cats:
            current = "全部"
        if self.category_filter.get() != current:
            self.category_filter.set(current)

        form_cats = self.storage.categories()
        self.fields["category"].configure(values=form_cats)  # type: ignore[union-attr]

        for w in self.account_list.winfo_children():
            w.destroy()
        self._account_items.clear()

        keyword = self.search_var.get()
        # 列表不解密敏感字段，显著降低卡顿
        accounts = self.storage.list_account_summaries(keyword=keyword, category=current)
        if not accounts:
            ctk.CTkLabel(
                self.account_list,
                text="暂无账户\n点击右上角「新建账户」",
                text_color=TEXT_MUTED,
                justify="center",
            ).grid(row=0, column=0, pady=24, sticky="ew")
            return

        for idx, acc in enumerate(accounts):
            selected = acc["id"] == self.selected_id
            # 单行按钮：去掉双行 Label 默认 28px 高度带来的空白/裁切
            btn = ctk.CTkButton(
                self.account_list,
                text=self._list_item_text(acc),
                anchor="w",
                height=34,
                corner_radius=6,
                border_width=1,
                border_color=BORDER,
                fg_color=BG,
                hover_color=DROPDOWN_HOVER,
                text_color=TEXT,
                font=ctk.CTkFont(size=13),
                command=lambda i=acc["id"]: self._select_account(i),
            )
            # 几乎无外边距，减少空白
            btn.grid(row=idx, column=0, sticky="ew", padx=1, pady=1)

            item = {"btn": btn, "id": acc["id"]}
            self._account_items[acc["id"]] = item
            self._style_list_item(item, selected)

    # ---------------- 表单 ----------------
    def _get_form_data(self) -> dict[str, Any]:
        notes_w = self.fields["notes"]
        notes = notes_w.get("1.0", "end").strip() if isinstance(notes_w, ctk.CTkTextbox) else ""
        return {
            "title": self._entry_get("title"),
            "category": self._entry_get("category"),
            "username": self._entry_get("username"),
            "password": self._entry_get("password"),
            "totp_secret": self._entry_get("totp_secret"),
            "website": self._entry_get("website"),
            "notes": notes,
        }

    def _entry_get(self, key: str) -> str:
        w = self.fields[key]
        if isinstance(w, ctk.CTkComboBox):
            return w.get()
        if isinstance(w, ctk.CTkEntry):
            return w.get()
        return ""

    def _entry_set(self, key: str, value: str) -> None:
        w = self.fields[key]
        if isinstance(w, ctk.CTkTextbox):
            w.delete("1.0", "end")
            w.insert("1.0", value or "")
        elif isinstance(w, ctk.CTkComboBox):
            w.set(value or "其他")
        elif isinstance(w, ctk.CTkEntry):
            w.delete(0, "end")
            w.insert(0, value or "")

    def _fill_form(self, acc: dict[str, Any] | None) -> None:
        if not acc:
            self._clear_form()
            return
        self._entry_set("title", acc.get("title", ""))
        self._entry_set("category", acc.get("category", "其他"))
        self._entry_set("username", acc.get("username", ""))
        self._entry_set("password", acc.get("password", ""))
        self._entry_set("totp_secret", acc.get("totp_secret", ""))
        self._entry_set("website", acc.get("website", ""))
        self._entry_set("notes", acc.get("notes", ""))
        self._show_password = False
        pw = self.fields["password"]
        if isinstance(pw, ctk.CTkEntry):
            pw.configure(show="•")

    def _clear_form(self) -> None:
        self.selected_id = None
        for key in ("title", "username", "password", "totp_secret", "website"):
            self._entry_set(key, "")
        self._entry_set("category", "其他")
        self._entry_set("notes", "")
        self.status_label.configure(text="新建模式")
        # 只改高亮，不整表重建
        self._update_list_selection()

    def _new_account(self) -> None:
        self._clear_form()
        self._entry_set("category", "人工智能")
        self._entry_set("website", "https://chatgpt.com")
        self.status_label.configure(text="新建账户 — 填写后点保存")

    def _select_account(self, account_id: str) -> None:
        if account_id == self.selected_id:
            return
        acc = self.storage.get_account(account_id)
        if not acc:
            return
        self.selected_id = account_id
        self._fill_form(acc)
        self.status_label.configure(text=f"已加载：{acc['title']}")
        # 关键：不再 refresh_accounts 整表销毁重建
        self._update_list_selection()

    def _save_account(self) -> None:
        data = self._get_form_data()
        if not data["title"].strip():
            messagebox.showwarning("提示", "请填写标题 / 用途")
            return
        if self.selected_id:
            self.storage.update_account(self.selected_id, data)
            self.status_label.configure(text="已更新")
        else:
            acc = self.storage.add_account(data)
            self.selected_id = acc["id"]
            self.status_label.configure(text="已新增")
        self.fields["category"].configure(values=self.storage.categories())  # type: ignore[union-attr]
        # 保存后标题/副标题可能变，需要重建列表
        self.refresh_accounts()

    def _delete_account(self) -> None:
        if not self.selected_id:
            messagebox.showinfo("提示", "请先选择要删除的账户")
            return
        acc = self.storage.get_account(self.selected_id)
        title = acc["title"] if acc else "该账户"
        if not pretty_confirm(self, "确认删除", f"确定删除「{title}」吗？此操作不可恢复。"):
            return
        self.storage.delete_account(self.selected_id)
        self.selected_id = None
        for key in ("title", "username", "password", "totp_secret", "website"):
            self._entry_set(key, "")
        self._entry_set("category", "其他")
        self._entry_set("notes", "")
        self.status_label.configure(text="已删除")
        self.refresh_accounts()

    def _toggle_password(self) -> None:
        self._show_password = not self._show_password
        pw = self.fields["password"]
        if isinstance(pw, ctk.CTkEntry):
            pw.configure(show="" if self._show_password else "•")

    def _copy_field(self, key: str) -> None:
        value = self._entry_get(key)
        if not value:
            self.status_label.configure(text="内容为空，无法复制")
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        cn = FIELD_CN.get(key, key)
        self.status_label.configure(text=f"已复制{cn}")

    def _copy_totp_code(self) -> None:
        code, _ = totp_code(self._entry_get("totp_secret"))
        if not code or code == "无效密钥":
            self.status_label.configure(text="无有效验证码")
            return
        self.clipboard_clear()
        self.clipboard_append(code)
        self.status_label.configure(text="已复制验证码")

    def _open_website(self) -> None:
        self._open_url(self._entry_get("website"))

    def _open_url(self, url: str) -> None:
        url = normalize_url(url)
        if not url:
            messagebox.showinfo("提示", "网站地址为空")
            return
        webbrowser.open(url)

    def _refresh_totp_display(self) -> None:
        raw = self._entry_get("totp_secret")
        code, remain = totp_code(raw)
        if not (raw or "").strip():
            self.totp_code_label.configure(text="—— ——", text_color=PRIMARY)
            self.totp_remain_label.configure(text="等待输入密钥")
        elif code == "无效密钥":
            self.totp_code_label.configure(text="密钥无效", text_color=DANGER)
            self.totp_remain_label.configure(text="请检查密钥格式")
        else:
            pretty = f"{code[:3]} {code[3:]}" if len(code) == 6 else code
            self.totp_code_label.configure(text=pretty, text_color=PRIMARY)
            self.totp_remain_label.configure(text=f"剩余 {remain} 秒 · 自动刷新")

    def _tick_totp(self) -> None:
        self._refresh_totp_display()
        self.after(500, self._tick_totp)

    # ---------------- 网站弹窗 ----------------
    def _add_site_dialog(self) -> None:
        dlg = ctk.CTkToplevel(self)
        dlg.title("添加常用网站")
        dlg.geometry("380x220")
        dlg.configure(fg_color=BG)
        dlg.transient(self)
        dlg.grab_set()

        ctk.CTkLabel(dlg, text="网站名称", text_color=TEXT_MUTED).pack(anchor="w", padx=20, pady=(20, 4))
        name_e = ctk.CTkEntry(dlg, fg_color=BG_SOFT, border_color=BORDER, height=34)
        name_e.pack(fill="x", padx=20)

        ctk.CTkLabel(dlg, text="网址", text_color=TEXT_MUTED).pack(anchor="w", padx=20, pady=(12, 4))
        url_e = ctk.CTkEntry(
            dlg,
            fg_color=BG_SOFT,
            border_color=BORDER,
            height=34,
            placeholder_text="例如 https://www.baidu.com",
        )
        url_e.pack(fill="x", padx=20)

        def save() -> None:
            name, url = name_e.get().strip(), url_e.get().strip()
            if not name or not url:
                messagebox.showwarning("提示", "名称和网址都要填写", parent=dlg)
                return
            self.storage.add_site(name, normalize_url(url))
            self.refresh_sites()
            dlg.destroy()
            self.status_label.configure(text=f"已添加网站：{name}")

        ctk.CTkButton(dlg, text="保存", fg_color=PRIMARY, hover_color=PRIMARY_HOVER, command=save).pack(pady=18)

    def _update_crypto_label(self) -> None:
        if hasattr(self, "crypto_label"):
            self.crypto_label.configure(text=self.storage.crypto_info())

    def _change_master_password_dialog(self) -> None:
        dlg = ctk.CTkToplevel(self)
        dlg.title("修改主密码")
        dlg.geometry("400x340")
        dlg.configure(fg_color=BG)
        dlg.transient(self)
        dlg.grab_set()

        ctk.CTkLabel(
            dlg,
            text="修改后将用新主密码重新加密全部敏感数据",
            text_color=TEXT_MUTED,
            wraplength=340,
        ).pack(anchor="w", padx=20, pady=(18, 10))

        def labeled_entry(label: str) -> ctk.CTkEntry:
            ctk.CTkLabel(dlg, text=label, text_color=TEXT_MUTED).pack(anchor="w", padx=20)
            e = ctk.CTkEntry(dlg, show="•", height=34, fg_color=BG_SOFT, border_color=BORDER)
            e.pack(fill="x", padx=20, pady=(2, 8))
            return e

        old_e = labeled_entry("原主密码")
        new_e = labeled_entry("新主密码（至少 6 位）")
        new2_e = labeled_entry("确认新主密码")
        err = ctk.CTkLabel(dlg, text="", text_color=DANGER)
        err.pack(anchor="w", padx=20)

        def ok() -> None:
            if new_e.get() != new2_e.get():
                err.configure(text="两次新主密码不一致")
                return
            try:
                self.storage.change_master_password(old_e.get(), new_e.get())
            except Exception as e:
                err.configure(text=str(e))
                return
            self._update_crypto_label()
            self.status_label.configure(text="主密码已修改，数据已重新加密")
            messagebox.showinfo("成功", "主密码已修改", parent=dlg)
            dlg.destroy()

        ctk.CTkButton(dlg, text="确认修改", fg_color=PRIMARY, hover_color=PRIMARY_HOVER, command=ok).pack(
            pady=14
        )

    def _on_close(self) -> None:
        try:
            if hasattr(self, "site_popup"):
                self.site_popup.close()
        except Exception:
            pass
        try:
            self.storage.close()
        except Exception:
            pass
        self.destroy()


def main() -> None:
    # 先创建隐藏根窗口，再弹解锁框（customtkinter 需要根窗口）
    root = ctk.CTk()
    root.withdraw()
    storage = VaultStorage()

    unlock = UnlockDialog(storage)
    unlock.grab_set()
    root.wait_window(unlock)
    if not unlock.result_ok or not storage.is_unlocked():
        try:
            storage.close()
        except Exception:
            pass
        root.destroy()
        return

    root.destroy()
    app = AccountVaultApp(storage)
    if not app.storage.list_accounts():
        app.storage.add_account(
            {
                "title": "对话示例账户",
                "category": "人工智能",
                "username": "you@example.com",
                "password": "请修改密码",
                "totp_secret": "",
                "website": "https://chatgpt.com",
                "notes": "这是示例数据，可编辑或删除。密码与二次验证密钥均国密加密。",
            }
        )
        app.refresh_accounts()
    app.mainloop()


if __name__ == "__main__":
    main()

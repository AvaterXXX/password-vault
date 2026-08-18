#!/usr/bin/env python3
"""密码保险柜 — 本地账户密码 / 二次验证管理（白色界面 · 国密加密）。"""
from __future__ import annotations

import ctypes
import re
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any

import customtkinter as ctk
import pyotp
from tkinter import filedialog, messagebox

from importer import FORMAT_HELP, detect_and_parse
from storage import VaultBusyError, VaultStorage

# 安全相关默认值
CLIPBOARD_CLEAR_MS = 45_000  # 复制密码/验证码后自动清空剪贴板
IDLE_LOCK_MS = 15 * 60_000  # 空闲自动锁定（15 分钟）
MIN_MASTER_PASSWORD_LEN = 8


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


def force_english_input(widget: Any) -> None:
    """在 Windows 密码/PIN 输入框上关闭 IME，避免继承中文输入状态。"""
    if sys.platform != "win32":
        return
    try:
        imm32 = ctypes.WinDLL("imm32")
        associate = imm32.ImmAssociateContext
        associate.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        associate.restype = ctypes.c_void_p
        # 关联空输入法上下文即可让该控件始终按英文/数字直输。
        native = getattr(widget, "_entry", widget)
        associate(ctypes.c_void_p(int(native.winfo_id())), ctypes.c_void_p(0))
    except Exception:
        # 非 Windows 兼容环境或极少数 Tk 实现没有 IME 句柄时不影响使用。
        pass

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
    owner = getattr(master, "_vault_modal_owner", None)
    if owner is None and hasattr(master, "_register_modal_window"):
        owner = master
    modal_entry = None
    if owner is not None:
        try:
            modal_entry = owner._register_modal_window(dlg)
        except Exception:
            modal_entry = None
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
    try:
        master.wait_window(dlg)
    finally:
        if owner is not None and modal_entry is not None:
            try:
                owner._modal_windows.remove(modal_entry)
            except (ValueError, AttributeError):
                pass
    return result["ok"]


class PinSetupDialog(ctk.CTkToplevel):
    """设置当前运行周期的自动锁定 PIN。"""

    def __init__(self, master: Any, storage: VaultStorage) -> None:
        super().__init__(master)
        self.storage = storage
        self.result_pin: str | None = None
        self._busy = False
        self._cancelled = False
        self._submitted_pin = ""
        self._set_result: tuple[str, str] | None = None
        self.title("设置锁定 PIN")
        self.geometry("440x350")
        self.resizable(False, False)
        self.configure(fg_color=BG)
        self.transient(master)
        register = getattr(master, "_register_modal_window", None)
        if register is not None:
            try:
                register(self, cleanup=self.close_for_lock)
            except Exception:
                pass
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        apply_window_icon(self)

        ctk.CTkLabel(
            self,
            text="设置自动锁定 PIN",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=TEXT,
        ).pack(anchor="w", padx=28, pady=(24, 8))
        ctk.CTkLabel(
            self,
            text=(
                f"PIN 仅限 {storage.PIN_MIN_LEN}-{storage.PIN_MAX_LEN} 位数字。\n"
                "它只保存在本次运行的内存中；程序重启后仍需输入主密码。"
            ),
            font=ctk.CTkFont(size=12),
            text_color=TEXT_MUTED,
            justify="left",
            wraplength=380,
        ).pack(anchor="w", padx=28, pady=(0, 14))

        ctk.CTkLabel(self, text="新 PIN", text_color=TEXT_MUTED).pack(anchor="w", padx=28)
        self.pin1 = ctk.CTkEntry(
            self, show="•", height=36, fg_color=BG_SOFT, border_color=BORDER, text_color=TEXT
        )
        self.pin1.pack(fill="x", padx=28, pady=(4, 10))
        ctk.CTkLabel(self, text="确认 PIN", text_color=TEXT_MUTED).pack(anchor="w", padx=28)
        self.pin2 = ctk.CTkEntry(
            self, show="•", height=36, fg_color=BG_SOFT, border_color=BORDER, text_color=TEXT
        )
        self.pin2.pack(fill="x", padx=28, pady=(4, 8))
        self.pin1.bind("<Return>", lambda _e: self._submit())
        self.pin2.bind("<Return>", lambda _e: self._submit())
        self.pin1.bind("<FocusIn>", lambda _e: force_english_input(self.pin1), add="+")
        self.pin2.bind("<FocusIn>", lambda _e: force_english_input(self.pin2), add="+")

        self.err = ctk.CTkLabel(self, text="", text_color=DANGER)
        self.err.pack(anchor="w", padx=28, pady=(0, 4))
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=28, pady=(6, 18))
        ctk.CTkButton(
            row,
            text="保存 PIN",
            height=38,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            command=self._submit,
        ).pack(side="left", expand=True, fill="x", padx=(0, 8))
        ctk.CTkButton(
            row,
            text="稍后设置",
            width=100,
            height=38,
            fg_color="#E5E7EB",
            hover_color="#D1D5DB",
            text_color=TEXT,
            command=self._cancel,
        ).pack(side="right")

        self.update_idletasks()
        try:
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            self.geometry(f"440x350+{(sw - 440) // 2}+{(sh - 350) // 2}")
        except Exception:
            pass
        self.after(100, self._focus_pin)

    def _focus_pin(self) -> None:
        try:
            self.focus_force()
            self.pin1.focus_force()
            force_english_input(self.pin1)
        except Exception:
            pass

    def _cancel(self) -> None:
        if self._busy:
            return
        self.result_pin = None
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

    def close_for_lock(self) -> None:
        """自动锁定时安全关闭，即使 PIN 派生线程仍在后台。"""
        self._cancelled = True
        self.result_pin = None
        try:
            self.pin1.delete(0, "end")
            self.pin2.delete(0, "end")
        except Exception:
            pass
        try:
            self.grab_release()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass

    def _submit(self) -> None:
        if self._busy:
            return
        pin = self.pin1.get()
        if pin != self.pin2.get():
            self.err.configure(text="两次 PIN 不一致")
            return
        try:
            self.storage.validate_pin(pin)
        except Exception as e:
            self.err.configure(text=str(e))
            return
        self._busy = True
        self._submitted_pin = pin
        self._set_result = None
        self.err.configure(text="正在设置 PIN…", text_color=TEXT_MUTED)

        def work() -> None:
            try:
                if self._cancelled:
                    self._set_result = ("err", "")
                    return
                self.storage.set_session_pin(pin)
                self._set_result = ("ok", "")
            except Exception as e:
                self._set_result = ("err", str(e) or "设置 PIN 失败")

        threading.Thread(target=work, daemon=True).start()
        self.after(80, self._poll_submit)

    def _poll_submit(self) -> None:
        if self._cancelled:
            return
        result = self._set_result
        if result is None:
            self.after(80, self._poll_submit)
            return
        self._busy = False
        status, msg = result
        if status != "ok":
            self.err.configure(text=msg, text_color=DANGER)
            return
        self.result_pin = self._submitted_pin
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()


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
            f"请使用至少 {MIN_MASTER_PASSWORD_LEN} 位、尽量复杂的主密码。"
            if first
            else "数据已用国密 SM3/SM4-MAC 加密存储。\n请输入主密码解锁保险库。"
        )
        discovery_note = getattr(storage, "database_discovery_note", None)
        if discovery_note:
            tip += f"\n\n数据库兼容提示：{discovery_note}"

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
        self.pw1.bind("<FocusIn>", lambda _e: force_english_input(self.pw1), add="+")
        if self.pw2 is not None:
            self.pw2.bind("<FocusIn>", lambda _e: force_english_input(self.pw2), add="+")

        def focus_password() -> None:
            try:
                self.focus_force()
                self.pw1.focus_force()
                force_english_input(self.pw1)
            except Exception:
                pass

        self.after(100, focus_password)
        self.update_idletasks()
        try:
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            w, h = 440, 420
            self.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")
        except Exception:
            pass

    def _cancel(self) -> None:
        self.result_ok = False
        try:
            self.destroy()
        except Exception:
            pass

    def _submit(self) -> None:
        if getattr(self, "_busy", False):
            return
        p1 = self.pw1.get()
        if self._first:
            p2 = self.pw2.get() if self.pw2 else ""
            if len(p1) < MIN_MASTER_PASSWORD_LEN:
                self.err.configure(
                    text=f"主密码至少 {MIN_MASTER_PASSWORD_LEN} 位", text_color=DANGER
                )
                return
            if p1 != p2:
                self.err.configure(text="两次输入的主密码不一致", text_color=DANGER)
                return
        self._busy = True
        self._unlock_result: tuple[str, str] | None = None  # ("ok","") | ("err", msg)
        self.err.configure(text="正在解锁（国密派生密钥，请稍候）…", text_color=TEXT_MUTED)

        def work() -> None:
            # 注意：Tk 非线程安全，禁止在子线程里 self.after / 改 UI
            try:
                if self._first:
                    self.storage.setup_master_password(p1)
                else:
                    self.storage.unlock(p1)
                self._unlock_result = ("ok", "")
            except Exception as e:
                self._unlock_result = ("err", str(e) or "解锁失败")

        threading.Thread(target=work, daemon=True).start()
        self.after(50, self._poll_unlock)

    def _poll_unlock(self) -> None:
        """主线程轮询后台解锁结果（兼容 Windows/Tk）。"""
        result = getattr(self, "_unlock_result", None)
        if result is None:
            # 动画点点点
            msg = self.err.cget("text") or ""
            if "正在解锁" in msg:
                dots = msg.count(".") % 3
                base = "正在解锁（国密派生密钥，请稍候）"
                self.err.configure(text=base + "." * (dots + 1), text_color=TEXT_MUTED)
            self.after(80, self._poll_unlock)
            return
        status, msg = result
        self._busy = False
        if status == "ok":
            self.result_ok = True
            self.destroy()
        else:
            self.err.configure(text=msg or "主密码错误或解锁失败", text_color=DANGER)

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
    """规范化网址；保留 ssh:// / rdp:// 等专用协议，不强制加 https。"""
    url = (url or "").strip()
    if not url:
        return ""
    # 已有明确协议（含 ssh/rdp/file 等）则原样返回
    if re.match(r"^[a-z][a-z0-9+.\-]*:", url, re.I):
        return url
    # 裸主机/域名默认 https
    return "https://" + url


def normalize_totp_secret(raw: str) -> str:
    """支持密钥或 otpauth 链接。

    - otpauth://：保留完整 URI（含 algorithm/digits/period）
    - 纯密钥：去空白、大写并补 Base32 padding
    """
    raw = (raw or "").strip()
    if not raw:
        return ""
    if raw.lower().startswith("otpauth://"):
        return raw
    secret = re.sub(r"[\s\-]+", "", raw).upper()
    pad = (-len(secret)) % 8
    if pad:
        secret += "=" * pad
    return secret


def _totp_from_raw(raw: str) -> tuple[Any, int]:
    """返回 (pyotp.TOTP 或 OTP 对象, period 秒)。"""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("empty")
    if raw.lower().startswith("otpauth://"):
        totp = pyotp.parse_uri(raw)
        period = int(getattr(totp, "interval", None) or 30)
        return totp, period
    secret = normalize_totp_secret(raw)
    totp = pyotp.TOTP(secret)
    return totp, 30


def totp_code(secret: str) -> tuple[str, int]:
    """生成当前验证码与剩余秒数；尊重 otpauth 中的算法/位数/周期。"""
    if not (secret or "").strip():
        return ("", 0)
    try:
        totp, period = _totp_from_raw(secret)
        code = totp.now()
        period = max(int(period), 1)
        remaining = period - (int(time.time()) % period)
        if remaining <= 0:
            remaining = period
        return (str(code), remaining)
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
        self._last_totp_ui: tuple[str, str] = ("", "")
        self._filling_form = False
        self._cats_cache: list[str] | None = None
        self._import_running = False
        self._clipboard_clear_after_id: str | None = None
        self._clipboard_expect: str | None = None
        self._idle_after_id: str | None = None
        self._locked_overlay: ctk.CTkFrame | None = None
        self._locked_pin_entry: ctk.CTkEntry | None = None
        self._locked_error_label: ctk.CTkLabel | None = None
        self._locked_parent_bindings: list[tuple[str, str]] = []
        self._pin_failed_attempts = 0
        self._pin_lock_level = 0
        self._pin_locked_until = 0.0
        self._pin_countdown_after_id: str | None = None
        self._locked_unlock_busy = False
        self._locked_waiting_for_storage = False
        self._locked_desc_label: ctk.CTkLabel | None = None
        self._locked_unlock_button: ctk.CTkButton | None = None
        self._locked_normal_desc_text = ""
        self._lock_pending = False
        self._pending_lock_after_id: str | None = None
        # 所有由主窗口打开的模态窗口都登记在这里。自动锁定前会统一释放 grab、
        # 清空输入并销毁，避免子窗口把输入焦点永远截走。
        self._modal_windows: list[dict[str, Any]] = []

        self._build_ui()
        self._build_site_context_menu()
        # 延后首屏刷新，先显示窗口骨架，减少“卡住”感
        self.after(10, self._bootstrap_ui)
        self.after(120, self._maybe_prompt_pin_setup)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        # 空闲自动锁定：任意键鼠活动重置计时
        self.bind_all("<Any-KeyPress>", self._note_activity, add="+")
        self.bind_all("<Any-Button>", self._note_activity, add="+")
        self.bind_all("<Motion>", self._note_activity, add="+")
        self._reset_idle_timer()

    def _bootstrap_ui(self) -> None:
        self.refresh_sites()
        self.refresh_accounts()
        self._tick_totp()
        self._update_crypto_label()
        self._update_pin_button_label()
        discovery_note = getattr(self.storage, "database_discovery_note", None)
        if discovery_note:
            self.status_label.configure(text=f"数据库提示：{discovery_note}")

    def _register_modal_window(
        self, window: Any, cleanup: Any = None
    ) -> dict[str, Any]:
        """登记由主窗口创建的模态窗口，返回可补充 cleanup 的登记项。"""
        entry: dict[str, Any] = {"window": window, "cleanup": cleanup}
        self._modal_windows.append(entry)
        try:
            # 让传给 pretty_confirm 的子 Toplevel 也能找到主窗口登记器。
            setattr(window, "_vault_modal_owner", self)

            def on_destroy(event: Any) -> None:
                event_widget = getattr(event, "widget", None)
                try:
                    is_window = event_widget is window or str(event_widget) == str(window)
                except Exception:
                    is_window = event_widget is window
                if is_window:
                    try:
                        self._modal_windows.remove(entry)
                    except ValueError:
                        pass

            window.bind("<Destroy>", on_destroy, add="+")
        except Exception:
            pass
        return entry

    def _clear_modal_widget(self, window: Any) -> None:
        """递归清除弹窗中的 Entry/Textbox 明文。"""
        try:
            children = list(window.winfo_children())
        except Exception:
            return
        for child in children:
            try:
                if isinstance(child, ctk.CTkEntry):
                    child.delete(0, "end")
                elif isinstance(child, ctk.CTkTextbox):
                    child.delete("1.0", "end")
            except Exception:
                pass
            self._clear_modal_widget(child)

    def _close_registered_modals(self) -> None:
        """关闭所有已登记弹窗，并确保 grab 不会阻塞锁定遮罩。"""
        for entry in reversed(list(self._modal_windows)):
            window = entry.get("window")
            cleanup = entry.get("cleanup")
            try:
                if cleanup:
                    cleanup()
            except Exception:
                pass
            try:
                self._clear_modal_widget(window)
            except Exception:
                pass
            try:
                window.grab_release()
            except Exception:
                pass
            try:
                window.destroy()
            except Exception:
                pass
        self._modal_windows.clear()

    def _maybe_prompt_pin_setup(self) -> None:
        if self.storage.is_unlocked() and self._locked_overlay is None and not self.storage.is_pin_configured():
            self._set_pin_dialog(initial=True)

    def _update_pin_button_label(self) -> None:
        try:
            self._pin_button.configure(
                text="修改锁定 PIN" if self.storage.is_pin_configured() else "设置锁定 PIN"
            )
        except Exception:
            pass

    def _set_pin_dialog(self, initial: bool = False) -> None:
        if self._locked_overlay is not None or not self.storage.is_unlocked():
            return
        if self._import_running or self.storage.is_busy():
            if not initial:
                messagebox.showwarning(
                    "请稍候",
                    f"正在执行「{self.storage.busy_op() or '其他操作'}」，完成后再设置 PIN。",
                )
            return
        dlg = PinSetupDialog(self, self.storage)
        self.wait_window(dlg)
        if dlg.result_pin:
            self._update_pin_button_label()
            self.status_label.configure(text="锁定 PIN 已设置（本次运行有效）")
        elif initial:
            self.status_label.configure(text="未设置 PIN，自动锁定时将要求主密码")

    def _note_activity(self, _event: Any = None) -> None:
        if self.storage.is_unlocked() and not self._lock_pending:
            self._reset_idle_timer()

    def _reset_idle_timer(self) -> None:
        if self._idle_after_id is not None:
            try:
                self.after_cancel(self._idle_after_id)
            except Exception:
                pass
            self._idle_after_id = None
        if self.storage.is_unlocked() and not self._lock_pending:
            self._idle_after_id = self.after(IDLE_LOCK_MS, self._idle_lock)

    def _idle_lock(self) -> None:
        """空闲超时：先遮挡界面，再在忙操作结束后完成锁定。"""
        self._idle_after_id = None
        if not self.storage.is_unlocked() or self._lock_pending:
            return
        if self._import_running or self.storage.is_busy():
            # 不能在写事务持锁时直接清掉主密钥；先遮挡并销毁弹窗，事务完成后立即锁定。
            self._lock_pending = True
            self._prepare_lock_ui()
            self._show_reunlock_dialog(waiting_for_storage=True)
            self._schedule_pending_lock()
            return
        self._prepare_lock_ui()
        try:
            self.storage.lock()
        except Exception:
            pass
        self._show_reunlock_dialog()

    def _prepare_lock_ui(self) -> None:
        """锁定前关闭弹窗、清空界面明文并清理剪贴板。"""
        self._close_registered_modals()
        try:
            if hasattr(self, "site_popup"):
                self.site_popup.close()
        except Exception:
            pass
        self._clear_form_for_lock()
        self._clear_clipboard_if_unchanged()

    def _schedule_pending_lock(self) -> None:
        if self._pending_lock_after_id is None:
            self._pending_lock_after_id = self.after(250, self._complete_pending_lock)

    def _complete_pending_lock(self) -> None:
        self._pending_lock_after_id = None
        if not self._lock_pending or self._locked_overlay is None:
            return
        if self._import_running or self.storage.is_busy():
            self._schedule_pending_lock()
            return
        try:
            self.storage.lock()
        except Exception:
            self._schedule_pending_lock()
            return
        self._lock_pending = False
        self._locked_waiting_for_storage = False
        if self._locked_desc_label is not None:
            try:
                self._locked_desc_label.configure(text=self._locked_normal_desc_text)
            except Exception:
                pass
        if self._locked_pin_entry is not None:
            try:
                self._locked_pin_entry.configure(state="normal")
                self._locked_pin_entry.focus_force()
                force_english_input(self._locked_pin_entry)
            except Exception:
                pass
        if self._locked_unlock_button is not None:
            try:
                self._locked_unlock_button.configure(state="normal")
            except Exception:
                pass

    def _clear_form_for_lock(self) -> None:
        """锁定前清空控件中的明文，避免遮罩失效时仍能看到敏感字段。"""
        if not hasattr(self, "fields"):
            return
        self._filling_form = True
        try:
            for key in ("title", "username", "password", "totp_secret", "website", "notes"):
                self._entry_set(key, "")
            self._entry_set("category", "其他")
            self._show_password = False
            pw = self.fields.get("password")
            if isinstance(pw, ctk.CTkEntry):
                pw.configure(show="•")
        finally:
            self._filling_form = False
        self._last_totp_ui = ("", "")
        self._refresh_totp_display()

    def _release_locked_bindings(self) -> None:
        for sequence, func_id in self._locked_parent_bindings:
            try:
                self.unbind(sequence, func_id)
            except Exception:
                pass
        self._locked_parent_bindings.clear()

    def _format_pin_lock_time(self, seconds: int) -> str:
        seconds = max(int(seconds), 0)
        minutes, rem = divmod(seconds, 60)
        if minutes:
            return f"{minutes} 分钟 {rem} 秒" if rem else f"{minutes} 分钟"
        return f"{seconds} 秒"

    def _show_reunlock_dialog(self, *, waiting_for_storage: bool = False) -> None:
        if self._locked_overlay is not None:
            return
        self._locked_waiting_for_storage = waiting_for_storage
        cover = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        cover.place(relx=0, rely=0, relwidth=1, relheight=1)
        cover.lift()
        self._locked_overlay = cover

        pin_mode = self.storage.is_pin_configured()
        card = ctk.CTkFrame(
            cover,
            width=500,
            height=330,
            fg_color=BG,
            corner_radius=14,
            border_width=1,
            border_color=BORDER,
        )
        card.place(relx=0.5, rely=0.5, anchor="center")
        card.pack_propagate(False)
        ctk.CTkLabel(
            card,
            text="保险库已锁定",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=TEXT,
        ).pack(anchor="w", padx=28, pady=(26, 6))
        normal_desc = (
            "因空闲超时，主界面已完全遮挡，敏感数据已从内存缓存清除。\n"
            + ("请输入锁定 PIN 继续。" if pin_mode else "尚未设置锁定 PIN，请输入主密码继续。")
        )
        self._locked_normal_desc_text = normal_desc
        desc_label = ctk.CTkLabel(
            card,
            text=("正在完成当前操作，主界面已遮挡；完成后即可输入解锁凭据。" if waiting_for_storage else normal_desc),
            text_color=TEXT_MUTED,
            justify="left",
            wraplength=440,
        )
        desc_label.pack(anchor="w", padx=28, pady=(0, 14))
        self._locked_desc_label = desc_label
        ctk.CTkLabel(card, text="锁定 PIN" if pin_mode else "主密码", text_color=TEXT_MUTED).pack(
            anchor="w", padx=28
        )
        pw = ctk.CTkEntry(
            card,
            show="•",
            height=36,
            fg_color=BG_SOFT,
            border_color=BORDER,
            text_color=TEXT,
        )
        pw.pack(fill="x", padx=28, pady=(4, 8))
        err = ctk.CTkLabel(card, text="", text_color=DANGER, wraplength=440, justify="left")
        err.pack(anchor="w", padx=28)
        unlock_btn = ctk.CTkButton(
            card,
            text="解锁",
            height=38,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            state="disabled" if waiting_for_storage else "normal",
        )
        unlock_btn.pack(fill="x", padx=28, pady=(14, 18))
        self._locked_pin_entry = pw
        self._locked_error_label = err
        self._locked_unlock_button = unlock_btn
        if waiting_for_storage:
            pw.configure(state="disabled")
        focus_guard = {"active": False}

        def bring_front(_event: Any = None) -> None:
            if self._locked_overlay is not cover:
                return
            if _event is not None and getattr(_event, "widget", None) is not self:
                return
            if focus_guard["active"]:
                return
            focus_guard["active"] = True
            try:
                cover.lift()
                self.lift()
                self.focus_force()
                pw.focus_force()
                force_english_input(pw)
            except Exception:
                pass
            finally:
                focus_guard["active"] = False

        # 监听窗口重新映射和主窗口自身重新获得焦点；忽略子控件的 FocusIn，
        # 避免聚焦 entry 时再次触发置顶回调。
        for sequence in ("<Map>", "<FocusIn>"):
            try:
                binding = self.bind(sequence, bring_front, add="+")
                self._locked_parent_bindings.append((sequence, binding))
            except Exception:
                pass
        cover.bind("<Map>", bring_front, add="+")

        def close_overlay() -> None:
            if self._pending_lock_after_id is not None:
                try:
                    self.after_cancel(self._pending_lock_after_id)
                except Exception:
                    pass
                self._pending_lock_after_id = None
            if self._pin_countdown_after_id is not None:
                try:
                    self.after_cancel(self._pin_countdown_after_id)
                except Exception:
                    pass
                self._pin_countdown_after_id = None
            self._release_locked_bindings()
            self._locked_pin_entry = None
            self._locked_error_label = None
            self._locked_desc_label = None
            self._locked_unlock_button = None
            self._locked_normal_desc_text = ""
            self._locked_waiting_for_storage = False
            self._lock_pending = False
            self._locked_overlay = None
            try:
                pw.delete(0, "end")
            except Exception:
                pass
            try:
                cover.destroy()
            except Exception:
                pass
            self._update_crypto_label()
            self.refresh_accounts()
            if self.selected_id:
                acc = self.storage.get_account(self.selected_id)
                self._fill_form(acc)
            self._reset_idle_timer()
            self.status_label.configure(text="已重新解锁")

        def update_lockout_message(from_timer: bool = False) -> None:
            if self._locked_overlay is not cover:
                return
            if not from_timer and self._pin_countdown_after_id is not None:
                return
            if from_timer:
                self._pin_countdown_after_id = None
            remain = int(max(0.0, self._pin_locked_until - time.monotonic()) + 0.999)
            if remain <= 0:
                err.configure(text="可以重新输入 PIN", text_color=TEXT_MUTED)
                return
            err.configure(
                text=f"PIN 错误次数过多，暂时锁定。请等待 {self._format_pin_lock_time(remain)}。",
                text_color=DANGER,
            )
            self._pin_countdown_after_id = self.after(1000, lambda: update_lockout_message(True))

        def record_pin_failure(message: str) -> None:
            self._pin_failed_attempts += 1
            if self._pin_failed_attempts < 5:
                left = 5 - self._pin_failed_attempts
                err.configure(text=f"{message}\n连续错误 {self._pin_failed_attempts} 次，还可尝试 {left} 次。")
                return
            self._pin_failed_attempts = 0
            self._pin_lock_level += 1
            lock_minutes = min(10 * (2 ** (self._pin_lock_level - 1)), 24 * 60)
            self._pin_locked_until = time.monotonic() + lock_minutes * 60
            update_lockout_message()

        def poll_unlock(result_box: dict[str, tuple[str, str] | None]) -> None:
            if self._locked_overlay is not cover:
                return
            result = result_box.get("result")
            if result is None:
                self.after(60, lambda: poll_unlock(result_box))
                return
            self._locked_unlock_busy = False
            try:
                pw.configure(state="normal")
            except Exception:
                pass
            unlock_btn.configure(state="normal")
            status, msg = result
            if status != "ok":
                if pin_mode:
                    record_pin_failure(msg or "PIN 错误")
                else:
                    err.configure(text=msg or "主密码错误或解锁失败", text_color=DANGER)
                bring_front()
                return
            self._pin_failed_attempts = 0
            self._pin_lock_level = 0
            self._pin_locked_until = 0.0
            close_overlay()

        def do_unlock() -> None:
            if getattr(self, "_locked_unlock_busy", False):
                return
            if self._locked_waiting_for_storage or self._lock_pending:
                return
            if pin_mode and time.monotonic() < self._pin_locked_until:
                update_lockout_message()
                return
            value = pw.get()
            if not value:
                err.configure(text="请输入内容", text_color=DANGER)
                return
            self._locked_unlock_busy = True
            pw.configure(state="disabled")
            unlock_btn.configure(state="disabled")
            err.configure(text="正在解锁，请稍候…", text_color=TEXT_MUTED)
            result_box: dict[str, tuple[str, str] | None] = {"result": None}

            def work() -> None:
                try:
                    if pin_mode:
                        self.storage.unlock_with_pin(value)
                    else:
                        self.storage.unlock(value)
                    result_box["result"] = ("ok", "")
                except Exception as e:
                    result_box["result"] = ("err", str(e) or "解锁失败")

            threading.Thread(target=work, daemon=True).start()
            self.after(60, lambda: poll_unlock(result_box))

        unlock_btn.configure(command=do_unlock)
        pw.bind("<Return>", lambda _e: do_unlock())
        pw.bind("<FocusIn>", lambda _e: force_english_input(pw), add="+")
        self.after(100, bring_front)

    def _copy_sensitive(self, value: str, label: str) -> None:
        """复制敏感内容，并在超时后尝试清空剪贴板。"""
        self.clipboard_clear()
        self.clipboard_append(value)
        self._clipboard_expect = value
        if self._clipboard_clear_after_id is not None:
            try:
                self.after_cancel(self._clipboard_clear_after_id)
            except Exception:
                pass
        self._clipboard_clear_after_id = self.after(
            CLIPBOARD_CLEAR_MS, self._clear_clipboard_if_unchanged
        )
        self.status_label.configure(
            text=f"已复制{label}（{CLIPBOARD_CLEAR_MS // 1000} 秒后尝试清空剪贴板）"
        )
        self._note_activity()

    def _clear_clipboard_if_unchanged(self) -> None:
        self._clipboard_clear_after_id = None
        expect = self._clipboard_expect
        self._clipboard_expect = None
        if expect is None:
            return
        try:
            current = self.clipboard_get()
        except Exception:
            return
        if current == expect:
            try:
                self.clipboard_clear()
                self.clipboard_append("")
            except Exception:
                pass
            try:
                self.status_label.configure(text="剪贴板已自动清空")
            except Exception:
                pass

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
            text="批量导入",
            width=90,
            height=36,
            fg_color="#EEF2FF",
            hover_color="#DBEAFE",
            text_color=PRIMARY,
            command=self._import_dialog,
        ).grid(row=0, column=2, sticky="e", padx=(0, 8))

        self._pin_button = ctk.CTkButton(
            top,
            text="设置锁定 PIN",
            width=110,
            height=36,
            fg_color="#EEF2FF",
            hover_color="#DBEAFE",
            text_color=PRIMARY,
            command=self._set_pin_dialog,
        )
        self._pin_button.grid(row=0, column=3, sticky="e", padx=(0, 8))

        ctk.CTkButton(
            top,
            text="修改主密码",
            width=100,
            height=36,
            fg_color="#E5E7EB",
            hover_color="#D1D5DB",
            text_color=TEXT,
            command=self._change_master_password_dialog,
        ).grid(row=0, column=4, sticky="e", padx=(0, 8))

        ctk.CTkButton(
            top,
            text="+ 新建账户",
            width=110,
            height=36,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            command=self._new_account,
        ).grid(row=0, column=5, sticky="e")

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
                widget.bind(
                    "<FocusIn>", lambda _e, entry=widget: force_english_input(entry), add="+"
                )
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
                widget.bind(
                    "<FocusIn>", lambda _e, entry=widget: force_english_input(entry), add="+"
                )
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
        form_cats = self.storage.categories()
        self._cats_cache = form_cats
        cats = ["全部"] + form_cats
        current = self.category_filter.get() or "全部"
        # 避免 set 触发多余刷新闪烁：仅值变化时更新
        self.category_filter.configure(values=cats)
        if current not in cats:
            current = "全部"
        if self.category_filter.get() != current:
            self.category_filter.set(current)

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
        self._filling_form = True
        try:
            # 仅当值变化时写入，减少控件重绘“闪一下”
            pairs = [
                ("title", acc.get("title", "")),
                ("category", acc.get("category", "其他") or "其他"),
                ("username", acc.get("username", "")),
                ("password", acc.get("password", "")),
                ("totp_secret", acc.get("totp_secret", "")),
                ("website", acc.get("website", "")),
                ("notes", acc.get("notes", "")),
            ]
            for key, val in pairs:
                cur = self._entry_get(key) if key != "notes" else self.fields["notes"].get("1.0", "end").strip()  # type: ignore[union-attr]
                if cur != (val or ""):
                    self._entry_set(key, val or "")
            self._show_password = False
            pw = self.fields["password"]
            if isinstance(pw, ctk.CTkEntry) and pw.cget("show") != "•":
                pw.configure(show="•")
        finally:
            self._filling_form = False
            self._last_totp_ui = ("", "")
            self._refresh_totp_display()

    def _clear_form(self) -> None:
        self.selected_id = None
        self._filling_form = True
        try:
            for key in ("title", "username", "password", "totp_secret", "website"):
                if self._entry_get(key):
                    self._entry_set(key, "")
            if self._entry_get("category") != "其他":
                self._entry_set("category", "其他")
            notes_w = self.fields["notes"]
            if isinstance(notes_w, ctk.CTkTextbox) and notes_w.get("1.0", "end").strip():
                self._entry_set("notes", "")
        finally:
            self._filling_form = False
        self.status_label.configure(text="新建模式")
        self._update_list_selection()
        self._last_totp_ui = ("", "")
        self._refresh_totp_display()

    def _new_account(self) -> None:
        self._clear_form()
        self._entry_set("category", "人工智能")
        self._entry_set("website", "https://chatgpt.com")
        self.status_label.configure(text="新建账户 — 填写后点保存")

    def _select_account(self, account_id: str) -> None:
        if account_id == self.selected_id:
            return
        # 先更新选中高亮（即时反馈），再填详情
        prev = self.selected_id
        self.selected_id = account_id
        self._update_list_selection()
        acc = self.storage.get_account(account_id)
        if not acc:
            self.selected_id = prev
            self._update_list_selection()
            return
        self._fill_form(acc)
        self.status_label.configure(text=f"已加载：{acc['title']}")

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
        self._cats_cache = None
        cats = self.storage.categories()
        self.fields["category"].configure(values=cats)  # type: ignore[union-attr]
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
        cn = FIELD_CN.get(key, key)
        if key in ("password", "totp_secret"):
            self._copy_sensitive(value, cn)
        else:
            self.clipboard_clear()
            self.clipboard_append(value)
            self.status_label.configure(text=f"已复制{cn}")
            self._note_activity()

    def _copy_totp_code(self) -> None:
        code, _ = totp_code(self._entry_get("totp_secret"))
        if not code or code == "无效密钥":
            self.status_label.configure(text="无有效验证码")
            return
        self._copy_sensitive(code, "验证码")

    def _open_website(self) -> None:
        self._open_url(self._entry_get("website"))

    def _open_url(self, url: str) -> None:
        url = normalize_url(url)
        if not url:
            messagebox.showinfo("提示", "网站地址为空")
            return
        webbrowser.open(url)

    def _refresh_totp_display(self) -> None:
        if self._filling_form:
            return
        raw = self._entry_get("totp_secret")
        code, remain = totp_code(raw)
        if not (raw or "").strip():
            state = ("—— ——", "等待输入密钥")
            color = PRIMARY
        elif code == "无效密钥":
            state = ("密钥无效", "请检查密钥格式")
            color = DANGER
        else:
            if code.isdigit() and len(code) in (6, 7, 8):
                mid = len(code) // 2
                pretty = f"{code[:mid]} {code[mid:]}"
            else:
                pretty = code
            state = (pretty, f"剩余 {remain} 秒 · 自动刷新")
            color = PRIMARY
        if state == self._last_totp_ui:
            return
        self._last_totp_ui = state
        self.totp_code_label.configure(text=state[0], text_color=color)
        self.totp_remain_label.configure(text=state[1])

    def _tick_totp(self) -> None:
        self._refresh_totp_display()
        # 有密钥时 1s 刷新；无密钥时 2s，降低空转开销
        has_secret = bool(self._entry_get("totp_secret").strip())
        self.after(1000 if has_secret else 2000, self._tick_totp)

    # ---------------- 网站弹窗 ----------------
    def _add_site_dialog(self) -> None:
        dlg = ctk.CTkToplevel(self)
        modal_entry = self._register_modal_window(dlg)
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

        def close_dialog() -> None:
            try:
                name_e.delete(0, "end")
                url_e.delete(0, "end")
            except Exception:
                pass
            try:
                dlg.grab_release()
            except Exception:
                pass
            try:
                dlg.destroy()
            except Exception:
                pass

        modal_entry["cleanup"] = close_dialog
        dlg.protocol("WM_DELETE_WINDOW", close_dialog)

        def save() -> None:
            name, url = name_e.get().strip(), url_e.get().strip()
            if not name or not url:
                messagebox.showwarning("提示", "名称和网址都要填写", parent=dlg)
                return
            self.storage.add_site(name, normalize_url(url))
            self.refresh_sites()
            close_dialog()
            self.status_label.configure(text=f"已添加网站：{name}")

        ctk.CTkButton(dlg, text="保存", fg_color=PRIMARY, hover_color=PRIMARY_HOVER, command=save).pack(pady=18)

    def _update_crypto_label(self) -> None:
        if hasattr(self, "crypto_label"):
            self.crypto_label.configure(text=self.storage.crypto_info())

    def _import_dialog(self) -> None:
        if self._import_running or self.storage.is_busy():
            messagebox.showwarning(
                "请稍候",
                f"正在执行「{self.storage.busy_op() or '其他操作'}」，请完成后再导入。",
            )
            return

        dlg = ctk.CTkToplevel(self)
        modal_entry = self._register_modal_window(dlg)
        dlg.title("批量导入账户")
        dlg.geometry("820x640")
        dlg.configure(fg_color=BG)
        dlg.transient(self)
        dlg.grab_set()
        apply_window_icon(dlg)
        import_active = {"running": False}

        def close_dialog() -> None:
            import_active["cancelled"] = True
            if import_active.get("running") and self._lock_pending:
                # 自动锁定已用遮罩接管界面；让后台写事务自行结束，随后立即锁库。
                self._import_running = False
            try:
                self._clear_modal_widget(dlg)
            except Exception:
                pass
            try:
                dlg.grab_release()
            except Exception:
                pass
            try:
                dlg.destroy()
            except Exception:
                pass

        modal_entry["cleanup"] = close_dialog

        def try_close() -> None:
            if import_active["running"]:
                messagebox.showwarning("导入进行中", "请等待导入完成后再关闭。", parent=dlg)
                return
            close_dialog()

        dlg.protocol("WM_DELETE_WINDOW", try_close)

        ctk.CTkLabel(
            dlg,
            text="批量导入",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=TEXT,
        ).pack(anchor="w", padx=20, pady=(16, 4))
        ctk.CTkLabel(
            dlg,
            text="粘贴文本或选择文件；支持 JSON / CSV / GPT账号 / SSH / RDP / 文本块，可自动识别",
            text_color=TEXT_MUTED,
            wraplength=760,
            justify="left",
        ).pack(anchor="w", padx=20, pady=(0, 8))

        bar = ctk.CTkFrame(dlg, fg_color="transparent")
        bar.pack(fill="x", padx=20, pady=(0, 6))
        ctk.CTkLabel(bar, text="格式", text_color=TEXT_MUTED).pack(side="left")
        fmt_box = make_combo(
            bar,
            values=["auto", "json", "csv", "gpt", "web", "ssh", "rdp", "block"],
            soft=True,
        )
        fmt_box.set("auto")
        fmt_box.pack(side="left", padx=(8, 12))
        status = ctk.CTkLabel(bar, text="", text_color=TEXT_MUTED)
        status.pack(side="left", fill="x", expand=True)

        text = ctk.CTkTextbox(
            dlg,
            fg_color=BG_SOFT,
            border_width=1,
            border_color=BORDER,
            text_color=TEXT,
            height=180,
        )
        text.pack(fill="x", padx=20, pady=(0, 8))
        text.insert("1.0", FORMAT_HELP)

        # 字段预览表（避免静默截断密码而不自知）
        preview_frame = ctk.CTkFrame(dlg, fg_color=BG_SOFT, border_width=1, border_color=BORDER)
        preview_frame.pack(fill="both", expand=True, padx=20, pady=(0, 8))
        preview_header = ctk.CTkLabel(
            preview_frame,
            text="解析预览（导入前请核对账号 / 密码 / 网站）",
            text_color=TEXT_MUTED,
            anchor="w",
        )
        preview_header.pack(fill="x", padx=10, pady=(8, 4))
        preview_box = ctk.CTkTextbox(
            preview_frame,
            fg_color=BG,
            border_width=0,
            text_color=TEXT,
            height=160,
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        preview_box.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        preview_box.insert("1.0", "（点击「预览解析」后在此显示字段）")
        preview_box.configure(state="disabled")

        def render_preview_table(items: list[dict[str, Any]]) -> None:
            lines = [
                f"{'标题':<14} {'账号':<22} {'密码':<18} {'TOTP':<10} {'网站/主机'}",
                "-" * 96,
            ]
            for it in items[:80]:
                title = (it.get("title") or "")[:12]
                user = (it.get("username") or "")[:20]
                pwd = (it.get("password") or "")[:16]
                totp = "有" if (it.get("totp_secret") or "").strip() else ""
                site = (it.get("website") or "")[:28]
                lines.append(f"{title:<14} {user:<22} {pwd:<18} {totp:<10} {site}")
            if len(items) > 80:
                lines.append(f"… 另有 {len(items) - 80} 条未显示")
            preview_box.configure(state="normal")
            preview_box.delete("1.0", "end")
            preview_box.insert("1.0", "\n".join(lines))
            preview_box.configure(state="disabled")

        def load_file() -> None:
            if import_active["running"]:
                return
            path = filedialog.askopenfilename(
                parent=dlg,
                title="选择导入文件",
                filetypes=[
                    ("文本/表格", "*.txt;*.csv;*.tsv;*.json;*.log"),
                    ("全部文件", "*.*"),
                ],
            )
            if not path:
                return
            raw = Path(path).read_bytes()
            content = None
            for enc in ("utf-8-sig", "utf-8", "gbk", "gb18030", "latin-1"):
                try:
                    content = raw.decode(enc)
                    break
                except Exception:
                    content = None
            if content is None:
                messagebox.showerror("错误", "无法解码文件", parent=dlg)
                return
            text.delete("1.0", "end")
            text.insert("1.0", content)
            status.configure(text=f"已载入：{Path(path).name}")

        def do_preview() -> tuple[str, list[dict[str, Any]]]:
            body = text.get("1.0", "end").strip()
            if body.startswith("支持格式"):
                return ("", [])
            name, items = detect_and_parse(body, force_format=fmt_box.get() or "auto")
            return name, items

        def preview() -> None:
            if import_active["running"]:
                return
            name, items = do_preview()
            if not items:
                status.configure(text="未解析到账户，请检查格式")
                render_preview_table([])
                preview_box.configure(state="normal")
                preview_box.delete("1.0", "end")
                preview_box.insert("1.0", "未解析到账户")
                preview_box.configure(state="disabled")
                return
            status.configure(text=f"识别为「{name}」，共 {len(items)} 条（预览未写入）")
            render_preview_table(items)

        btn_import: ctk.CTkButton
        btn_close: ctk.CTkButton

        def set_import_ui_busy(busy: bool) -> None:
            import_active["running"] = busy
            self._import_running = busy
            state = "disabled" if busy else "normal"
            try:
                btn_import.configure(state=state)
                btn_close.configure(state=state)
                fmt_box.configure(state=state)
            except Exception:
                pass

        def do_import() -> None:
            if import_active["running"]:
                return
            name, items = do_preview()
            if not items:
                messagebox.showwarning("提示", "未解析到可导入账户", parent=dlg)
                return
            render_preview_table(items)
            if not pretty_confirm(
                dlg,
                "确认导入",
                f"识别格式：{name}\n将导入 {len(items)} 条账户，是否继续？\n\n"
                "请确认上方预览中的密码字段无误。",
            ):
                return
            status.configure(text="正在加密写入…")
            set_import_ui_busy(True)
            dlg.update_idletasks()
            import_state: dict[str, Any] = {"done": False}

            def work() -> None:
                try:
                    n = self.storage.add_accounts_batch(items)
                    import_state["ok"] = True
                    import_state["n"] = n
                    import_state["name"] = name
                except Exception as e:
                    import_state["ok"] = False
                    import_state["err"] = str(e)
                import_state["done"] = True

            def poll() -> None:
                if import_active.get("cancelled"):
                    return
                if not import_state.get("done"):
                    dlg.after(50, poll)
                    return
                set_import_ui_busy(False)
                if import_state.get("ok"):
                    n = int(import_state.get("n") or 0)
                    fmt_name = str(import_state.get("name") or "")
                    self._cats_cache = None
                    self.refresh_accounts()
                    status.configure(text=f"已导入 {n} 条（{fmt_name}）")
                    self.status_label.configure(text=f"批量导入 {n} 条")
                    messagebox.showinfo("完成", f"成功导入 {n} 条账户", parent=dlg)
                else:
                    msg = str(import_state.get("err") or "未知错误")
                    status.configure(text=f"导入失败：{msg}")
                    messagebox.showerror("失败", msg, parent=dlg)

            threading.Thread(target=work, daemon=True).start()
            dlg.after(50, poll)

        btns = ctk.CTkFrame(dlg, fg_color="transparent")
        btns.pack(fill="x", padx=20, pady=(0, 16))
        ctk.CTkButton(
            btns, text="选择文件", width=100, fg_color="#E5E7EB", hover_color="#D1D5DB",
            text_color=TEXT, command=load_file,
        ).pack(side="left")
        ctk.CTkButton(
            btns, text="预览解析", width=100, fg_color="#EEF2FF", hover_color="#DBEAFE",
            text_color=PRIMARY, command=preview,
        ).pack(side="left", padx=8)
        btn_import = ctk.CTkButton(
            btns, text="开始导入", width=120, fg_color=SUCCESS, hover_color="#047857",
            command=do_import,
        )
        btn_import.pack(side="right")
        btn_close = ctk.CTkButton(
            btns, text="关闭", width=80, fg_color="#E5E7EB", hover_color="#D1D5DB",
            text_color=TEXT, command=try_close,
        )
        btn_close.pack(side="right", padx=(0, 8))

    def _change_master_password_dialog(self) -> None:
        if self._import_running or self.storage.is_busy():
            messagebox.showwarning(
                "请稍候",
                f"正在执行「{self.storage.busy_op() or '导入/其他操作'}」，请完成后再修改主密码。",
            )
            return

        dlg = ctk.CTkToplevel(self)
        modal_entry = self._register_modal_window(dlg)
        dlg.title("修改主密码")
        dlg.geometry("420x380")
        dlg.configure(fg_color=BG)
        dlg.transient(self)
        dlg.grab_set()

        ctk.CTkLabel(
            dlg,
            text=(
                f"修改后将用新主密码重新加密全部敏感数据（单事务）。\n"
                f"操作前自动备份数据库；新密码至少 {MIN_MASTER_PASSWORD_LEN} 位。"
            ),
            text_color=TEXT_MUTED,
            wraplength=360,
            justify="left",
        ).pack(anchor="w", padx=20, pady=(18, 10))

        def labeled_entry(label: str) -> ctk.CTkEntry:
            ctk.CTkLabel(dlg, text=label, text_color=TEXT_MUTED).pack(anchor="w", padx=20)
            e = ctk.CTkEntry(dlg, show="•", height=34, fg_color=BG_SOFT, border_color=BORDER)
            e.pack(fill="x", padx=20, pady=(2, 8))
            e.bind("<FocusIn>", lambda _e, entry=e: force_english_input(entry), add="+")
            return e

        old_e = labeled_entry("原主密码")
        new_e = labeled_entry(f"新主密码（至少 {MIN_MASTER_PASSWORD_LEN} 位）")
        new2_e = labeled_entry("确认新主密码")
        err = ctk.CTkLabel(dlg, text="", text_color=DANGER, wraplength=360, justify="left")
        err.pack(anchor="w", padx=20)

        def close_dialog() -> None:
            for entry in (old_e, new_e, new2_e):
                try:
                    entry.delete(0, "end")
                except Exception:
                    pass
            try:
                dlg.grab_release()
            except Exception:
                pass
            try:
                dlg.destroy()
            except Exception:
                pass

        modal_entry["cleanup"] = close_dialog
        dlg.protocol("WM_DELETE_WINDOW", close_dialog)

        def focus_old_password() -> None:
            try:
                old_e.focus_force()
                force_english_input(old_e)
            except Exception:
                pass

        dlg.after(100, focus_old_password)

        def ok() -> None:
            if self._import_running or self.storage.is_busy():
                err.configure(text="有其他操作进行中，请稍后再试")
                return
            if new_e.get() != new2_e.get():
                err.configure(text="两次新主密码不一致")
                return
            if len(new_e.get()) < MIN_MASTER_PASSWORD_LEN:
                err.configure(text=f"新主密码至少 {MIN_MASTER_PASSWORD_LEN} 位")
                return
            try:
                bak = self.storage.change_master_password(old_e.get(), new_e.get())
            except VaultBusyError as e:
                err.configure(text=str(e))
                return
            except Exception as e:
                err.configure(text=str(e))
                return
            self._update_crypto_label()
            self._update_pin_button_label()
            self.status_label.configure(text="主密码已修改；锁定 PIN 需要重新设置")
            messagebox.showinfo(
                "成功",
                f"主密码已修改。\n锁定 PIN 已清除，请重新设置。\n备份文件：\n{bak}",
                parent=dlg,
            )
            close_dialog()
            self.after(120, self._set_pin_dialog)

        ctk.CTkButton(dlg, text="确认修改", fg_color=PRIMARY, hover_color=PRIMARY_HOVER, command=ok).pack(
            pady=14
        )

    def _on_close(self) -> None:
        if getattr(self, "_locked_unlock_busy", False):
            messagebox.showwarning("正在解锁", "请等待解锁完成后再退出。")
            return
        if self._import_running or self.storage.is_busy():
            if not messagebox.askyesno(
                "操作进行中",
                "仍有导入或写入操作未完成，强制退出可能损坏数据。确定退出吗？",
            ):
                return
        try:
            if self._idle_after_id is not None:
                self.after_cancel(self._idle_after_id)
        except Exception:
            pass
        try:
            if self._pin_countdown_after_id is not None:
                self.after_cancel(self._pin_countdown_after_id)
        except Exception:
            pass
        try:
            if self._pending_lock_after_id is not None:
                self.after_cancel(self._pending_lock_after_id)
        except Exception:
            pass
        self._pending_lock_after_id = None
        self._lock_pending = False
        self._close_registered_modals()
        self._release_locked_bindings()
        try:
            if hasattr(self, "site_popup"):
                self.site_popup.close()
        except Exception:
            pass
        try:
            self.storage.close()
        except VaultBusyError:
            try:
                # 最后尝试阻塞关闭
                self.storage._begin_op("关闭", block=True)
                self.storage._sm4_key = None
                self.storage._account_cache.clear()
                self.storage._conn.close()
                self.storage._end_op()
            except Exception:
                pass
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
    # 仅首次启动写入示例账户；用户删光后不再复活
    if storage.should_seed_sample_account():
        storage.mark_sample_account_seeded()
        if storage.count_accounts() == 0:
            storage.add_account(
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

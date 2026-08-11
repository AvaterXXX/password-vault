#!/usr/bin/env python3
"""打包 密码保险柜.exe（含钥匙图标）。"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ICON = ROOT / "assets" / "app.ico"


def main() -> int:
    if not ICON.exists():
        print("缺少图标文件:", ICON)
        return 1

    # Windows --add-data 用分号分隔
    add_data = f"{ICON};assets"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name",
        "密码保险柜",
        "--icon",
        str(ICON),
        "--add-data",
        add_data,
        "--paths",
        str(ROOT),
        "--hidden-import",
        "storage",
        "--hidden-import",
        "crypto_gm",
        "--hidden-import",
        "pyotp",
        "--hidden-import",
        "gmssl",
        "--hidden-import",
        "gmssl.sm4",
        "--hidden-import",
        "gmssl.sm3",
        "--hidden-import",
        "cryptography",
        str(ROOT / "main.py"),
    ]
    print("Running:", " ".join(cmd))
    return subprocess.call(cmd, cwd=str(ROOT))


if __name__ == "__main__":
    raise SystemExit(main())

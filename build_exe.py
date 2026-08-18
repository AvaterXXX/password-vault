#!/usr/bin/env python3
"""打包 密码保险柜.exe（含钥匙图标）。"""
from __future__ import annotations

import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ICON = ROOT / "assets" / "app.ico"


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="构建 Windows 密码保险柜 EXE")
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="EXE 输出目录；默认使用 dist\\build-时间戳，避免覆盖旧发布文件",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="PyInstaller 临时工作目录；默认使用 build\\build-时间戳",
    )
    parser.add_argument(
        "--spec-dir",
        type=Path,
        help="PyInstaller spec 输出目录；默认与 work-dir 相同",
    )
    parser.add_argument(
        "--name",
        default="密码保险柜",
        help="EXE 名称（不含 .exe）",
    )
    args = parser.parse_args(argv)

    if not ICON.exists():
        print("缺少图标文件:", ICON)
        return 1

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = (args.output_dir or (ROOT / "dist" / f"build-{stamp}")).resolve()
    work_dir = (args.work_dir or (ROOT / "build" / f"build-{stamp}")).resolve()
    spec_dir = (args.spec_dir or work_dir).resolve()
    target_exe = output_dir / f"{args.name}.exe"
    if target_exe.exists():
        print("拒绝覆盖已有 EXE，请改用新的 --output-dir:", target_exe)
        return 2
    output_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    spec_dir.mkdir(parents=True, exist_ok=True)

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
        args.name,
        "--distpath",
        str(output_dir),
        "--workpath",
        str(work_dir),
        "--specpath",
        str(spec_dir),
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
        "importer",
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
        "--collect-all",
        "customtkinter",
        "--collect-all",
        "gmssl",
        str(ROOT / "main.py"),
    ]
    print("Running:", " ".join(cmd))
    return subprocess.call(cmd, cwd=str(ROOT))


if __name__ == "__main__":
    raise SystemExit(main())

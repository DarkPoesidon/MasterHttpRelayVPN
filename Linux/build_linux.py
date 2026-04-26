#!/usr/bin/env python3
"""Build VPN (Linux binary) using PyInstaller.

Run this script from the Linux/ sub-folder or from the project root:
    python Linux/build_linux.py
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
from datetime import date
from pathlib import Path

APP_NAME = "MasterHttpRelayVPN"
APP_EXE_NAME = "VPN"
APP_VERSION = "1.1.0.0"

# Directories
LINUX_DIR = Path(__file__).resolve().parent


def _version_file_content() -> str:
    yyyy = date.today().year
    return f"""# UTF-8
VSVersionInfo(
    ffi=FixedFileInfo(
        filevers=(1, 1, 0, 0),
        prodvers=(1, 1, 0, 0),
        mask=0x3F,
        flags=0x0,
        OS=0x4,
        fileType=0x1,
        subtype=0x0,
        date=(0, 0)
        ),
    kids=[
        StringFileInfo(
            [
            StringTable(
                '040904B0',
                [StringStruct('CompanyName', 'MasterHttpRelayVPN'),
                StringStruct('FileDescription', 'MasterHttpRelayVPN Desktop Client'),
                StringStruct('FileVersion', '{APP_VERSION}'),
                StringStruct('InternalName', '{APP_EXE_NAME}'),
                StringStruct('LegalCopyright', 'Copyright (C) {yyyy}'),
                StringStruct('OriginalFilename', '{APP_EXE_NAME}'),
                StringStruct('ProductName', '{APP_NAME}'),
                StringStruct('ProductVersion', '{APP_VERSION}')])
            ]),
        VarFileInfo([VarStruct('Translation', [1033, 1200])])
    ]
)
"""


def _ensure_default_icon(icon_path: Path) -> None:
    """Create a minimal embedded ICO if no custom icon exists yet."""
    if icon_path.exists():
        return

    icon_path.parent.mkdir(parents=True, exist_ok=True)

    width = 16
    height = 16
    bpp = 32

    pixels = bytearray()
    for y in range(height - 1, -1, -1):
        for x in range(width):
            r = 15
            g = 76 + int((120 * y) / (height - 1))
            b = 129 + int((70 * x) / (width - 1))
            a = 255
            pixels.extend((b, g, r, a))

    and_mask = b"\x00" * (height * 4)

    info_header = struct.pack(
        "<IIIHHIIIIII",
        40, width, height * 2, 1, bpp, 0, len(pixels), 0, 0, 0, 0,
    )
    image_data = info_header + bytes(pixels) + and_mask

    icon_dir = struct.pack("<HHH", 0, 1, 1)
    icon_entry = struct.pack(
        "<BBBBHHII",
        width, height, 0, 0, 1, bpp, len(image_data), 6 + 16,
    )

    with icon_path.open("wb") as fh:
        fh.write(icon_dir)
        fh.write(icon_entry)
        fh.write(image_data)


def _ensure_version_file(version_path: Path) -> None:
    if version_path.exists():
        return
    version_path.parent.mkdir(parents=True, exist_ok=True)
    version_path.write_text(_version_file_content(), encoding="utf-8")


def main() -> int:
    os.chdir(LINUX_DIR)

    icon_path = LINUX_DIR / "assets" / "vpn.ico"
    version_path = LINUX_DIR / "assets" / "version_info.txt"

    _ensure_default_icon(icon_path)
    _ensure_version_file(version_path)

    config_example = LINUX_DIR / "config.example.json"

    try:
        import PyInstaller  # noqa: F401
    except ModuleNotFoundError:
        print("PyInstaller is not installed in this Python environment.")
        print(f"Install with: {sys.executable} -m pip install pyinstaller")
        return 1

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--noconsole",
        "--name", APP_EXE_NAME,
        "--icon", str(icon_path),
        "--version-file", str(version_path),
        "--hidden-import", "cryptography",
        "--hidden-import", "h2",
        # Linux uses ':' as the --add-data separator.
        "--add-data", f"{config_example}:.",
        str(LINUX_DIR / "gui_app_linux.py"),
    ]

    print("Running:")
    print(" ".join(cmd))

    result = subprocess.run(cmd)
    if result.returncode == 0:
        print(f"Build successful. Output: {LINUX_DIR / 'dist' / APP_EXE_NAME}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())

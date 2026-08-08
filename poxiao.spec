# -*- mode: python ; coding: utf-8 -*-
"""破晓 PyInstaller 打包配置（B1：单文件二进制）

用法:
  pyinstaller poxiao.spec

产物: dist/poxiao(.exe) — 含 templates/ 与 configs/ 数据文件
（loader/discovery 已支持 sys._MEIPASS 解包路径）。
"""

from PyInstaller.utils.hooks import collect_data_files

a = Analysis(
    ["poxiao.py"],
    pathex=[],
    binaries=[],
    datas=[
        ("templates", "templates"),
        ("configs", "configs"),
    ],
    hiddenimports=[
        "httpx_sse",
        "cryptography.hazmat.primitives.asymmetric.ec",
        "cryptography.hazmat.primitives.serialization",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "PyQt5", "PyQt6", "matplotlib", "numpy"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="poxiao",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

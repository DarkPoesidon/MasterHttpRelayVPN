# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['D:\\httprelay\\MasterHttpRelayVPN-python_testing\\MasterHttpRelayVPN-python_testing\\Windows\\gui_app.py'],
    pathex=[],
    binaries=[],
    datas=[('D:\\httprelay\\MasterHttpRelayVPN-python_testing\\MasterHttpRelayVPN-python_testing\\Windows\\config.example.json', '.')],
    hiddenimports=['cryptography', 'h2'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='MasterHttpRelayVPN-hotspot',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='D:\\httprelay\\MasterHttpRelayVPN-python_testing\\MasterHttpRelayVPN-python_testing\\Windows\\assets\\version_info.txt',
    icon=['D:\\httprelay\\MasterHttpRelayVPN-python_testing\\MasterHttpRelayVPN-python_testing\\Windows\\assets\\vpn.ico'],
)

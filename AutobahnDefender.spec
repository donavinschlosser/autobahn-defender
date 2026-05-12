# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('256.png', '.'),
        ('512.png', '.'),
        ('banner.png', '.'),
        ('icons', 'icons'),
        ('rules', 'rules'),
    ],
    hiddenimports=[
        'PyQt6.QtWidgets',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.sip',
        'updater',
        'history_db',
        'kernel_checker',
        'firewall',
        'hardening',
        'usb_monitor',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_directories=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)
# Remove bundled OpenSSL to avoid conflicts with system ClamAV's OpenSSL version.
# The system libclamav.so will load the system's OpenSSL at runtime instead.
a.binaries = [
    (name, path, typ) for name, path, typ in a.binaries
    if 'libcrypto' not in name and 'libssl' not in name
]
pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='autobahn-defender',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='512.png',
)
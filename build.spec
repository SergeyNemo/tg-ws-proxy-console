# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file для TG WS Proxy

import os
import sys

from PyInstaller.utils.hooks import collect_data_files

# config.json не хранится в репозитории (там пароль), но без него exe не запустится.
_CFG = os.path.join(SPECPATH, 'config', 'config.json')  # noqa: F821
if not os.path.exists(_CFG):
    print()
    print('=' * 60)
    print('  config/config.json not found')
    print('=' * 60)
    print('  Create it from the example:')
    print('    copy config\\config.example.json config\\config.json')
    print()
    print('  Then run the build again.')
    print('=' * 60)
    sys.exit(1)

# certifi должен попасть внутрь exe: _create_ssl_context берёт его из
# sys._MEIPASS/certifi/cacert.pem, иначе TLS-проверка упадёт.
certifi_datas = collect_data_files('certifi')

a = Analysis(
    ['windows.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('proxy', 'proxy'),
    ] + certifi_datas,
    hiddenimports=['cryptography'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludedimports=[],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='windows',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
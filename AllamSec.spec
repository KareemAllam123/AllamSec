
# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build configuration for AllamSec."""

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


project_root = Path(SPECPATH).resolve()

datas = [
    (
        str(project_root / "dashboard" / "templates"),
        "dashboard/templates",
    ),
    (
        str(project_root / "dashboard" / "static"),
        "dashboard/static",
    ),
    (
        str(project_root / "config.json"),
        ".",
    ),
]

hiddenimports = (
    collect_submodules("dashboard")
    + collect_submodules("app")
    + collect_submodules("database")
)

a = Analysis(
    [str(project_root / "start_allamsec.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="AllamSec",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="AllamSec",
)

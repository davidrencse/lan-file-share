# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: two self-contained Windows executables.

  LANShare.exe      -- the desktop GUI (windowed; no console flash on launch)
  lanshare-cli.exe  -- the command-line tool (console)

The two names must differ by more than case: Windows paths are case-insensitive,
so a "lanshare.exe" would be the same file as "LANShare.exe" and the second
build would silently overwrite the first.

Both are one-file builds: everything (Python, Qt, cryptography) is inside the
executable, so an alpha tester only has to download and double-click.
"""

import os
import sys

ROOT = os.path.abspath(os.path.join(os.getcwd()))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from lanshare import __version__  # noqa: E402

ICON = os.path.join(ROOT, "packaging", "lanshare.ico")
ICON = ICON if os.path.exists(ICON) else None

# Qt ships far more than a five-page desktop app uses. Dropping these keeps the
# executables roughly a third smaller without touching anything we import.
QT_EXCLUDES = [
    "PySide6.Qt3DAnimation", "PySide6.Qt3DCore", "PySide6.Qt3DExtras",
    "PySide6.Qt3DInput", "PySide6.Qt3DLogic", "PySide6.Qt3DRender",
    "PySide6.QtBluetooth", "PySide6.QtCharts", "PySide6.QtDataVisualization",
    "PySide6.QtDesigner", "PySide6.QtHelp", "PySide6.QtMultimedia",
    "PySide6.QtMultimediaWidgets", "PySide6.QtNfc", "PySide6.QtOpenGL",
    "PySide6.QtOpenGLWidgets", "PySide6.QtPdf", "PySide6.QtPdfWidgets",
    "PySide6.QtPositioning", "PySide6.QtQml", "PySide6.QtQuick",
    "PySide6.QtQuick3D", "PySide6.QtQuickControls2", "PySide6.QtQuickWidgets",
    "PySide6.QtRemoteObjects", "PySide6.QtScxml", "PySide6.QtSensors",
    "PySide6.QtSerialPort", "PySide6.QtSpatialAudio", "PySide6.QtSql",
    "PySide6.QtStateMachine", "PySide6.QtTest", "PySide6.QtTextToSpeech",
    "PySide6.QtWebChannel", "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets", "PySide6.QtWebSockets",
]

COMMON_EXCLUDES = QT_EXCLUDES + [
    "tkinter", "unittest", "pydoc_data", "test", "setuptools", "pip",
    "numpy", "matplotlib", "PIL",
]

gui_a = Analysis(
    [os.path.join(ROOT, "packaging", "entry_gui.py")],
    pathex=[ROOT],
    hiddenimports=["lanshare.gui.pages"],
    excludes=COMMON_EXCLUDES,
    noarchive=False,
)

cli_a = Analysis(
    [os.path.join(ROOT, "packaging", "entry_cli.py")],
    pathex=[ROOT],
    # The CLI never touches Qt; leaving PySide6 out is what keeps it small.
    excludes=COMMON_EXCLUDES + ["PySide6", "shiboken6", "lanshare.gui"],
    noarchive=False,
)

gui_pyz = PYZ(gui_a.pure)
cli_pyz = PYZ(cli_a.pure)

gui_exe = EXE(
    gui_pyz, gui_a.scripts, gui_a.binaries, gui_a.datas, [],
    name="LANShare",
    icon=ICON,
    console=False,
    upx=False,
    strip=False,
)

cli_exe = EXE(
    cli_pyz, cli_a.scripts, cli_a.binaries, cli_a.datas, [],
    name="lanshare-cli",
    icon=ICON,
    console=True,
    upx=False,
    strip=False,
)

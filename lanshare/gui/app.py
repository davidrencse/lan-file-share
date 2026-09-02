"""GUI entry point."""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
    except ImportError:
        from ..deps import missing_dependency_help

        print(missing_dependency_help("PySide6", purpose="for the desktop GUI"),
              file=sys.stderr)
        return 1

    from . import icons
    from .main_window import MainWindow
    from .splash import SplashScreen
    from .theme import PALETTE, build_stylesheet

    app = QApplication(sys.argv)
    app.setApplicationName("LANShare")
    app.setStyleSheet(build_stylesheet())
    app.setWindowIcon(icons.icon("shield_check", size=64, color=PALETTE.accent))

    splash = SplashScreen()
    splash.show()

    state = {}

    def _boot() -> None:
        window = MainWindow()
        state["window"] = window
        window.show()
        splash.close()

    QTimer.singleShot(600, _boot)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

"""Helpful guidance when a required third-party package is missing.

Kept dependency-free and importable on its own, so it still works when the
thing it is explaining is exactly what failed to import.
"""

from __future__ import annotations

import os
import shutil
import sysconfig


def externally_managed() -> bool:
    """True if this interpreter refuses ``pip install`` under PEP 668.

    Arch, Debian 12+, Ubuntu 23.04+ and Fedora 38+ ship an EXTERNALLY-MANAGED
    marker next to the standard library; pip then refuses to install into the
    system environment. Advice that boils down to "just run pip install" is
    actively unhelpful on those systems.
    """
    stdlib = sysconfig.get_path("stdlib")
    return bool(stdlib) and os.path.exists(os.path.join(stdlib, "EXTERNALLY-MANAGED"))


# Distro package names, keyed by the Python distribution we actually need.
_DISTRO_PACKAGES = {
    "pacman": {"cryptography": "python-cryptography",
               "PySide6": "pyside6 qt6-wayland"},
    "apt": {"cryptography": "python3-cryptography",
            "PySide6": "python3-pyside6.qtwidgets"},
    "dnf": {"cryptography": "python3-cryptography",
            "PySide6": "python3-pyside6"},
    "zypper": {"cryptography": "python3-cryptography",
               "PySide6": "python3-pyside6"},
}

_INSTALL_VERB = {"pacman": "sudo pacman -S --needed",
                 "apt": "sudo apt install",
                 "dnf": "sudo dnf install",
                 "zypper": "sudo zypper install"}


def missing_dependency_help(module: str, *, purpose: str = "") -> str:
    """A message telling the user how to install *module* on *this* system."""
    what = f"{module} is required{f' {purpose}' if purpose else ''}, " \
           f"but it is not installed."
    lines = [what]

    for manager, packages in _DISTRO_PACKAGES.items():
        if shutil.which(manager) and module in packages:
            lines += [
                "",
                f"Install it with your package manager:",
                f"    {_INSTALL_VERB[manager]} {packages[module]}",
            ]
            if manager == "pacman" and module == "PySide6":
                lines.append(
                    "    (qt6-wayland is needed for Hyprland/Sway; without it\n"
                    "     Qt falls back to XWayland or fails to start.)"
                )
            break

    if externally_managed():
        lines += [
            "",
            "This Python is externally managed (PEP 668), so 'pip install'",
            "into it will be refused. To use a virtual environment instead:",
            "    ./install.sh",
            "which creates .venv and installs everything there.",
        ]
    else:
        lines += ["", "Or with pip:", f"    pip install {module}"]
    return "\n".join(lines)

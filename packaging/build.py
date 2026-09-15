"""Build the standalone LANShare executables.

    python packaging/build.py            # build into dist/
    python packaging/build.py --clean    # discard previous build artefacts

Requires PySide6, cryptography and PyInstaller in the *building* interpreter --
whatever is bundled comes from there, so build with the Python you want to ship.
The result is dist/LANShare.exe, dist/lanshare-cli.exe and a zip of both plus
the tester instructions, with SHA-256 sums written alongside.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "packaging")
DIST = os.path.join(ROOT, "dist")
BUILD = os.path.join(ROOT, "build")

sys.path.insert(0, ROOT)
from lanshare import __version__  # noqa: E402


def _require(module: str) -> None:
    try:
        __import__(module)
    except ImportError:
        sys.exit(
            f"error: {module} is not installed in {sys.executable}.\n"
            f"       pip install PySide6 cryptography pyinstaller"
        )


def _run(args: list, **kw) -> None:
    print("+", " ".join(args))
    subprocess.run(args, check=True, cwd=ROOT, **kw)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _exe(name: str) -> str:
    return name + (".exe" if os.name == "nt" else "")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--clean", action="store_true",
                    help="remove build/ and dist/ before building")
    args = ap.parse_args()

    for module in ("PySide6", "cryptography", "PyInstaller"):
        _require(module)

    if args.clean:
        for path in (BUILD, DIST):
            shutil.rmtree(path, ignore_errors=True)

    _run([sys.executable, os.path.join(PKG, "make_icon.py")])
    _run([sys.executable, "-m", "PyInstaller", "--noconfirm",
          "--distpath", DIST, "--workpath", BUILD,
          os.path.join(PKG, "lanshare.spec")])

    binaries = [os.path.join(DIST, _exe("LANShare")),
                os.path.join(DIST, _exe("lanshare-cli"))]
    missing = [b for b in binaries if not os.path.exists(b)]
    if missing:
        sys.exit("error: PyInstaller did not produce: " + ", ".join(missing))

    tag = f"LANShare-{__version__}-{platform.system().lower()}-{platform.machine().lower()}"
    zip_path = os.path.join(DIST, tag + ".zip")
    notes = os.path.join(PKG, "ALPHA-README.txt")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for b in binaries:
            zf.write(b, os.path.basename(b))
        if os.path.exists(notes):
            zf.write(notes, "README.txt")

    sums = os.path.join(DIST, "SHA256SUMS.txt")
    with open(sums, "w", encoding="utf-8") as fh:
        for path in binaries + [zip_path]:
            fh.write(f"{_sha256(path)}  {os.path.basename(path)}\n")

    print()
    print(f"LANShare {__version__} built:")
    for path in binaries + [zip_path]:
        print(f"  {path}  ({os.path.getsize(path) / 1e6:.1f} MB)")
    print(f"  {sums}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

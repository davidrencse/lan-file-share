"""Frozen-executable entry point for the desktop GUI."""

import multiprocessing
import sys

from lanshare.gui.app import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())

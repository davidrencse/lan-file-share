"""Frozen-executable entry point for the command-line tool."""

import multiprocessing
import sys

from lanshare.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())

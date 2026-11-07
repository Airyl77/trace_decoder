#!/usr/bin/env python3
"""Build a standalone GUI executable with PyInstaller.

Build-time only: `pip install pyinstaller`. The tool itself stays stdlib-only.
PyInstaller does not cross-compile: run this on Windows for a .exe, on macOS/Linux for a native binary.
Output: dist/polystar-trace-converter[.exe]
"""
import subprocess
import sys

NAME = "polystar-trace-converter"

try:
    import PyInstaller  # noqa: F401
except ImportError:
    sys.exit("PyInstaller not found. Install it with: pip install pyinstaller")

sys.exit(subprocess.call([
    sys.executable, "-m", "PyInstaller",
    "--onefile", "--windowed", "--noconfirm", "--clean",
    "--name", NAME,
    "polystar_trace_gui.py",
]))

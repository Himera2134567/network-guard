"""Build a standalone Windows x64 EXE with Tk/Tcl included."""
import subprocess
import sys
from pathlib import Path

if sys.platform != 'win32' or sys.maxsize <= 2**32:
    raise SystemExit('Build on Windows with 64-bit Python.')
if sys.version_info[:3] < (3, 12, 10):
    raise SystemExit('Use Python 3.12.10 or newer to build the executable.')
root = Path(__file__).resolve().parent
subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--windowed', '--name', 'NetworkGuard', str(root/'network_guard.py')], cwd=root, check=True)

#!/usr/bin/env python3
"""WRS — WhatsApp Recovery Scanner.

Forensic acquisition and recovery-assistance tool for Android devices via ADB.
"""

import os
import sys
from pathlib import Path

# Add src/ to front of python path
root_dir = Path(__file__).resolve().parent
src_dir = root_dir / "src"

if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# Ensure root dir is at the back of sys.path so wrs package in src/ takes precedence
if str(root_dir) in sys.path:
    sys.path.remove(str(root_dir))
    sys.path.append(str(root_dir))

# Remove self from sys.modules if imported as module 'wrs'
current_mod = sys.modules.get("wrs")
if current_mod and getattr(current_mod, "__file__", "") == str(Path(__file__).resolve()):
    del sys.modules["wrs"]

import wrs.cli

if __name__ == "__main__":
    wrs.cli.main()

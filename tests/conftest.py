"""Pytest configuration and test path setup."""

import sys
from pathlib import Path

# Ensure src/ takes precedence over root directory in sys.path
root_dir = Path(__file__).resolve().parent.parent
src_dir = root_dir / "src"

if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# Ensure root directory is not shadowing package if present before src
if str(root_dir) in sys.path:
    sys.path.remove(str(root_dir))
    sys.path.append(str(root_dir))

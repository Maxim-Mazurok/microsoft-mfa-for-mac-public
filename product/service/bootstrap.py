"""Load pinned publication codecs, never the mutable diagnostic directory."""
from pathlib import Path
import sys

VENDOR = Path(__file__).resolve().parent / "vendor"
if str(VENDOR) not in sys.path:
    sys.path.insert(0, str(VENDOR))

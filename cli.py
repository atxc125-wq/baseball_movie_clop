"""`pip install -e .` せずに `python cli.py ...` で直接実行するための薄いラッパー。"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from baseball_clop.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

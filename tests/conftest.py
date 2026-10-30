"""让 tests/ 下的用例能 import 仓库根的 akcdn 包（不依赖安装）。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

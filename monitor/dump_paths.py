"""Dump path lists to JSON so the Go scanner can read the same data
that Python's `env_paths.py` defines. Run this once after any change
to `env_paths.py`. The Go binary expects:

  data/env_paths_full.json  — list[str], 1745 deep-mode paths
  data/env_paths_fast.json  — list[str], ~32 fast-mode paths
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"

sys.path.insert(0, str(ROOT))
from env_paths import ENV_PATHS, FAST_ENV_PATHS  # noqa: E402

DATA.mkdir(parents=True, exist_ok=True)
(DATA / "env_paths_full.json").write_text(json.dumps(ENV_PATHS))
(DATA / "env_paths_fast.json").write_text(json.dumps(FAST_ENV_PATHS))

print(f"[dump_paths] wrote env_paths_full.json ({len(ENV_PATHS)} paths)")
print(f"[dump_paths] wrote env_paths_fast.json ({len(FAST_ENV_PATHS)} paths)")

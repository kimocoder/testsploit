"""Deep re-scan of env_found.jsonl using the full Python pattern set.

Designed to run AFTER the Go scanner finishes a round. Go finds candidate
files fast; this pass re-extracts keys from each entry's content_preview
using Python regexes — catching anything Go's RE2 engine missed (heavy
multi-line patterns, future patterns added Python-only, etc.).

Pipeline:
  1. Read env_found.jsonl line-by-line
  2. Resume from byte offset stored in data/deep_scan_offset.json
  3. For each new entry, run extract_keys on content_preview
  4. Compare with the entry's existing keys (by fingerprint)
  5. Append any NEW keys to env_found_deep.jsonl (separate file so we
     never mutate the primary scan log)
  6. Persist new offset

Output schema (env_found_deep.jsonl):
  {
    "host": "...", "url": "...", "path": "...",
    "fingerprint": "...",          # links to original env_found row
    "deep_keys": [<key dicts>],    # NEW keys not in original
    "deep_run_id": "...", "ts": "..."
  }

Run modes:
  python deep_scan.py            # one pass, exit
  python deep_scan.py --watch    # tail forever (every 5s)
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

FOUND_FILE = DATA_DIR / "env_found.jsonl"
DEEP_FILE = DATA_DIR / "env_found_deep.jsonl"
OFFSET_FILE = DATA_DIR / "deep_scan_offset.json"
STATUS_FILE = DATA_DIR / "deep_scan_status.json"

sys.path.insert(0, str(ROOT))
from env_scanner import extract_keys  # type: ignore


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_offset() -> int:
    if not OFFSET_FILE.exists():
        return 0
    try:
        return int(json.loads(OFFSET_FILE.read_text()).get("offset", 0))
    except Exception:
        return 0


def _save_offset(offset: int) -> None:
    tmp = OFFSET_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps({"offset": offset, "ts": _now_iso()}))
    tmp.replace(OFFSET_FILE)


def _write_status(state: str, scanned: int, new_keys: int, run_id: str) -> None:
    STATUS_FILE.write_text(json.dumps({
        "state": state, "scanned": scanned, "new_keys": new_keys,
        "run_id": run_id, "ts": _now_iso(),
    }))


def _existing_fps(entry: dict) -> set[str]:
    return {
        k.get("fingerprint", "")
        for k in entry.get("keys", [])
        if k.get("fingerprint")
    }


def scan_once(run_id: str) -> tuple[int, int]:
    """Process all new entries since last offset. Returns (scanned, new_keys)."""
    if not FOUND_FILE.exists():
        return 0, 0

    start_off = _load_offset()
    file_size = FOUND_FILE.stat().st_size
    if start_off >= file_size:
        return 0, 0

    scanned = 0
    new_keys = 0
    out_fh = open(DEEP_FILE, "a", encoding="utf-8")
    try:
        end_off = start_off
        with open(FOUND_FILE, "r", encoding="utf-8") as f:
            f.seek(start_off)
            while True:
                line = f.readline()
                if not line:
                    break
                end_off = f.tell()
                if not line.strip():
                    continue
                scanned += 1
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                preview = entry.get("content_preview") or ""
                if not preview:
                    continue
                url = entry.get("url") or ""
                host = entry.get("host") or ""
                fp = entry.get("fingerprint") or ""

                try:
                    keys = extract_keys(preview, url, host)
                except Exception as e:
                    print(f"[deep_scan] extract_keys failed for {url}: {e}",
                          flush=True)
                    continue

                already = _existing_fps(entry)
                fresh = [
                    k for k in keys
                    if k.get("fingerprint") and k["fingerprint"] not in already
                ]
                if not fresh:
                    continue

                new_keys += len(fresh)
                out_fh.write(json.dumps({
                    "host": host, "url": url, "path": entry.get("path", ""),
                    "fingerprint": fp, "deep_keys": fresh,
                    "deep_run_id": run_id, "ts": _now_iso(),
                }, ensure_ascii=False) + "\n")
                out_fh.flush()

                if scanned % 100 == 0:
                    _write_status("running", scanned, new_keys, run_id)

        _save_offset(end_off)
    finally:
        out_fh.close()

    return scanned, new_keys


def main() -> None:
    watch = "--watch" in sys.argv
    run_id = uuid.uuid4().hex[:12]
    _write_status("running", 0, 0, run_id)
    total_scanned = 0
    total_new = 0
    started = time.time()

    try:
        while True:
            scanned, new = scan_once(run_id)
            total_scanned += scanned
            total_new += new
            if scanned > 0:
                print(f"[deep_scan] +{scanned} scanned, +{new} new keys "
                      f"(total: {total_scanned}/{total_new})", flush=True)
            _write_status("running" if watch else "done",
                          total_scanned, total_new, run_id)
            if not watch:
                break
            time.sleep(5)
    finally:
        STATUS_FILE.write_text(json.dumps({
            "state": "done", "scanned": total_scanned, "new_keys": total_new,
            "run_id": run_id, "ts": _now_iso(),
            "duration_s": round(time.time() - started, 2),
        }))


if __name__ == "__main__":
    main()

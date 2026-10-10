#!/usr/bin/env python3
"""
KMON Data Management ? purge keys/hosts by filter
Usage:
  python3 purge.py --preview --host 1.2.3.4
  python3 purge.py --preview --service stripe
  python3 purge.py --delete  --host 1.2.3.4         --confirm
  python3 purge.py --delete  --service stripe        --confirm
"""
import json, sys, os, argparse, shutil
from pathlib import Path
from datetime import datetime

DATA = Path("/opt/kmon-deploy/monitor/data")
FILES = {
    "found_keys": DATA / "found_keys.jsonl",
    "env_found":  DATA / "env_found.jsonl",
    "results":    DATA / "results.jsonl",
}

def matches(obj: dict, host=None, service=None) -> bool:
    if host:
        url = obj.get("url","") or ""
        q   = obj.get("query","") or ""
        h   = obj.get("host","") or ""
        if host in url or host == q or host == h:
            return True
        return False
    if service:
        return obj.get("service","") == service
    return False

def purge(host=None, service=None, dry_run=True):
    label = f"host={host}" if host else f"service={service}"
    print(f"\n{'DRY RUN' if dry_run else 'DELETING'}: {label}")
    print("="*55)
    total_removed = 0
    for name, path in FILES.items():
        if not path.exists():
            print(f"  {name}: not found, skipping")
            continue
        kept = removed = 0
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if matches(obj, host, service):
                        removed += 1
                    else:
                        kept += 1
                except:
                    kept += 1
        total_removed += removed
        pct = removed/(kept+removed)*100 if kept+removed > 0 else 0
        print(f"  {name}: {removed:,} would be removed ({pct:.1f}%), {kept:,} kept")
        if not dry_run and removed > 0:
            bak = path.with_suffix(".jsonl.bak")
            shutil.copy2(path, bak)
            tmp = path.with_suffix(".jsonl.tmp")
            with open(path, encoding="utf-8", errors="replace") as fin, \
                 open(tmp, "w", encoding="utf-8") as fout:
                for line in fin:
                    line = line.strip()
                    if not line: continue
                    try:
                        obj = json.loads(line)
                        if not matches(obj, host, service):
                            fout.write(line + "\n")
                    except:
                        fout.write(line + "\n")
            tmp.replace(path)
            print(f"    -> done. Backup: {bak.name}")
    print(f"\nTotal: {total_removed:,} records {'would be' if dry_run else ''} removed")
    if dry_run:
        print("\nRun with --delete --confirm to actually delete")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host",    default=None, help="IP/host to purge")
    p.add_argument("--service", default=None, help="Service name (e.g. stripe)")
    p.add_argument("--preview", action="store_true", help="Preview only (default)")
    p.add_argument("--delete",  action="store_true", help="Actually delete")
    p.add_argument("--confirm", action="store_true", help="Required with --delete")
    args = p.parse_args()
    if not args.host and not args.service:
        print("Error: specify --host or --service"); sys.exit(1)
    if args.delete and not args.confirm:
        print("Error: --delete requires --confirm"); sys.exit(1)
    dry = not (args.delete and args.confirm)
    purge(host=args.host, service=args.service, dry_run=dry)


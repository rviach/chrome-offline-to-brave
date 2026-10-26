#!/usr/bin/env python3
"""
Convert ChromElevator-style password JSON into (optional) CSV.

Usage:
    python3 convert_passwords.py --dir <folder with passwords.json> [-o passwords_import.csv]

Direct CDP import (import_passwords_cdp.py) is the preferred path; the CSV is
kept for manual import through <browser>://password-manager/settings UI.
"""
import argparse
import csv
import json
import os
import sys


def load_entries(d):
    """Collect entries from passwords.json and passwords_account.json."""
    entries = []
    for fn in ("passwords.json", "passwords_account.json"):
        f = os.path.join(d, fn)
        if os.path.isfile(f):
            with open(f, encoding="utf-8") as fh:
                part = json.load(fh)
                entries.extend(part)
                print(f"  {fn}: {len(part)} entries")
    return entries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("-o", "--out", default="passwords_import.csv")
    args = ap.parse_args()

    src = os.path.expanduser(args.dir)
    entries = load_entries(src)
    if not entries:
        sys.exit(f"No passwords.json / passwords_account.json found in {src}")

    out_path = os.path.expanduser(args.out)
    rows = []
    seen = set()
    for e in entries:
        url = (e.get("url") or "").strip()
        user = (e.get("user") or "").strip()
        pw = e.get("pass") or ""
        if not url or not pw:
            continue  # credentials without URL/password cannot be added
        if not url.startswith(("http://", "https://")):
            url = "https://" + url.lstrip("/")
        key = (url, user)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"name": url, "url": url, "username": user, "password": pw})

    if not rows:
        sys.exit("No importable entries after filtering")

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["name", "url", "username", "password"])
        w.writeheader()
        w.writerows(rows)
    print(f"Written {len(rows)} rows -> {out_path}")

    # WARNING: the CSV contains plaintext passwords — delete it right after use.
    print("!!! Delete this CSV immediately after importing — it stores plaintext passwords.")


if __name__ == "__main__":
    main()

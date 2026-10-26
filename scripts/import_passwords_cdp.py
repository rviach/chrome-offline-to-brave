#!/usr/bin/env python3
"""
Bulk-import passwords into a Chromium-based browser via CDP + the
`chrome.passwordsPrivate.addPassword` WebUI API.

Why not the UI? The <browser>://password-manager "Import" button opens a
native file chooser that CDP cannot intercept on WebUI pages. Why not the
SQLite DB? The rows must be encrypted with the target browser's os-crypt key;
writing plaintext rows leaves the store non-functional. This script talks to
the browser's own API instead, so encryption is always correct.

Requirements (the importer needs full AddPasswordOptions):
    url, username, password, note (REQUIRED, may be ""), useAccountStore (bool)

Usage:
    python3 import_passwords_cdp.py \
        --dirs ../Chrome/Default ../Chrome/"Profile 1" ../Chrome/"Profile 6" \
        --port 9222

Notes:
  * target browser must be running with --remote-debugging-port,
  * a tab on <browser>://password-manager must be open (this script opens one),
  * duplicates are rejected by the browser itself ("entry ... already exists"),
  * the browser UI later *groups* identical url+username pairs, so the number
    of visible rows is smaller than the number of stored records — that is normal.
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from import_cookies import Cdp


def load_all(dirs):
    entries, seen = [], set()
    for d in dirs:
        d = os.path.expanduser(d)
        for fn in ("passwords.json", "passwords_account.json"):
            f = os.path.join(d, fn)
            if not os.path.isfile(f):
                continue
            for e in json.load(open(f, encoding="utf-8")):
                url = (e.get("url") or "").strip()
                user = (e.get("user") or "").strip()
                pw = e.get("pass") or ""
                if not url or not pw:
                    continue
                if not url.startswith(("http://", "https://", "android://")):
                    url = "https://" + url.lstrip("/")
                key = (url, user)
                if key in seen:
                    continue
                seen.add(key)
                entries.append({"url": url, "username": user, "password": pw})
    return entries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", nargs="+", required=True,
                    help="ChromElevator profile folders with passwords.json")
    ap.add_argument("--port", type=int, default=9222)
    ap.add_argument("--chunk", type=int, default=20)
    args = ap.parse_args()

    entries = load_all(args.dirs)
    print(f"deduped: {len(entries)} passwords to import")

    cdp = Cdp(args.port)
    t = cdp.call("Target.createTarget",
                 {"url": "chrome://password-manager/passwords"})
    a = cdp.call("Target.attachToTarget", {"targetId": t["targetId"], "flatten": True})
    sid = a["sessionId"]
    time.sleep(2)
    cdp.call_session(sid, "Runtime.enable")

    ok = err = 0
    start = time.time()
    for i in range(0, len(entries), args.chunk):
        part = entries[i:i + args.chunk]
        # NOTE: passwords live only in script memory; nothing is printed.
        expr = ("new Promise(res => { const L = " +
                json.dumps(part, ensure_ascii=False) + "; "
                "let okc=0, errc=0; Promise.all(L.map(v => "
                "chrome.passwordsPrivate.addPassword({url: v.url, "
                "username: v.username, password: v.password, note: '', "
                "useAccountStore: false}).then(()=>{okc++;},()=>{errc++;})))"
                ".then(()=> res(okc+':'+errc)); })")
        r = cdp.call_session(sid, "Runtime.evaluate",
                             {"expression": expr, "awaitPromise": True,
                              "returnByValue": True})
        val = r.get("result", {}).get("value")
        if val:
            a2, e2 = val.split(":")
            ok += int(a2)
            err += int(e2)
        done = min(i + args.chunk, len(entries))
        print(f"  {done}/{len(entries)}  ok={ok} err={err} ({time.time()-start:.0f}s)",
              flush=True)
    print(f"Finished: added {ok}, rejected {err} (duplicates are shown as errors).")

    # sanity check
    n = cdp.evaluate(sid, "new Promise(res => "
                          "chrome.passwordsPrivate.getSavedPasswordList("
                          "l => res(l.length)))", await_promise=True)
    print(f"Password manager now reports {n} credential group(s).")

    print("Restart the target browser WITHOUT --remote-debugging-port now!")


if __name__ == "__main__":
    main()

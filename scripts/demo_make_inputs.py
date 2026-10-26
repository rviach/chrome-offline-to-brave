#!/usr/bin/env python3
"""
Build a FAKE profile for recording demo GIFs/screencasts — zero real data.

Generates `demo/<name>/cookies.json` + `passwords.json` in the exact format
`chrome_ab_chain.py` produces (ChromElevator-compatible), but filled with
synthetic entries only: IANA reserved domains (example.com/.net/.org, ...),
usernames like `demo_user`, random throwaway passwords never shown on screen.

Record your demo with:
    python3 scripts/demo_make_inputs.py            # creates ./demo/Default
    # then follow docs/DEMO.md to run the importers against a disposable
    # browser profile and capture the terminal.

Everything generated here is safe to share: no real hosts, users or keys.
Delete ./demo afterwards anyway — it's meant for a single recording.
"""

import argparse
import json
import os
import random
import secrets
import string
import time

DEMO_DOMAINS = [
    "example.com", "example.org", "example.net", "example.edu",
    "www.w3.org", "datatracker.ietf.org", "httpbin.org",
]

COOKIES_PER_DOMAIN = 3
PASSWORDS_PER_DOMAIN = 1

NAME_POOL = [
    "session", "_ga", "csrf_token", "lang", "theme", "consent", "sid",
]

USER_POOL = [
    "demo_user", "alice@example.com", "bob@example.org", "tester",
]


def rand_password():
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(18))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="demo/Default")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    rng = random.Random(0xC0FFEE)
    now = time.time()

    cookies = []
    for dom in DEMO_DOMAINS:
        for i in range(COOKIES_PER_DOMAIN):
            name = rng.choice(NAME_POOL) + (str(i) if i else "")
            cookies.append({
                "name": name,
                "value": secrets.token_hex(8),
                "host": dom,
                "path": "/",
                "expires": int(now + rng.randint(86400, 86400 * 30)),
                "is_secure": rng.random() < 0.7,
                "is_httponly": rng.random() < 0.7,
            })

    passwords = []
    for dom in DEMO_DOMAINS:
        for i in range(PASSWORDS_PER_DOMAIN):
            passwords.append({
                # safe to show on screen; random and never printed again
                "url": f"https://{dom}/login",
                "user": USER_POOL[(len(passwords) + i) % len(USER_POOL)],
                "pass": rand_password(),
            })

    cf = os.path.join(args.out, "cookies.json")
    pf = os.path.join(args.out, "passwords.json")
    with open(cf, "w") as f:
        json.dump(cookies, f, ensure_ascii=False, indent=1)
    with open(pf, "w") as f:
        json.dump(passwords, f, ensure_ascii=False, indent=1)

    print(f"demo inputs written:")
    print(f"  {cf}: {len(cookies)} synthetic cookies")
    print(f"  {pf}: {len(passwords)} synthetic passwords")
    print(f"\nnext: see docs/DEMO.md for the recording recipe")
    print(f"(the passwords above were random one-offs, safe to disclose)")


if __name__ == "__main__":
    main()

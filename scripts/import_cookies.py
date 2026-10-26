#!/usr/bin/env python3
"""
Import cookies from a ChromElevator-style `cookies.json` into a target
Chromium-based browser (e.g. Brave) on Linux, via the Chrome DevTools
Protocol (CDP).

Usage:
    python3 import_cookies.py --dir <folder with cookies.json, e.g. ../Chrome/Default>
Options:
    --port 9222      CDP port (default 9222)
    --dry-run        count only, do not import
    --binary PATH    browser binary (default $BRAVE_BIN or "brave")

IMPORTANT: the target browser must be *fully closed* before starting. The
script checks this itself and can launch the browser with
--remote-debugging-port on the default profile.

Note: Chromium's remote-debugging endpoint only exposes valid UTF-8 "value"
fields, so cookies with binary values are skipped automatically (see README
"Known limitations").
"""

import argparse
import base64
import http.client
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PORT_DEFAULT = 9222
CHROME_EPOCH_DIFF = 11644473600  # seconds between 1601-01-01 and 1970-01-01 (Windows epoch)

BRAVE_BIN = os.environ.get("BRAVE_BIN", "brave")


# ---------------------------------------------------------------- websocket
class WsClient:
    """Minimal websocket client, stdlib only (built for CDP)."""

    def __init__(self, host, port, path):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(None)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        # read the HTTP response headers
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("ws handshake: connection closed")
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        if b"101" not in head.split(b"\r\n")[0]:
            raise RuntimeError(f"ws handshake failed: {head[:200]!r}")
        self._buf = rest

    def _recv_exact(self, n):
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("ws: connection closed by server")
            self._buf += chunk
        data, self._buf = self._buf[:n], self._buf[n:]
        return data

    def recv(self):
        """Return bytes of the next websocket message (handles fragmentation)."""
        payload = b""
        while True:
            b0, b1 = self._recv_exact(2)
            fin, opcode = bool(b0 & 0x80), b0 & 0x0F
            masked = bool(b1 & 0x80)
            length = b1 & 0x7F
            if length == 126:
                length = int.from_bytes(self._recv_exact(2), "big")
            elif length == 127:
                length = int.from_bytes(self._recv_exact(8), "big")
            mask = self._recv_exact(4) if masked else None
            data = self._recv_exact(length)
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if opcode == 9:  # ping -> pong
                self._send_frame(10, data)
                continue
            if opcode == 8:  # close
                raise RuntimeError("ws: server closed connection (close frame)")
            if opcode in (1, 0):
                payload += data
                if fin:
                    return payload

    def _send_frame(self, opcode, data):
        header = bytearray([0x80 | opcode])
        n = len(data)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += n.to_bytes(2, "big")
        else:
            header.append(0x80 | 127)
            header += n.to_bytes(8, "big")
        mask = os.urandom(4)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.sock.sendall(bytes(header) + masked)

    def send_text(self, text):
        self._send_frame(1, text.encode())


class Cdp:
    def __init__(self, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        conn.request("GET", "/json/version")
        resp = conn.getresponse()
        info = json.loads(resp.read().decode())
        if resp.status != 200:
            raise RuntimeError("CDP endpoint unavailable")
        ws_url = urllib.parse.urlsplit(info["webSocketDebuggerUrl"])
        self._ws = WsClient(ws_url.hostname, ws_url.port, ws_url.path)
        self._id = 0

    def call(self, method, params=None):
        """Browser-level CDP call (no sessionId)."""
        self._id += 1
        msg = json.dumps({"id": self._id, "method": method, "params": params or {}})
        self._ws.send_text(msg)
        target = self._id
        while True:
            data = json.loads(self._ws.recv().decode())
            if data.get("id") == target:
                if "error" in data:
                    raise RuntimeError(f"{method}: {data['error']}")
                return data.get("result", {})

    def call_session(self, sid, method, params=None):
        """Session-scoped CDP call.

        NOTE: `sessionId` must be a *top-level* field of the JSON message,
        NOT a key inside "params". Putting it inside params makes the browser
        look up `method` in the browser-level domain and answer
        `-32601 "X wasn't found"`.
        """
        self._id += 1
        msg = {"id": self._id, "method": method, "params": params or {}, "sessionId": sid}
        self._ws.send_text(json.dumps(msg))
        target = self._id
        while True:
            data = json.loads(self._ws.recv().decode())
            if data.get("id") == target:
                if "error" in data:
                    raise RuntimeError(f"{method}: {data['error']}")
                return data.get("result", {})

    def evaluate(self, sid, expression, await_promise=False, return_by_value=True):
        """Runtime.evaluate helper.

        NOTE: the response is *nested*: the value lives in
        result -> result -> value. Forgetting the nesting makes every
        evaluation look like it returned None.
        """
        params = {"expression": expression, "returnByValue": return_by_value}
        if await_promise:
            params["awaitPromise"] = True
        r = self.call_session(sid, "Runtime.evaluate", params)
        return r.get("result", {}).get("value")


# ---------------------------------------------------------------- helpers
def norm_cookie(raw):
    """ChromElevator JSON -> CDP Storage.Cookie dict. None = skip."""
    host = (raw.get("host") or raw.get("host_key") or "").strip()
    name = raw.get("name") or ""
    value = raw.get("value") or ""
    if not host or not name:
        return None

    expiry = None
    raw_exp = raw.get("expires")
    if isinstance(raw_exp, (int, float)) and raw_exp > 0:
        if raw_exp > 10_000_000_000_000_000:  # Chromium timestamp, us since 1601
            expiry = raw_exp / 1_000_000 - CHROME_EPOCH_DIFF
        elif raw_exp > 10_000_000_000:  # safety: treat as ms
            expiry = raw_exp / 1000
        else:  # already unix seconds
            expiry = float(raw_exp)

    cookie = {
        "name": name,
        "value": value,
        "domain": host,
        "path": (raw.get("path") or "/") or "/",
    }
    if expiry and expiry <= time.time():
        return None  # do not import expired cookies
    if expiry:
        cookie["expires"] = expiry
    if raw.get("is_secure"):
        cookie["secure"] = True
    if raw.get("is_httponly"):
        cookie["httpOnly"] = True
    return cookie


def load_cookies(json_file):
    with open(json_file, encoding="utf-8") as f:
        raw_list = json.load(f)
    seen = {}
    skipped = 0
    for raw in raw_list:
        c = norm_cookie(raw)
        if not c:
            skipped += 1
            continue
        key = (c["domain"], c["path"], c["name"])
        seen[key] = c  # duplicates: last one wins
    return list(seen.values()), skipped


# ---------------------------------------------------------------- main
def ensure_cdp(port):
    # port already open -> just recreate the Cdp handle
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=2)
        print(f"CDP already open on port {port} — reusing it.")
        return
    except (urllib.error.URLError, OSError):
        pass
    running = subprocess.run(["pgrep", "-x", os.path.basename(BRAVE_BIN)],
                             capture_output=True).returncode == 0
    if running:
        sys.exit(
            f"{BRAVE_BIN} is already running without CDP port {port}.\n"
            "Close it completely (pkill brave) and run the script again."
        )
    subprocess.Popen([BRAVE_BIN, f"--remote-debugging-port={port}", "--no-first-run"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=2)
            break
        except Exception:
            time.sleep(0.5)
    else:
        sys.exit("Could not bring up the CDP port on the browser.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True,
                    help="folder containing cookies.json (one Chrome profile)")
    ap.add_argument("--port", type=int, default=PORT_DEFAULT)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    src = os.path.expanduser(args.dir)
    json_file = os.path.join(src, "cookies.json")
    if not os.path.isfile(json_file):
        sys.exit(f"File not found: {json_file}")

    cookies, skipped = load_cookies(json_file)
    print(f"cookies.json: {len(cookies)} cookies to import "
          f"({skipped} skipped: expired or empty)")

    if args.dry_run:
        return

    ensure_cdp(args.port)
    cdp = Cdp(args.port)
    print("CDP connected.", flush=True)

    ctx = cdp.call("Target.getBrowserContexts")
    browser_context_id = ctx.get("defaultBrowserContextId")
    print(f"Profile (browserContextId): {browser_context_id}", flush=True)

    # Import one cookie per call: a single batch call fails entirely if ANY
    # cookie has a binary (non-UTF-8) value (CDP/mojo accepts only valid UTF-8).
    ok = 0
    bad = 0
    for c in cookies:
        cc = dict(c, browserContextId=browser_context_id)
        try:
            cdp.call("Storage.setCookies", {"cookies": [cc]})
            ok += 1
        except RuntimeError:
            bad += 1
            if bad <= 15:
                v = c.get("value", "")
                print(f"  skipped {c.get('domain')} {c.get('name')[:12]!r} "
                      f"(binary value, {len(v)} bytes)", flush=True)
    print(f"  imported one-by-one: OK={ok}, binary skipped={bad}", flush=True)

    after = cdp.call("Storage.getCookies",
                     {"browserContextId": browser_context_id}).get("cookies", [])
    print(f"Done. Browser now holds {len(after)} cookies "
          f"(whole default profile).", flush=True)

    print("The browser is still running with the CDP port open — verify tabs/logins, "
          "then restart it normally (without --remote-debugging-port).", flush=True)


if __name__ == "__main__":
    main()

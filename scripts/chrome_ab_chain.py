#!/usr/bin/env python3
"""
Offline Chrome App-Bound Encryption (ABE) recovery + data decryption.

Runs on Linux against a *mounted, powered-off* Windows drive (Measure: the
Windows system was never booted). Reproduces the ChromElevator JSON exports
(cookies.json / passwords.json) without running any Windows code.

Only flag-0x03 blobs (Chrome 137+ AES-256-GCM wrap) are fully implemented;
older flag-0x01/0x02 payloads are left as TODO (see docs/PIPELINE.md).

Usage:
  python3 chrome_ab_chain.py \
      --local-state "/mnt/win/Users/<u>/AppData/Local/Google/Chrome/User Data/Local State" \
      --keys keys.json \
      --ksp-dir "/mnt/win/ProgramData/Microsoft/Crypto/SystemKeys" \
      --profile "/mnt/win/Users/<u>/AppData/Local/Google/Chrome/User Data/Default" \
      [--profile ".../Profile 1" ...] \
      -o outdir

Each --profile must contain "Cookies" and/or "Login Data" SQLite files.
Output: outdir/<profile name>/cookies.json, passwords.json (ChromElevator
format, importable by the import_* scripts in this repo).

SECURITY: output JSONs contain PLAINTEXT cookies/passwords. Keep them in a
tmpfs, import immediately, then shred. See README "Ethics & threat model".
"""

import argparse
import base64
import io
import json
import os
import shutil
import sqlite3
import struct
import sys
import tempfile

from Cryptodome.Cipher import AES, PKCS1_v1_5
from impacket.dpapi import DPAPI_BLOB, bin_to_string, privatekeyblob_to_pkcs1

# public constants (see docs/PIPELINE.md for provenance)
KSP_ENTROPY = b"xT5rZW5qVVbrvpuA\x00"
XOR_KEY = bytes.fromhex(
    "CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
DPAPI_BLOB_MAGIC = b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf"
PRIVKEYBLOB_MAGIC = b"\x07\x02\x00\x00\x00\xa4\x00\x00"  # PRIVATEKEYBLOB, CALG_RSA_KEYX
CHROME_EPOCH_DIFF = 11644473600


def dpapi_blob_decrypt(blob_bytes, keys_by_guid, entropy=None):
    """Decrypt one DPAPI blob using a {masterkey-guid: masterkey-bytes} map."""
    blob = DPAPI_BLOB(blob_bytes)
    guid = bin_to_string(blob["GuidMasterKey"]).lower()
    key = keys_by_guid.get(guid)
    if key is None:
        return None
    try:
        return blob.decrypt(key, entropy)
    except Exception:
        return None


# ----------------------------------------------------------------- KSP path
def load_system_masterkeys(keys_json):
    store = json.load(open(keys_json))
    return {guid: bytes.fromhex(h)
            for guid, h in store.get("S-1-5-18", {}).items()}


def scan_ksp_containers(ksp_dir, sys_keys, entropy=KSP_ENTROPY):
    """Yield (filepath, decrypted payload) for every DPAPI blob inside the
    Microsoft Software KSP system key files that opens with the SYSTEM
    masterkeys + the elevation-service entropy."""
    for name in sorted(os.listdir(ksp_dir)):
        path = os.path.join(ksp_dir, name)
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        off = 0
        seen = set()
        while True:
            off = data.find(DPAPI_BLOB_MAGIC, off)
            if off < 0:
                break
            for ent in (entropy, None):
                plain = dpapi_blob_decrypt(data[off:], sys_keys, ent)
                if plain is not None:
                    seen.add(off)
                    yield path, plain
                    break
            off += 1
        # KSP export containers may use a non-1 version field before the
        # provider GUID, so also scan for the GUID alone (case: d42cc…key)
        off = 0
        while True:
            off = data.find(bytes.fromhex("d08c9ddf"), off)
            if off < 0:
                break
            start = off - 20  # typical DPAPI_BLOB leading header
            if start < 0:
                off += 1
                continue
            for ent in (entropy, None):
                if len(data) - start < 128:  # too short to be a DPAPI blob
                    break
                try:
                    plain = dpapi_blob_decrypt(data[start:], sys_keys, ent)
                except Exception:
                    plain = None
                if plain is not None and start not in seen:
                    seen.add(start)
                    yield path, plain
                    break
            off += 1


def rsa_wrap_unwrap(enc_key32, containers):
    """Strategy 1 (public, runassu-style but offline): the KSP container holds
    an RSA PRIVATEKEYBLOB; emulate NCryptDecrypt of the 32-byte wrapped key."""
    for path, blob in containers:
        i = blob.find(PRIVKEYBLOB_MAGIC)
        if i < 0 and blob[:4] == b"RSA2":
            # KSP export stores a bare RSAPUBKEY blob ("RSA2"…) without the
            # 8-byte PUBLICKEYSTRUC header; re-attach it (CALG_RSA_KEYX).
            blob = bytes((0x07, 0x02, 0x00, 0x00)) + struct.pack("<I", 0x0000A400) + blob
            i = 0
        if i < 0:
            continue
        try:
            rsa_key = privatekeyblob_to_pkcs1(parse_privkeyblob(blob[i:]))
            dec = PKCS1_v1_5.new(rsa_key).decrypt(enc_key32, b"\x00" * 32)
            if len(dec) == 32:
                return bytes(a ^ b for a, b in zip(dec, XOR_KEY)), path
        except Exception:
            continue
    return None, None


def parse_privkeyblob(data):
    """Minimal MS PRIVATEKEYBLOB (CALG_RSA_KEYX) parser."""
    # PUBLICKEYSTRUC: bType bVersion reserved(u16) aiKeyAlg(u32)
    # RSAPUBKEY: magic('RSA1') bitlen(u32) pubexp(u32)
    bitlen = struct.unpack_from("<I", data, 12)[0]
    pubexp = struct.unpack_from("<I", data, 16)[0]
    nbytes = bitlen // 8
    o = 20
    modulus = data[o:o + nbytes][::-1]; o += nbytes
    prime1 = data[o:o + nbytes // 2][::-1]; o += nbytes // 2
    prime2 = data[o:o + nbytes // 2][::-1]; o += nbytes // 2
    exp1 = data[o:o + nbytes // 2][::-1]; o += nbytes // 2
    exp2 = data[o:o + nbytes // 2][::-1]; o += nbytes // 2
    coeff = data[o:o + nbytes // 2][::-1]; o += nbytes // 2
    privexp = data[o:o + nbytes][::-1]
    return {"publickeystruc": data[:8], "rsapubkey": {"pubexp": pubexp},
            "modulus": modulus, "prime1": prime1, "prime2": prime2,
            "exponent1": exp1, "exponent2": exp2,
            "coefficient": coeff, "privateExponent": privexp}


def gcm_try(key, iv, ct_tag):
    try:
        return AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(
            ct_tag[:-16], ct_tag[-16:])
    except ValueError:  # tag mismatch
        return None


def recover_browser_key(payload93, sys_keys, ksp_dir):
    """payload93 = [flag(1) | enc_key(32) | iv(12) | ct(32) | tag(16)]."""
    flag = payload93[0]
    if flag != 3:
        raise SystemExit(
            f"flag {flag} blob: only Chrome 137+ (flag 0x03) is implemented")
    enc_key, iv = payload93[1:33], payload93[33:45]
    ct_tag = payload93[45:93]
    containers = list(scan_ksp_containers(ksp_dir, sys_keys))

    strategies = []

    # strategy 1: offline RSA unwrap from the SystemKeys container
    key, used = rsa_wrap_unwrap(enc_key, containers)
    if key:
        strategies.append(("KSP-RSA offline", key, used))

    # strategy 2/3 (empirical, see docs/PIPELINE.md): DPAPI(+entropy) result
    # is the wrapping material
    for path, blob in containers:
        if len(blob) >= 32:
            k32 = blob[:32]
            key = bytes(a ^ b for a, b in zip(k32, XOR_KEY))
            strategies.append(("KSP-DPAPI direct-XOR", key, path))
            # AES-256-CBC with zero IV variant
            if len(enc_key) % 16 == 0:
                dec = AES.new(k32, AES.MODE_CBC,
                              iv=b"\x00" * 16).decrypt(enc_key)[:32]
                key = bytes(a ^ b for a, b in zip(dec, XOR_KEY))
                strategies.append(("KSP-DPAPI AES-CBC0+XOR", key, path))
        if blob[:4] == b"KDBM" and len(blob) >= 44:
            # BCRYPT_KEY_DATA_BLOB: magic(4) ver(4) cbKeyData(4) key...
            # (verified recipe, aabston 2026 / SpecterOps 2025)
            cb = int.from_bytes(blob[8:12], "little")
            ksp_key = blob[12:12 + cb]
            key = bytes(a ^ b for a, b in zip(ksp_key, XOR_KEY))
            strategies.append(("KDBM direct-XOR", key, path))
            if len(enc_key) % 16 == 0:
                dec = AES.new(ksp_key, AES.MODE_CBC,
                              iv=b"\x00" * 16).decrypt(enc_key)[:32]
                key = bytes(a ^ b for a, b in zip(dec, XOR_KEY))
                strategies.append(("KDBM AES-CBC0+XOR", key, path))

    for name, key, src in strategies:
        plain = gcm_try(key, iv, ct_tag)
        if plain is not None and len(plain) == 32:
            print(f"browser key recovered via {name} (container: "
                  f"{os.path.basename(src)})")
            return plain
    raise SystemExit("browser key recovery failed: no strategy verified "
                     "(check ksp-dir / keys.json)")


# ------------------------------------------------------- app-bound key chain
def recover_app_bound_key(local_state_path, keys_json, ksp_dir):
    ls = json.load(open(local_state_path, encoding="utf-8"))
    b64 = ls["os_crypt"]["app_bound_encrypted_key"]
    blob = base64.b64decode(b64)
    assert blob[:4] == b"APPB", "unexpected app-bound key prefix"

    sys_keys = load_system_masterkeys(keys_json)
    outer = dpapi_blob_decrypt(blob[4:], sys_keys)  # SYSTEM layer
    if outer is None:
        raise SystemExit("outer (SYSTEM) DPAPI layer failed — keys.json "
                         "missing S-1-5-18 masterkey?")

    store = json.load(open(keys_json))
    user_keys = {g: bytes.fromhex(h)
                 for sid in store if sid != "S-1-5-18"
                 for g, h in store[sid].items()}
    inner = dpapi_blob_decrypt(outer, user_keys)  # user layer
    if inner is None:
        raise SystemExit("inner (user) DPAPI layer failed — user masterkey "
                         "not in keys.json?")

    stream = io.BytesIO(inner)
    vlen1 = struct.unpack("<I", stream.read(4))[0]
    stream.read(vlen1)                       # validation data (install path)
    vlen2 = struct.unpack("<I", stream.read(4))[0]
    payload = stream.read(vlen2)             # the 93-byte flagged payload
    return recover_browser_key(payload, sys_keys, ksp_dir)


# ------------------------------------------------------------- data decrypt
def gcm_decrypt(key, data):
    """v20 = b'v20' | nonce12 | ct | tag16. Returns plaintext bytes or None."""
    if len(data) < 3 + 12 + 20 or not data.startswith(b"v20"):
        return None
    nonce, body = data[3:15], data[15:]
    try:
        return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(
            body[:-16], body[-16:])
    except (ValueError, KeyError):
        return None


def open_sqlite_copy(path):
    """Copy DB (+wal/shm) to tmp so the read-only mount is never touched."""
    tmpd = tempfile.mkdtemp(prefix="abchain-")
    dst = os.path.join(tmpd, os.path.basename(path))
    shutil.copy(path, dst)
    for ext in ("-wal", "-shm"):
        if os.path.exists(path + ext):
            shutil.copy(path + ext, dst + ext)
    return sqlite3.connect(dst), tmpd


def decrypt_cookies(db_path, browser_key):
    conn, tmp = open_sqlite_copy(db_path)
    out = []
    for name, value, host, path_, is_secure, is_httponly, expiry in conn.execute(
            "SELECT name, encrypted_value, host_key, path, is_secure, "
            "is_httponly, expires_utc FROM cookies"):
        plain = gcm_decrypt(browser_key, value)
        if plain is None or len(plain) <= 32:
            continue
        val = plain[32:].decode("utf-8", "replace")
        exp = 0
        if expiry:
            exp = int(expiry / 1_000_000 - CHROME_EPOCH_DIFF)
        out.append({"name": name, "value": val, "host": host,
                    "path": path_, "expires": max(0, exp),
                    "is_secure": bool(is_secure),
                    "is_httponly": bool(is_httponly)})
    conn.close()
    shutil.rmtree(tmp, ignore_errors=True)
    return out


def decrypt_passwords(db_path, browser_key):
    conn, tmp = open_sqlite_copy(db_path)
    out = []
    for origin, user, pw in conn.execute(
            "SELECT origin_url, username_value, password_value FROM logins "
            "WHERE password_value != x''"):
        plain = gcm_decrypt(browser_key, pw)
        if plain is None:
            continue
        out.append({"url": origin or "", "user": user or "",
                    "pass": plain.decode("utf-8", "replace")})
    conn.close()
    shutil.rmtree(tmp, ignore_errors=True)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local-state", required=True)
    ap.add_argument("--keys", required=True, help="keys.json from "
                                                  "dpapi_keys_offline.py")
    ap.add_argument("--ksp-dir", required=True,
                    help="ProgramData/Microsoft/Crypto/SystemKeys")
    ap.add_argument("--profile", action="append", required=True,
                    help="Chrome user-data profile dir (repeatable)")
    ap.add_argument("-o", "--out", default="out")
    args = ap.parse_args()

    browser_key = recover_app_bound_key(
        args.local_state, args.keys, args.ksp_dir)
    print(f"app-bound browser key: recovered (32 bytes)")

    os.makedirs(args.out, exist_ok=True)
    total_c = total_p = 0
    for prof in args.profile:
        prof = os.path.expanduser(prof.rstrip("/"))
        pname = os.path.basename(prof) or "Default"
        d = os.path.join(args.out, pname)
        os.makedirs(d, exist_ok=True)
        cookies = passwords = []
        ck = os.path.join(prof, "Cookies")
        ld = os.path.join(prof, "Login Data")
        if os.path.isfile(ck):
            cookies = decrypt_cookies(ck, browser_key)
            json.dump(cookies, open(os.path.join(d, "cookies.json"), "w",
                                    encoding="utf-8"), ensure_ascii=False)
        if os.path.isfile(ld):
            passwords = decrypt_passwords(ld, browser_key)
            json.dump(passwords, open(os.path.join(d, "passwords.json"), "w",
                                      encoding="utf-8"), ensure_ascii=False)
        total_c += len(cookies)
        total_p += len(passwords)
        print(f"{pname}: {len(cookies)} cookies, {len(passwords)} passwords "
              f"-> {d}")

    print(f"\nDONE. {total_c} cookies, {total_p} passwords decrypted.")
    print("NOTE: the JSONs hold PLAINTEXT secrets. Import now, then delete "
          "(shred -u). Next: scripts/import_cookies.py + "
          "scripts/import_passwords_cdp.py.")


if __name__ == "__main__":
    main()

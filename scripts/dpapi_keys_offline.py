#!/usr/bin/env python3
"""
Offline DPAPI masterkey recovery from a *mounted, powered-off* Windows drive.

This replaces the live-Windows admin approach: no services, no LSASS, no
Windows boot. Windows registry hives plus Protect directories are read as
plain files and every discovered masterkey is dumped to a JSON key store.

Only impacket + pycryptodomex are required (same deps Chrome's own
OSCrypt work needs), no pip beyond those:
    impacket >= 0.11 (tested with 0.13.1)
    pycryptodomex

Required files from the Windows drive:
  --security        C:\\Windows\\System32\\config\\SECURITY
  --system          C:\\Windows\\System32\\config\\SYSTEM
  --system-protect  C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User
        (for SYSTEM-context DPAPI blobs, e.g. the outer ABE layer)
  --user-protect    C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Protect\\<SID>
        (for user-context DPAPI blobs, e.g. the inner ABE layer + legacy keys)
  --sid             S-1-5-21-... of the Windows user
  --password        the Windows user's login password (never leaves the script)

Usage:
    python3 dpapi_keys_offline.py \\
      --system /mnt/win/Windows/System32/config/SYSTEM \\
      --security /mnt/win/Windows/System32/config/SECURITY \\
      --system-protect /mnt/win/Windows/System32/Microsoft/Protect/S-1-5-18/User \\
      --user-protect "/mnt/win/Users/<u>/AppData/Roaming/Microsoft/Protect/S-1-5-21-XXXXXXXX" \\
      --sid S-1-5-21-XXXXXX -o keys.json

Output keys.json: {"system": {guid: hex}, "user": {sid: {guid: hex}}} —
hex only, no plaintext secrets.
"""

import argparse
import getpass
import json
import os
import sys
import glob
import binascii

from binascii import hexlify
from impacket import LOG
from impacket.dpapi import (MasterKeyFile, MasterKey, deriveKeysFromUser)
from impacket.examples.secretsdump import LocalOperations, LSASecrets

LOG.setLevel("ERROR")


def read_masterkey_file(path):
    """Return (guid, [segment],

    Segments: [primary MasterKey, backup MasterKey] as naked structures.
    """
    with open(path, "rb") as f:
        data = f.read()
    mkf = MasterKeyFile(data)
    guid = mkf["Guid"].decode("utf-16le")
    data = data[len(mkf):]
    segments = []
    if mkf["MasterKeyLen"] > 0:
        segments.append(MasterKey(data[: mkf["MasterKeyLen"]]))
        data = data[mkf["MasterKeyLen"]:]
    if mkf["BackupKeyLen"] > 0:
        segments.append(MasterKey(data[: mkf["BackupKeyLen"]]))
        data = data[mkf["BackupKeyLen"]:]
    return guid, segments


def lsa_dpapi_keys(system_path, security_path):
    """Extract dpapi_machinekey / dpapi_userkey from the SECURITY hive."""
    out = {}

    def cb(secret_type, secret):
        # LSASecrets prints the secret string before the callback for
        # dpapi_machinekey / dpapi_userkey.
        if isinstance(secret, str) and secret.startswith("dpapi_machinekey:"):
            for line in secret.split("\n"):
                kind, _, hexpart = line.partition(":")
                kind = kind.strip()
                if kind in ("dpapi_machinekey", "dpapi_userkey"):
                    out["MachineKey" if kind.endswith("machinekey") else "UserKey"] = \
                        binascii.unhexlify(hexpart.strip().removeprefix("0x"))

    boot_key = LocalOperations(system_path).getBootKey()
    lsa = LSASecrets(security_path, boot_key, None, isRemote=False,
                     history=False, perSecretCallback=cb)
    lsa.dumpSecrets()
    if "MachineKey" not in out or "UserKey" not in out:
        sys.exit("Could not obtain dpapi_machinekey/dpapi_userkey "
                 "(check SYSTEM+SECURITY paths)")
    return out


def decrypt_masterkey_dir(prot_dir, sid, candidates, result):
    """Decrypt every masterkey file in <prot_dir> using the candidate keys."""
    found = result.setdefault(sid, {})
    for path in sorted(glob.glob(os.path.join(prot_dir, "*"))):
        if os.path.isdir(path):
            continue
        try:
            guid, segments = read_masterkey_file(path)
        except Exception:
            continue
        for seg in segments:
            for cand in candidates:
                try:
                    key = seg.decrypt(cand)
                except Exception:
                    key = None
                if key:
                    found.setdefault(guid, hexlify(key).decode())
                    break
            else:
                continue
            break
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--system", required=True)
    ap.add_argument("--security", required=True)
    ap.add_argument("--system-protect", help="Protect\\S-1-5-18\\User dir")
    ap.add_argument("--user-protect", help="Protect\\<SID> dir")
    ap.add_argument("--sid", help="SID corresponding to --user-protect")
    ap.add_argument("--password", help="Windows login password "
                                      "(or leave empty to be prompted)")
    ap.add_argument("-o", "--out", default="keys.json")
    args = ap.parse_args()

    keys = {}

    # ---- system (S-1-5-18) masterkeys --------------------------------
    if args.system_protect:
        dpapi_keys = lsa_dpapi_keys(args.system, args.security)
        sys_candidates = [dpapi_keys["UserKey"], dpapi_keys["MachineKey"]]
        decrypt_masterkey_dir(args.system_protect, "S-1-5-18",
                              sys_candidates, keys)
        got = keys.get("S-1-5-18", {})
        print(f"system (S-1-5-18) masterkeys: {len(got)} decrypted")
    else:
        keys["S-1-5-18"] = {}

    # ---- user masterkeys ---------------------------------------------
    if args.user_protect:
        sid = args.sid
        password = args.password or getpass.getpass(
            f"Windows login password for {sid}: ")
        user_candidates = deriveKeysFromUser(sid, password)
        keys[sid] = {}
        got = decrypt_masterkey_dir(args.user_protect, sid,
                                    user_candidates, keys)
        n_new = sum(1 for _, v in got.items() if v)
        print(f"user ({sid}) masterkeys: {n_new} decrypted "
              f"(password-based, never written anywhere)")
        if not got:
            sys.exit("No user masterkey decrypted — wrong password? "
                     "(the newest masterkey usually matches)")

    with open(args.out, "w") as f:
        json.dump(keys, f, indent=1)
    print(f"key store written -> {args.out}")
    print("WARNING: keys.json unlocks the browser profile — keep it out of sync"
          " folders and delete it after the migration.")


if __name__ == "__main__":
    main()

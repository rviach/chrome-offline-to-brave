# The offline pipeline, byte by byte

Everything below was performed **offline**: the Windows drive was mounted
read-only on Linux (`/mnt/win*`, `ro`), the Windows OS was **never booted**.
All decoding was done with Python + `impacket` + `pycryptodomex` only.

Chromium versions involved: modern Windows Chrome (flag `0x03` ABE wrap,
Chrome 137+) → Brave on Linux. Public reference points:
[runassu/chrome_v20_decryption](https://github.com/runassu/chrome_v20_decryption)
(live-Windows + admin path, same inner formats) and
[xaitax/Chrome-App-Bound-Encryption-Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
(JSON export formats our scripts reuse). The novelty here is the
**no-Windows-boot** variant of flag `0x03` recovery.

## 0. Overview

```
Windows NTFS (mounted ro)
├── Windows/System32/config/{SYSTEM,SECURITY}          → system DPAPI keys
├── Windows/System32/Microsoft/Protect/S-1-5-18/User   → SYSTEM masterkeys
├── Users/<u>/AppData/Roaming/Microsoft/Protect/<SID>  → user masterkeys
├── Users/<u>/AppData/Local/Google/Chrome/User Data
│   ├── Local State        (os_crypt.app_bound_encrypted_key, base64 "APPB…")
│   └── {Default,Profile N}/{Cookies,"Login Data",Bookmarks}
└── ProgramData/Microsoft/Crypto/SystemKeys            → KSP key container(s)
```

## 1. DPAPI masterkeys, offline

* Bootkey is carved out of the `SYSTEM` hive (`JD`/`Skew1`/`GBG`/`GF`
  class strings, deskewed) — `impacket.examples.secretsdump.LocalOperations`.
* `LSASecrets` (SECURITY hive) decrypts the LSA secrets with the bootkey;
  the `DPAPI_SYSTEM` secret carries two 20-byte keys:
  `dpapi_machinekey` and `dpapi_userkey`.
* Masterkey files under `Protect\S-1-5-18\User\` are decrypted with those
  20-byte keys directly (masterkey segment vs HMAC check in
  `impacket.dpapi.MasterKey.decrypt`).
* User masterkeys under `Roaming\Microsoft\Protect\<SID>\` are decrypted
  with candidates from `impacket.dpapi.deriveKeysFromUser(sid, password)` —
  the Windows login password is needed for the *newest* key only; wrong
  passwords decrypt nothing (HMAC verification). The password never leaves
  the script; `keys.json` stores derived masterkeys as hex.

Observed in the real run: the newest user masterkey used the
SHA-512/AES-256/rounds=8000 scheme; all blobs below resolved through it.

## 2. The App-Bound key chain (`Local State` → browser key)

`Local State → os_crypt.app_bound_encrypted_key`:

```
base64 → strip 4-byte "APPB" prefix
       → DPAPI blob  (context: SYSTEM)          ← S-1-5-18 masterkey
       → DPAPI blob  (context: user)            ← user masterkey
       → plaintext:
             [u32 31][31-B validation data]     ← browser install path etc.
             [u32 93][93-B payload]
```

93-byte payload (flag `0x03`, Chrome 137+):

```
[1B flag=0x03][32B enc_aes_key][12B IV][32B ct][16B GCM tag]
```

`enc_aes_key` is unwrapped by the elevation service's KSP key
(Windows Software Key Storage Provider, key name `Google Chromekey1`,
container files under `ProgramData/Microsoft/Crypto/SystemKeys/`):

1. The container file (on the real box: `7096db7aeb75c0d3497ecd56d355a695_`
   `<GUID>`; the `<16hex>` prefix is an install-independent hash of the key
   name, the GUID suffix differs per install) holds a DPAPI blob protected
   with the **system** masterkey + the hard-coded entropy
   `xT5rZW5qVVbrvpuA\0` (embedded in Chrome's elevation-service binary; the
   same constant observed by public research). Decrypting it offline needs
   the S-1-5-18 masterkeys — no live Windows, unlike the public admin-mode
   PoCs.
2. The DPAPI plaintext is a **`BCRYPT_KEY_DATA_BLOB`** (`KDBM` magic):
   `magic(4) | version=1(4) | cbKeyData=32(4) | key(32B)` — the KSP key is
   `plaintext[12:44]`, **not** the first 32 bytes. (Taking `[:32]`, including
   the 12-byte header, made every strategy silently fail — that off-by-12
   was the real bug in earlier attempts, masked as "wrong crypto".)
3. Unwrap the wrapped AES key:
   ```python
   key1 = AES(ksp_key, AES.MODE_CBC, iv=b"\x00"*16).decrypt(enc_aes_key)
   key2 = key1 XOR CCF8A1CE…392390          # public constant (runassu)
   browser_key = AES-GCM(key2, IV).decrypt_and_verify(ct‖tag)   # 32 bytes
   ```
   The GCM tag is the built-in integrity oracle: the blob verifies only
   with the one correct key.
4. The 32-byte plaintext **is** the browser key for every v20 row.

Verified end-to-end offline (no Windows boot) on a real profile:
201 v20 rows in the account store + v20 cookie rows, 100% GCM-verified.

What the earlier revision of this doc got wrong (fixed 2026-10-27,
commit `c0cb20b`):
* it claimed the real path went through an RSA `PRIVATEKEYBLOB` inside the
  container — no RSA is involved anywhere in the working chain; the
  `RSA2`-prefixed 388-byte export found in
  `Crypto/RSA/S-1-5-18/d42cc…_295…` is a different (non-Chrome or
  auxiliary) KSP structure and never verified;
* scripts re-strip the GCM tag twice (`data[15:-16]` then `ct[:-16]`)
  which made *every* row decrypt fail — corrected `gcm_decrypt` in
  `chrome_ab_chain.py`;
* KSP blob scanning must also try `entropy=None` and a GUID-only magic
  (some containers use a non-1 version field before the provider GUID);
* the v10 key (`os_crypt.encrypted_key`, user-DPAPI) is still needed to
  satisfy legacy rows, and the same user masterkey is reused for the
  inner (user-DPAPI) layer above — one masterkey lookup serves both.

Legacy note: flag `0x01` (AES-GCM with the constant key `B31C…4787`) and
flag `0x02` (ChaCha20-Poly1305, constant `E98F…9660`) are pre-137 formats,
documented by `runassu`; those branches are TODO in these scripts (the test
machine was already on 137+).

## 3. Data formats

### Cookies (`v20`)

```
encrypted_value = "v20" | 12B nonce | AES-256-GCM(ct‖tag, key=browser key)
plaintext       = 32B header + cookie value UTF-8
```

The 32-byte per-row header is discarded. Rows with v10/v11 legacy prefixes
were absent on the target system; legacy branches are TODO.

### Passwords

`Login Data → logins.password_value`, same v20 layout; the plaintext **is**
the password (no 32-byte header).

Also check `Login Data For Account` (same directory): on Google-synced
profiles the *account* store is where the synced credentials (including
`android://` rows) actually live — on the real target the per-profile
`Login Data` had **0** rows while `Login Data For Account` held 249
(233 v20 + 16 empty). The upstream tooling (`import_passwords_cdp.py`)
reads both `passwords.json` and `passwords_account.json` per profile dir.

### Bookmarks

Chromium `Bookmarks` JSON is identical on both ends. Merge recipe: fresh
numeric `id`s behind the target's max id, fresh `guid`s, delete the source
`checksum` (the target recomputes and self-repairs), imported trees go under
wrapper folders ("Chrome Default", …).

## 4. Known limitations found on the real run

* 13 cookies had **binary values** (invalid UTF-8) — CDP
  `Storage.setCookies` rejects them; those sessions need a manual re-login.
  A batched `setCookies` call fails *entirely* if any cookie in it is binary —
  so the importer calls it one cookie per call.
* Google-account profile sync cannot move to Brave (Brave does not
  participate in Google sync). Saved-site data moves; the account state does
  not.
* `android://` credentials keep their original identifier format
  (`android://<hash>@<package>/`); password managers render them as
  `android://` entries and they re-group visually by package, which looks
  odd at first but is normal. They cannot be rewritten to https:// URLs —
  the browser treats them as a separate scheme.
* KSP `Google Chromekey1` is only resolvable on a live Windows box via the
  NCrypt name; offline we go straight to the container files on disk.

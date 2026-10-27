# Brave-specific troubleshooting (things that cost us hours)

Everything in this file was hit and fixed on the real migration
(Linux Brave/Chromium receiving data imported from Windows Chrome).

## 1. "Password manager is empty although `Login Data` has 200+ rows"

Symptom: the SQLite DB clearly contains imported passwords, but
`brave://password-manager/passwords` shows nothing right after import, and
no error appears anywhere.

Cause: Chromium **hides** password rows it cannot decrypt. The importer
talked to a running browser whose os-crypt service had no keyring access,
so every freshly written row existed but was invisible.

On this setup the keyring is `kwalletd6` (KWallet), and under a plain GNOME
session nobody had started it. Fixes:

1. Start it once immediately:
   ```sh
   systemctl --user start kwalletd6.service
   # or dbus-run: busctl --user call org.freedesktop.DBus \
   #   /org/freedesktop/DBus org.freedesktop.DBus StartServiceByName ss ...
   ```
2. Make it survive reboots under a non-Plasma desktop — autostart file:
   `~/.config/autostart/kwalletd6.desktop`
   ```ini
   [Desktop Entry]
   Type=Application
   Name=KWallet Wallet Service
   Exec=/usr/lib/kf6/kwalletd6
   NoDisplay=true
   ```
   (adjust `Exec` to your distro path, e.g. `/usr/bin/kwalletd6`.)
3. **Restart the browser** after the keyring appears. Rows already pass
   through invisible → visible without reimport.

Sanity check: `ls ~/.local/share/kwalletd/` — the wallet file must be
non-empty and owned by your user.

## 2. Silent total loss: os-crypt key rotation after an agent relaunch

(added 2026-10-27 after a real incident)

Symptom: after some restarts of the browser **every** password row becomes
undecryptable and **all** sessions are logged out at once. No errors
anywhere. The user did nothing unusual — the relaunches were done by
automation.

Cause chain on this box (GNOME + kwallet):

1. A launch was made in a broken environment (no `DBUS_SESSION_BUS_ADDRESS`
   / `XDG_RUNTIME_DIR`, e.g. through `systemd-run` without harvesting the
   session env). kwallet was unreachable from that context.
2. Chromium falls back to "make a new key" and **overwrites** the
   `Brave Keys/Brave Safe Storage` item in the wallet. The old key value
   is gone — not moved, overthrown. The same happened to a
   `gnome-keyring/Brave Safe Storage` item created during a different
   fallback run (it held the *newly* rotated key too).
3. From that moment every stored blob in `Login Data` / `Cookies` is
   garbage to the browser, and every session cookie is dropped.

Verification toolkit (all offline, no secrets printed):

* `pgrep -ax kwalletd6` — the daemon must be up before any browser start.
* item present: `secret-tool search --all application brave`
  and `kwallet-query -f 'Brave Keys' -l kdewallet`.
* checking which backend the browser actually used, and the forensics of
  "is it decryptable at all": brute-force the recorded key candidates
  against `logins.password_value` with `salty-salt`/`peppy`/`peanuts`
  salt variants — expect 2 spurious "hits" out of hundreds of rows from
  statistical noise (both observed); a real hit is a wall of rows.

Rules that keep it from ever happening again:

* **Agent-driven relaunches must go through `port.sh`** (it aborts when
  kwalletd6 is down, harvests the GNOME session env, and pins
  `--password-store=kwallet --disable-features=UsePortalOsCrypt`).
  The user's own desktop launcher starts with a sane env and does not
  need any change — recorded as `~/.agents/memory/brave-launch-rule.md`.
* Never `pkill -9` the browser from scripts unless SIGTERM fails twice;
  graceful restart keeps the profile file handle clean.
* After any scripted restart: close the CDP port (`port.sh off`), the
  browser must not live on `9222`.

Recovery paths when the key *was* rotated (both proven on this machine):

* **Same-day**: if you have an older machine/wallet copy of
  `Brave Safe Storage`, write it back into both kwallet and
  gnome-keyring and restart the browser through `port.sh`.
* **Offline Windows decrypt**: follow `docs/PIPELINE.md` — the Windows
  account store (`Login Data For Account`, `v20` rows) decrypts fully
  offline (SYSTEM masterkeys from hives + the KSP container blob), then
  re-import through `import_passwords_cdp.py`.

## 3. CDP gotchas (remote-debugging automation)

* **`sessionId` must be a top-level JSON field**, not a member of
  `params`. Putting it inside `params` makes the browser look the method up
  in the *browser-level* domain and answer `-32601 … wasn't found` even for
  perfectly valid `Storage.*` calls.
* **`Runtime.evaluate` nests its result twice**: the response is
  `result → result → value`. Reading only the outer `result` makes every
  evaluation look like it returned `None`.
* **Batch cookie import fails atomically**: one `Storage.setCookies` call
  with several cookies dies completely if *any* of them has a binary
  (non-UTF-8) value. Import one cookie per call; count and skip the failures.
* The password-manager page has **no importable UI**: the "Import" button
  opens a *native* file chooser, which CDP cannot drive. That is why the
  import path in this repo goes through
  `chrome.passwordsPrivate.addPassword` on the WebUI page instead. The
  options object must include `note` (may be `""`) and `useAccountStore`
  (`false`), or the call rejects.
* Duplicates are rejected by the browser itself ("entry already exists");
  count them as successful skips, not errors.
* The manager later **groups** entries with identical url+username, so the
  number of visible rows is smaller than the number of stored records —
  normal.

## 4. `android://` credential entries

Credentials captured from Chrome-on-Android (usually synced into the PC
profile) are stored under the scheme `android://<hash>@<package>/`. They
import fine, render in the UI tied to the app package, and are a legitimate
scheme — do not "fix" them into fake https:// URLs; the browser handles the
display. Deduplication during import: skip a candidate whose
(url, username) pair already exists.

## 5. Rules that prevent re-doing the whole migration

* Back up `~/.config/BraveSoftware/Brave-Browser` before touching anything.
* Never write to the Windows drive: mount `ro`, copy databases out, and
  work on copies (`chrome_ab_chain.py` does the copy internally).
* After any CDP session, close the browser and start it normally —
  `--remote-debugging-port` must not stay on in day-to-day use.
* Deletion discipline: keys.json, decryption outputs, password CSVs — all
  live in tmpfs and are removed right after import.

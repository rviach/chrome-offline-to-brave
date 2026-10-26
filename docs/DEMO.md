# Recording a safe demo (GIF / screencast)

Goal: a short README video showing the importers working end-to-end, using
**only synthetic data** (see `demo_make_inputs.py`). Real data must never
appear — the original artifacts were destroyed on purpose after the
migration.

## 1. Generate the fake inputs

```sh
python3 scripts/demo_make_inputs.py        # → ./demo/Default
```

Hosts are IANA reserved domains (example.com/…), passwords are random
one-offs. Safe to record, safe to publish.

## 2. Launch a disposable browser profile

Use a separate user-data directory so nothing touches the real profile:

```sh
brave --user-data-dir=/tmp/demo-profile \
      --remote-debugging-port=9222 \
      --no-first-run &
```

## 3. Run the importers (as-is, they are data-agnostic)

```sh
python3 scripts/import_cookies.py --dir demo/Default
python3 scripts/import_passwords_cdp.py --dirs demo/Default
```

What appears on screen, and why it is demo gold:

* `cookies.json: 21 cookies to import (0 skipped)`
* `imported one-by-one: OK=21, binary skipped=0`
* `Done. Browser now holds 21 cookies`
* password phase ending with
  `Password manager now reports N credential group(s).`
* optionally switch to the Brave window and show the fake passwords listed
  in `brave://password-manager` (they are synthetic — nothing to blur)

## 4. Capture

Terminal-only version (recommended for a README):

```sh
asciinema rec demo.cast          # run section 2+3 inside
agg demo.cast demo.gif           # asciinema's gif generator (package: agg)
```

With UI:

* `kooha` or `peek` (Wayland-friendly) — record the region with the terminal
  and the browser side by side, 20–40 s, cut the fat.

Keep it under ~30 seconds — that is the whole point of a README demo.

## 5. Where to put it

* `docs/demo.gif` (keep < 2 MB; `agg -s 8 demo.cast demo.gif` downsamples)
* Reference it at the very top of `README.md`:

```markdown
![demo](docs/demo.gif)
```

## 6. Honest-labeling note (important)

A demo has already been recorded this way: `docs/demo.gif` shows the
**import/migration half faithfully** — the GIF was produced from the
verbatim stdout of the real scripts running against a disposable headless
Brave profile with the synthetic inputs above (`agg`-free pipeline:
ghostscript-rendered frames + ffmpeg). Long "restart the browser" notice
lines were trimmed for length; nothing else was changed, and prompts are
echoed as the commands that actually ran.

The **decryption half** (`chrome_ab_chain.py`) requires actual Windows
DPAPI artifacts and cannot be re-run — its demo would need a
"reconstructed transcript" clearly captioned as such. Do not present a
scripted replay as a live run.

# Parity Plan: wormhole-william (Go) ↔ magic-wormhole (Python reference)

**Analysis date:** 2026-11-12
**Go side:** this repository — `github.com/dougsko/wormhole-william` (recently rebranded fork of psanford/wormhole-william)
**Python reference:** `magic-wormhole` 0.24.0, installed at `/tmp/wormhole-venv/lib/python3.14/site-packages/wormhole/` (venv binaries: `/tmp/wormhole-venv/bin/wormhole`, `/tmp/wormhole-venv/bin/magic-wormhole`)
**Scope exclusions:** dilation is explicitly out of scope. Also out of scope: the Python `wormhole-mailbox-server` package (rendezvous *server*), `magic-wormhole-mailbox-urandom`, and any Twisted-specific architecture.
**Guiding constraints:**
- Keep the existing Go library API stable; parity work adds behavior and options, it does not break callers.
- The Go client must stay wire-compatible with the Python client (interop both directions).
- Where the Python behavior is clearly a bug or an accident, document it and choose the sane behavior — flag for decision, don't silently copy.

Recent commits already delivered a chunk of parity work (`CLI parity with python 0.24.0`, `P0: path-traversal safety on receive`, `ssh subcommand`). This document reflects the current, verified state and what remains. Status legend: **DONE** (implemented + tested), **PARTIAL**, **OPEN**, **DECIDE** (needs a decision before work), **WONTFIX** (consciously not matching Python).

---

## 1. Baseline inventory

### 1.1 Python 0.24.0 surface (reference)

CLI commands: `send` (alias `tx`), `receive` (aliases `rx`, `recv`, `recieve` [sic]), `ssh invite`, `ssh accept`, `help`.
Global options: `--appid`, `--relay-url` (env `WORMHOLE_RELAY_URL`, default `ws://relay.magic-wormhole.io:4000/v1`), `--transit-helper` (env `WORMHOLE_TRANSIT_HELPER`, default `tcp:transit.magic-wormhole.io:4001`), `--dump-timing FILE.json`, `--version`.
Common per-subcommand flags (send/receive): `-0/--zeromode`, `-c/--code-length`, `-v/--verify`, `--hide-progress`, `--listen/--no-listen`, `--tor`, `--launch-tor`, `--tor-control-port`.
Send-only: `--code`, `--text` (`-` = stdin), `--ignore-unsendable-files`, `--debug-state`, `--qr/--no-qr` (env `WORMHOLE_QR`, default on).
Receive-only: `-t/--only-text`, `--accept-file` (env `WORMHOLE_ACCEPT_FILE`), `-o/--output-file`, `-a/--allocate`, `--debug-state`.
`receive --code-length` only valid together with `--allocate`.
SSH flags: `ssh invite -c/--code-length (default 2) --user`; `ssh accept -F/--key-file -y/--yes`.
Hidden debug: `--debug-state MACHINES` (state-machine tracing; send/receive).
Interactive receiver prompt uses readline-style input with tab-completion of code words (`input_with_completion`, `_rlcompleter.py`).

Send behaviors: realpath resolution of `what`, basename preserved even across symlinked directories; files (`.isfile`), directories (zip via ZipStream, streamed, follows symlinks with `followlinks=True`, `preserve_empty=True`), block devices (`S_ISBLK`); unsendable files → `UnsendableFileError` unless `--ignore-unsendable-files`; broken symlinks inside a directory → error unless flag.
Directory entries arcname = `relpath(path, top)` with forward slashes.
Sender sends `{"offer": {...}}` after `{"transit": ...}`; receives `{"answer": {"file_ack": "ok"}}` then a transit connection; zero-length files are never transmitted ("don't send zero-length files"); empty zip possible.

Receive behaviors: zero-mode code `0-`; allocate-mode prints "Allocated code: …"; prompt `Enter receive wormhole code: ` with completion; `ok? (Y/n): ` permission prompt (default **yes**); `--output-file` semantics (see §4.3); free-disk-space check (`estimate_free_space`) before accepting; temp file `.tmp` + rename; zip extraction with path-traversal guard and `chmod` from external_attr; sha256 hash sent back in `{"ack": "ok", "sha256": …}`; text messages printed via stdout.
Errors → `scary` mood on wrong password; `ServerConnectionError` special-cased; `WelcomeError` ("welcome" motd) printed.
Welcome handling: prints motd; prints "errors may occur…" version warning only if our version is a *release* (no `+` in version) and differs from `current_cli_version`.
Status: prints "Note: code has been consumed and can no longer be used." when the mailbox closes consumed.
`--dump-timing`: writes `DebugTiming` JSON (import, state-machine timings…).

### 1.2 wormhole-william current state (verified 2026-11-12)

- Protocol core: SPAKE2 (internal/gospake2, python test vectors), HKDF phase-key derivation, secretbox record encryption, transit-key derivation, transit handshake + relay "please relay" token, app_versions message, `pake` message, version message. Interop with Python works for text/file/directory (existing Go tests + manual).
- CLI: `send` (text/file/dir, `--code`, `-c/--code-length`, `--text -`, `--ignore-unsendable-files`, `--verify`, `--hide-progress`, `--qr` (env `WORMHOLE_QR`, default on), `-0/--zeromode`), `receive`/`recv` (`-0`, `-t/--only-text`, `-a/--allocate`, `--accept-file` (env), `-o/--output-file`, `--verify`, `--hide-progress`, `--code` via arg), `ssh invite/accept`, `shell-completion` (cobra; completes the receive code's nameplate + word pairs — Go-only extra), global `--relay-url`/`WORMHOLE_RELAY_URL`, `--transit-helper`/`WORMHOLE_TRANSIT_HELPER`, `--appid`, `--no-listen`.
- receive `--allocate` prints "Allocated code: …" and instructions.
- Path safety: `safeBaseName`, `zipPathContained` (with tests), zip slip protection, unsafe-filename refusal, `.tmp` + rename, progress bars (pb), sha256 verify of received payload.
- Welcome: motd printed, version warning printed on mismatch (not gated on release-vs-dev versions).
- `NoListen` implemented (`--no-listen`), plumbed into transit hints.
- Tests: `wormhole_test.go` (send/recv text, file, directory, relay, cancel mid-stream, empty file), `rendezvousservertest` in-process server, `internal/gospake2` vector tests, `cmd/paths_test.go`.
- Go version: `version.AgentVersion = v1.0.8`.

---

## 2. Gap matrix

| # | Area | Python 0.24.0 | Go status | Plan item |
|---|------|---------------|-----------|-----------|
| 1 | send alias `tx` | yes | OPEN | §3.1 |
| 2 | receive aliases `rx`, `recieve` | yes (`recv` exists in Go) | PARTIAL | §3.1 |
| 3 | `receive --code-length` (requires `--allocate`) | yes | OPEN | §3.2 |
| 4 | Version-mismatch warning gated on release versions | yes | PARTIAL (warns always) | §3.3 |
| 5 | Interactive tab-completion of code on receive prompt | yes | OPEN (shell completion only completes argv) | §3.4 (optional) |
| 6 | `--listen/--no-listen` as a pair (default listen) | yes | PARTIAL (`--no-listen` only) | §3.5 |
| 7 | `--dump-timing FILE.json` | yes | OPEN | §6.2 |
| 8 | `--debug-state` | yes | OPEN | §6.3 (DECIDE: implement vs accept-and-ignore) |
| 9 | Tor: `--tor`, `--launch-tor`, `--tor-control-port` (send/receive/ssh) | yes | OPEN | §7 |
| 10 | Free disk space check before accepting a file/directory | yes (`estimate_free_space`) | OPEN | §4.1 |
| 11 | `--output-file` pointing at existing **file** → overwrite allowed | yes | OPEN (always refuses) | §4.3 |
| 12 | `--output-file` pointing at existing **directory** → put transfer inside it (join basename), for directories too | yes | PARTIAL (works for files; directory case doesn't join basename) | §4.3 |
| 13 | Permission prompt `ok? (Y/n):` default-yes, accepts "y…"/empty | yes | DIFFERS (`ok? (y/N):` default-no, requires exactly "y") | §4.2 |
| 14 | Empty directory send (0 entries, `preserve_empty`) | yes | OPEN (errors "no files provided") | §5.1 |
| 15 | Directory send follows symlinks (`followlinks=True`), incl. symlinked dirs | yes | OPEN (Walk doesn't follow; symlinks silently skipped) | §5.2 |
| 16 | Broken symlink in directory → error (or skipped with flag) | yes | OPEN (silently skipped) | §5.2 |
| 17 | Directory send: preserve file mtimes / dir modes in zip | yes (ZipStream keeps metadata-ish) | PARTIAL (mode set, mtime not) | §5.3 |
| 18 | Block device send (`S_ISBLK`) | yes (Linux/macOS) | OPEN | §5.4 (DECIDE) |
| 19 | "Note: code has been consumed and can no longer be used." | yes (via status machine) | OPEN | §4.5 |
| 20 | Wrong-password CLI error → friendly `WrongPasswordError` text + scary mood | yes | PARTIAL (raw "decrypt message failed") | §4.4 |
| 21 | `ServerConnectionError` special-case (relay down) | yes | OPEN (raw websocket error) | §4.4 |
| 22 | Directory receive: set dir mtimes, chmod files from zip external_attr | yes | PARTIAL (file mode set; dirs always 0777-ish, no chmod of existing) | §5.3 |
| 23 | Send progress / "Sending N bytes file named X" / "Building zipfile.." UX | yes | PARTIAL (minimal output) | §6.1 (cosmetic) |
| 24 | Aliases of version output (`magic-wormhole X` vs cobra default) | — | cosmetic | §6.1 |
| 25 | Interop test harness (Go⇄Python in CI) | n/a | OPEN | §8 |
| 26 | Port python `test_cli.py` scenario suite | — | OPEN | §8 |
| 27 | README/feature matrix, CHANGELOG, compatibility statement | n/a | OPEN | §9 |
| 28 | Zero-length file send (skip transit) | yes | DONE (both sides tolerate) | — |
| 29 | Empty file / sha256 ack / 16 KiB records / relay fallback direct→relay | yes | DONE | — |
| 30 | Zip-slip protection on directory receive | Go-only hardening (Python relies on extract guard; Go has both) | DONE (Go stricter) | keep |
| 31 | Path traversal in offered filename | both handle | DONE | — |
| 32 | `zeromode`, `--accept-file`, `--only-text`, `--allocate`, `--qr`, `--ignore-unsendable-files` | yes | DONE | — |
| 33 | MOTD + `current_cli_version` welcome handling, `OnConnect` hook | yes | DONE | — |
| 34 | `--verify` (sender- and receiver-side), verifier mismatch aborts with TransferError | yes | DONE | §4.4 (message text only) |
| 35 | Wrong nameplate / `nameplateFromCode` validation before connect | python errors similarly | DONE | — |
| 36 | ssh invite/accept interop | yes | DONE | §4.4 (verify error text matches) |
| 37 | `apptx` — empty appid uses default; `--appid` flag | yes | DONE | — |
| 38 | Dilation | yes (opt-in) | WONTFIX (this plan) | — |
| 39 | Go-only extras: `shell-completion`, ssh parity already, QR default-on | Go-only | keep | note in docs |

---

## 3. Phase 1 — quick CLI wins (each: implement + unit test)

### 3.1 Aliases
Add cobra aliases: `send` → `["tx"]`; `receive` → `["recv", "rx", "recieve"]` (keep Go's existing `recv`; include the Python typo alias for parity). Add a test invoking both aliases.

### 3.2 `receive --code-length` (`-c`)
- Add `codeLength` flag to `recvCommand` (Python uses `-c`).
- Behavior (copy Python): if `--code-length` given without `--allocate` → `UsageError`-style exit ("Must use --allocate with --code-length"); if `--allocate` given with a code arg → error ("Cannot specify a code when using --allocate").
- Default 2 (consistent with send).
- Plumb into `ReceiveAllocated` → `c.PassPhraseComponentLength` on the temporary client.
- Tests: flag conflict matrix (code + allocate, code-length without allocate, defaults).

### 3.3 Version-warning gating
Python only warns when *our* version is a release (no `+`) and differs from server's `current_cli_version`. `version.AgentVersion` (`v1.0.8`) is release-shaped; `+` would come from a `git describe`-style build stamp injected via ldflags, which this repo does not currently wire — add a helper `version.IsRelease()` (strings.Contains(ver, "+") == false) and gate the warning on it. Also suppress the warning when `CurrentCLIVersion == AgentVersion` (already) and add a unit test for the helper.

### 3.4 Interactive completion on receive prompt (optional, DECIDE)
Python: `input_with_completion("Enter receive wormhole code: ", w.input_code())` with tab-completion of word pairs and active nameplates. Go currently: plain `ReadString`. Options: (a) keep plain prompt (rely on `shell-completion` for argv completion), (b) use `peterh/liner` for inline completion, (c) use `charmbracelet/bubbles` textinput (heavier). Recommendation: (a) for now; note as follow-up. If adopted, reuse `wordlist.RawWords` + `activeNameplates()` from `cmd/completion.go`.

### 3.5 `--listen` flag pair
Python exposes `--listen/--no-listen` (default listen) per subcommand. Go has global `--no-listen`. Minimal change: add `--listen` bool (default true) alongside `--no-listen` and error on conflict; or formally document the difference. DECIDE: prefer adding `--listen` with `DefaultTrue` semantics, keeping `--no-listen` for back-compat, effective value = `noListen || !listen`.

---

## 4. Phase 2 — receive-side semantics parity

### 4.1 Free disk space check (#10)
Add `internal/diskspace/diskspace_{unix,windows}.go` using `syscall.Statfs` / `golang.org/x/sys/windows.GetDiskFreeSpaceEx` (x/sys already an indirect dep; promote to direct). On receive of file or directory offers, before prompting: compute free space for `filepath.Dir(destName)`; if `< needed bytes` → print error, `msg.Reject()`, exit 1 (mirrors `TransferRejectedError`). Needed bytes: `offer.file.filesize` or `offer.directory.numbytes`. No check for text. Add a small interface so tests can stub it; wire `WORMHOLE_NO_FREE_SPACE_CHECK=1` escape hatch (or unexported var hook for tests). Tests: stub returning tiny value → transfer refused; large → accepted.

### 4.2 Permission prompt parity (#13)
Change the receive confirm to Python's semantics: prompt `ok? (Y/n): `; empty input → accept; input starting with `y`/`Y` (case-insensitive) → accept; anything else → reject. Keep `--accept-file` to skip the prompt. Applies to files and directories. Update `cmd/recv.go`, plus any tests relying on `y/N`. **Note in CHANGELOG: default answer to the overwrite/accept prompt changed from no to yes.**

### 4.3 `--output-file` semantics (#11, #12)
Rewrite `_decide_destname` as a pure function `resolveDestName(cwd, outputFile, offerName, isDir bool) (string, overwriteAllowed bool, err error)` in a new `cmd/destname.go` (or extend `cmd/paths.go`):
1. `base = safeBaseName(offerName)` (unchanged).
2. If `outputFile == ""`: `dest = cwd/base`; `overwriteAllowed = false`.
3. If `outputFile` set and exists and is a directory: `dest = outputFile/base`; `overwriteAllowed = false` (Python puts it inside; existing join still refuses to clobber).
4. If `outputFile` set and exists and is **not** a directory (existing file): `dest = outputFile`; `overwriteAllowed = true`. (Python allows clobbering the named file.)
5. Else `dest = cwd/outputFile` (if relative) or as given (if absolute); `overwriteAllowed = true` only if `outputFile` itself existed as a file (case 4) — otherwise false.
6. Non-existing `dest` → fine. Existing `dest` + `overwriteAllowed` → print `Overwriting '<file>'`; with `--accept-file` remove it before writing; interactive prompt per §4.2 with the remove happening on yes. Existing dir at `dest` → never overwritten ("Not deleting existing directory").
7. Existing `dest` + !overwriteAllowed → `msg.Reject()` + exit 1 ("Error refusing to overwrite existing …").
Apply identically to file and directory modes (directory fix joins basename — #12).
Tests: table-driven over (exists-file / exists-dir / missing) × (file mode / dir mode) × (accept flag), plus integration test with a real transfer for the overwrite path. Python test names to mirror: `test_file_overwrite_mock_accept`, `test_directory_overwrite`, `test_fail_file_noclobber`, `test_fail_directory_noclobber`, `test_existing_destdir`, `test_not_remove_existing_destdir`, `test_override`, `test_file_override`, `test_directory_override`.

### 4.4 Error-message parity (#19–22, 36)
Map internal error sentinels to friendly messages at the `cmd` layer (keep library errors as-is):
- `errDecryptFailed` → `ERROR: WrongPasswordError …`-style block (two-line, "ERROR:" prefix, plus a line "(relay URL was …)" not needed here), exit 1, scary mood (already sent).
- Websocket/connect failure → "ERROR: Could not connect to the relay at <url>" + wrapped cause.
- Python `TransferError` text parity for: sender rejected verify, receiver rejected (file_ack != ok → "ambiguous response from remote…"), duplicate offer/answer.
- Receiver-side verify failure already sends `{"error": …}`; match the exact strings used by Python where they're part of the wire protocol (`sender rejected verification check, abandoned transfer`) — keep as-is; only CLI rendering changes.
Tests: CLI-level tests spawning receive against a sender with wrong code; assert exit code 1 and stderr contains "WrongPasswordError"-ish marker (choose stable marker `WrongPasswordError` for grep-ability).

### 4.5 "code consumed" note (#19)
Python: when the mailbox closes (peer claimed nameplate / we closed), prints "Note: code has been consumed and can no longer be used." to stdout. Go: needs the rendezvous client to surface mailbox-close distinctly from socket errors. Check `rendezvous/client.go` for `close`/`closed` handling; add a callback (e.g. `OnStatus func(rendezvous.Status)` with `StatusConsumed`/`StatusClosed`) keeping the existing unexported behavior by default. Wire CLI to print the note once per process. If the plumbing grows beyond ~100 lines, defer with a note (mark OPEN) rather than hack it. Also useful groundwork for `--dump-timing`.

---

## 5. Phase 3 — directory transfer parity

### 5.1 Empty directory send (#14)
`SendDirectory` currently errors with zero entries. Change to allow zero entries: create an empty temp zip (valid central directory, 0 records), offer with `numfiles: 0, numbytes: 0, zipsize: <size of empty zip>`, stream it. Receiver handles it fine (zip.NewReader on empty zip works). Tests: send/recv an empty directory end-to-end via in-process rendezvous server; `numfiles: 0` offer accepted; Python interop check that a Python receiver can receive it (add to §8 harness).

### 5.2 Symlink handling (#15, #16)
- Replace `filepath.Walk` with `filepath.WalkDir` + manual follow: when an entry's `Type().IsRegular()==false` and it's a symlink, `os.Stat` (following) the path; if stat fails (broken symlink) → error unless `--ignore-unsendable-files`, then skip with a stderr note. If stat succeeds and target is a regular file → include with arcname = the symlink's relpath (Python's `walk(..., followlinks=True)` yields the symlink path itself, and ZipStream stores the target's content under the link's arcname).
- Symlinked directories: Python yields them as directories and recurses (followlinks=True). Implement a small recursive walker with cycle detection (visited dev+inode set) to avoid infinite recursion via symlink cycles. Arcnames remain relpath-style with forward slashes (already handled by `filepath.ToSlash`).
- Decision on storing *symlinks* as links: Python does **not** store unix symlinks; it follows them. Match.
- Tests: dir containing (a) symlink→file, (b) symlink→dir, (c) broken symlink (expect error; and success with flag), (d) symlink cycle a↔b (must terminate), (e) verify archived content matches target content.

### 5.3 Metadata fidelity (#17, #22)
- Send side: set `zip.FileHeader.Modified` from `info.ModTime()` (nearest even-second? Go supports seconds; DOS-time granularity is fine — Python also stores DOS timestamps for zip).
- Directory receive: after extraction set file mtimes from zip header (`zf.FileInfo().Modified`); for directories created via `MkdirAll`, optionally chmod to 0700/0755 per zip entries if a dir entry exists; skip otherwise.
- File mode restore already happens (`zf.Mode()`); keep.
- Tests: archive entries carry mtimes; after recv, extracted files have matching mtime (second granularity).

### 5.4 Block devices (#18) — DECIDE
Python sends `S_ISBLK` from send. Go can read block devices on Linux (`os.Open` works, size via Seek) but portability to Windows/macOS is nil. Proposal: implement on Linux only (`//go:build linux` + fallback returning a clear error elsewhere), or mark WONTFIX (documented). Recommendation: implement opportunistically (it's ~20 lines) but do **not** test in CI; document.

---

## 6. Phase 4 — UX / output parity (low risk, user-visible)

### 6.1 Informational output (#23, #24)
- send: print `Sending <naturalsize(size)> file named '<name>'` / `Sending directory (<size> compressed) named '<dir>'` / `Sending text message (<n> bytes)` / `Building zipfile..` before starting — mirror Python stderr messages.
- receive: print `Receiving (<desc>)..` where desc is `direct TCP` / `relay` — Go currently lacks a "Receiving (…)…" line; add from transport connect method; `description` string exists conceptually — expose it.
- `--version`: print `magic-wormhole-william <version>`? Keep cobra default but change root `Version` template already overridden to `wormhole-william <v>` — fine; document. Not required to match python's literal string.
- Keep human byte formatting; note kB/MB (1000-based) vs Python humanize KiB/MiB (1024-based) discrepancy and switch Go to 1024 + "KiB…"? DECIDE — cosmetic; switching breaks nobody; recommend matching python's 1024 base.

### 6.2 `--dump-timing` (#7) — DECIDE
Implement a small `internal/timing` package: `type Timing` with `Add(name string, which string)` and `Write(path, stderr)`, JSON object of `{name: seconds}`. Instrument: start, import done, pake done, version done, transit connected, offer sent/received, answer, file done. If this balloons, drop to WONTFIX with docs (it's a debug flag). Recommendation: implement minimal version, exact key parity **not** required; document deviations.

### 6.3 `--debug-state` (#8) — DECIDE
Python flag traces state-machine transitions. Go has no state machines to trace. Options: (a) WONTFIX + doc, (b) accept the flag and wire it to `log`-level debug output for rendezvous messages (redact bodies — bodies are encrypted anyway; OK to log hex length), (c) accept-and-ignore silently (bad UX). Recommendation: (b) minimal — with strict machine list validation like Python's (`invalid machine` → usage error) but only `B,N,M,S,O,K,SK,R,RC,L,C,T` accepted; unrecognized → error. Log lines like `R.rx(message .0a31f…)`, `K.spake2.pake`. Do **not** claim full parity of trace output.

---

## 7. Phase 5 — Tor support (#9)

Python: `--tor` (connect via SOCKS/control port), `--launch-tor` (launch own tor via txtorcon), `--tor-control-port ENDPOINT` (script an existing tor). All three subcommands (send/receive/ssh).

Go design options:
- **Option A (recommended, incremental):** `--tor` = route all outbound connections through a SOCKS5 proxy at `127.0.0.1:9050` (configurable via `--tor-socks` or env `WORMHOLE_TOR_SOCKS`), using `golang.org/x/net/proxy`. Applies to: rendezvous websocket — the client is built on `nhooyr.io/websocket`, whose `DialOptions` accepts an `*http.Client`; use a custom `http.Transport` with a SOCKS5 `DialContext` (`golang.org/x/net/proxy`) — feasible without swapping libraries; transit TCP dials (easy, `proxy.SOCKS5`), and the local listener (disable local listen when `--tor`; matches python `no_listen` semantics for tor). `--tor-control-port` without launch = "verify tor is up" via control protocol — implement minimal control handshake or simply accept-and-assume; `--launch-tor` deferred (requires spawning tor binary; Go has no txtorcon equivalent).
- **Option B:** depend on `github.com/cretz/bine` + require tor binary; heavier; supports launch-tor properly.
- Recommendation: A now, B later if users ask. `--launch-tor`: print explanatory error ("not supported yet; start tor yourself, or use --tor-control-port with a running tor") instead of failing silently.

Open questions for the user (record decision in README + this file):
1. Is `--tor` against system tor (9050) sufficient, or must we launch tor?
2. Transit relay over tor: with `--tor`, python still offers the transit relay hint but refuses local listening; direct-tcp hints from the Go side must be **suppressed** (they'd leak the real IP). Already handled by `--no-listen` logic — reuse: when `--tor`, force no-listen equivalent.
3. Dependency policy: OK to add `golang.org/x/net/proxy`? `nhooyr.io/websocket` can be proxied via a custom `http.Client`/`Transport` (preferred, no library swap); a switch to `gorilla/websocket` stays on the table if that proves insufficient.

Milestone shape: M1 `--tor` for send/receive text+file+directory through system tor (manual test against real tor; not in CI), M2 `--launch-tor`, M3 `tor-control-port` verification. CI can't run tor (or can, via service container — revisit).

---

## 8. Phase 6 — testing hardening

### 8.1 Unit/table tests
- §3 flags matrix; §4 destname table; §4.2 prompt parsing (factor prompt into `confirm(rd io.Reader, acceptOnEmpty bool) bool` for testability); §4.1 diskspace stub; §5.1–5.3 zip behavior; §4.4 error mapping (grep-able markers).

### 8.2 Port of python `test_cli.py` scenarios to Go integration tests
Use the in-process `rendezvousservertest` + local transit relay (already exists) to cover: text send/recv (exists), file noclobber refuse, dir noclobber refuse, output-file override (file & dir), only-text refuse, allocate flow, allocate+code conflict, empty file, empty dir, `--verify` abort both sides, wrong-password exit path, zeromode round trip, directory with symlinks (§5.2). Gate any test that needs the real relay behind `WORMHOLE_LIVE_TEST=1` (default skip).

### 8.3 Interop harness (Go⇄Python) (#25)
New `scripts/interop_test.sh` (or Go test `interop_test.go` with `//go:build interop` and `WORMHOLE_PYTHON=…/wormhole` env):
- Cases (both directions: go→py, py→go): text, file (small/large/empty), directory (nested), zeromode, wrong-code failure, `--verify` happy path.
- Setup: use `/tmp/wormhole-venv/bin/wormhole` if present, else `python -m wormhole`. Assert byte counts and sha256.
- Add CI workflow `.github/workflows/interop.yml` installing magic-wormhole 0.24.0 from PyPI in a job (matrix: go send/py recv, py send/go recv).
- Document expected manual run locally.

### 8.4 Fuzz/property tests (stretch)
- Fuzz `safeBaseName`, `zipPathContained`, `resolveDestName` (Go native fuzzing; run 30s in CI).

---

## 9. Phase 7 — docs & release

- README: add **Feature matrix** table (Go vs Python, with links to sections of this file), explicit **Non-goals** (dilation), **Behavior differences** list (QR rendering, byte units if changed, prompt default change), **Compatibility** statement (protocol-compatible with magic-wormhole ≥0.12 cli; tested against 0.24.0), updated CLI usage output, interop instructions.
- CHANGELOG.md (new): v1.1.0 entries: aliases, receive --code-length, --listen, prompt default, output-file overwrite semantics, free-space check, empty-dir send, symlink follow, --tor (when done).
- `parity_plan.md`: keep updated (check off items); this file is the source of truth until parity declared; final state → fold into docs/ and archive plan.
- Release checklist additions: run interop suite before tagging; `tag_version.go` flow unchanged; mention parity status in release notes.

---

## 10. Sequencing & milestones

| Milestone | Contents | Exit criteria |
|---|---|---|
| **M0** (done) | analysis, this plan, baseline tests | `go test ./...` green |
| **M1** | §3.1, §3.2, §3.3, §3.5 + §4.2 prompt parity + §4.4 error messages | unit tests green; manual smoke send/recv |
| **M2** | §4.1 diskspace, §4.3 destname rewrite, §4.5 consumed-note (or deferred) | receive-semantics tests green |
| **M3** | §5.1–§5.3 directory parity | zip tests + interop dir cases green |
| **M4** | §8.1–§8.3 test harness + CI interop job | interop job green on PR |
| **M5** | §6 UX polish (byte units decision, sending lines), §6.2 timing, §6.3 debug-state | documented output diff |
| **M6** | §7 Tor (Option A), opt-in manual test | `--tor` works against local tor |
| **M7** | §9 docs, CHANGELOG, v1.1.0 | docs merged, release tagged |

Estimated effort: M1 0.5–1d, M2 1–2d, M3 1–2d, M4 1–2d, M5 0.5–1d, M6 2–4d, M7 0.5d. Riskiest: M6 (Tor), §4.5 (rendezvous plumbing).

## 11. Decision log (fill in as decided)

| # | Decision | Date | Outcome |
|---|----------|------|---------|
| D1 | Default interactive accept prompt `(y/N)` → `(Y/n)` | | pending (§4.2) |
| D2 | Byte units: keep 1000-based (kB) or switch to 1024 (KiB/MiB)? | | pending (§6.1) |
| D3 | Tor: system-socks only vs launch tor (Option A vs B) | | pending (§7) |
| D4 | `--debug-state`: minimal log tracing vs WONTFIX | | pending (§6.3) |
| D5 | Block devices: implement Linux-only vs WONTFIX | | pending (§5.4) |
| D6 | Add `--listen` alongside `--no-listen` vs doc-only | | pending (§3.5) |
| D7 | Interactive tab-completion via liner vs rely on shell completion | | pending (§3.4) |

## 12. Explicit non-goals

- Dilation (anywhere: `wormhole/_dilation`, noise protocol, subchannels). The Python `"can-dilate"` version dict entries remain absent on the Go side, which is the correct signal.
- Rendezvous **server** parity (Go's `rendezvousservertest` is a test stub; Python ships a real server in a separate package — not in scope).
- Mobile/GUI clients; third-party app integration.
- Byte-for-byte CLI output parity with Python (messages may differ in wording).
- Wire protocol changes of any kind.

## 13. References

- Python source of truth for this plan: `/tmp/wormhole-venv/lib/python3.14/site-packages/wormhole/` (cli/cli.py, cli/cmd_send.py, cli/cmd_receive.py, cli/cmd_ssh.py, cli/welcome.py, transit.py, xfer_util.py, errors.py, _status.py, _nameplate.py)
- Python test suite being mirrored: same tree under `test/test_cli.py` (80+ CLI scenario tests), `test/test_wormhole.py`
- Go implementation anchors: `cmd/send.go`, `cmd/recv.go`, `cmd/ssh.go`, `cmd/cmd.go`, `cmd/paths.go`, `cmd/completion.go`, `wormhole/wormhole.go`, `wormhole/send.go`, `wormhole/recv.go`, `wormhole/file_transport.go`, `rendezvous/client.go`, `internal/gospake2/`
- Verified working interop today: text/file/directory go↔py (manual), zeromode, verify, ssh accept/invite

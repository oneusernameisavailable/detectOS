# Plan — Fix RedTeam round-3 findings in fx-detect-os.sh

Status: EXECUTED
Date: 2026-09-15. No git (approved: "no git for now"). Plan location approved.
Target version: 1.3.0. Scope: Tasks 1 and 7 INCLUDED (user-approved).

## Decisions (user-approved)
- Version bump 1.3.0 (additive fixes, non-breaking).
- `_OS_ROOT` lsb-cmd skip ADOPTED: when `_OS_ROOT` is set, `lsb_release` the
  command is never consulted (host binary cannot leak rootfs values, demoed as
  `ID=cachyos` from an empty fake root). File probes (`os-release`,
  `lsb-release`) still detect the OS; `uname` remains the last resort.
- Tasks 1 (SSOT field names) and 7 (`-f` regular-file guards) in scope.
- C7 (redaction wordlist gaps / env floor) EXPLICITLY DEFERRED, not in scope.

## Findings addressed (round-3 red team)
- C1 os-release ID-less / 0-byte file reported `ID=linux` with rc 0 and
  false confidence (spec-default claimed paternity over a file that supplied no
  identity). -> Task 3: defer ID-less os-release to the rest of the ladder;
  `ID=linux` only ever comes from `uname` (last resort), so
  `OS_SOURCE=uname` + `OS_FALLBACK_USED=1` are honest.
- C2 `_os_readonly_collision` only understands `declare -r NAME=` lines.
  Under bash 4.0-4.4 / `set -o posix`, `readonly -p` emits `readonly NAME=`
  lines, so a caller-owned readonly `OS_ID` is missed -> the later write aborts
  the caller's shell (exit 127). Also the unguarded `_DETECT_OS_SOURCED=1`
  write at source time aborts if a caller pre-declares it readonly.
  -> Task 2: parse both output formats; guard the `_DETECT_OS_SOURCED` write.
- C3 `_OS_ROOT` only prefixes file reads; `lsb_release`/`uname` still hit the
  host. -> Task 6: skip `lsb_release` command when `_OS_ROOT` is set; make
  `_os_file_probe` slash-safe.
- C4 only `ID`/`VERSION_ID` were sanitized; PRETTY_NAME/NAME/VERSION/CODENAME/
  ID_LIKE and lsb/legacy/lsb-cmd display fields passed raw (ANSI/terminal
  injection via `echo "$OS_DISTRO"`). -> Task 4: `_os_sanitize_display`
  (strip ESC + C0 controls) applied to every display-field assignment site.
- C5 amzn/ol never populate `OS_ID_LIKE` (legacy path only). -> Task 5:
  presets `rhel fedora` (amzn) / `rhel centos fedora` (ol).
- C6 PATH-pin empty slots freeze forever (readonly, re-source blocked).
  -> Task 8: emit a source-time warning when `uname` is missing; document the
  empty-slot degrade. Full re-resolution is out of scope (readonly slots are
  deliberate).
- C7 redaction gaps -> DEFERRED (wordlist extension, <4 floor, exported-only).
- C8 four hand-synced OS_* name lists drift. -> Task 1: single `_OS_FIELDS`
  array + `_OS_RESET_FIELDS`; collision check and STATE DUMP iterate it.
- Extra: FIFO/device os-release blocks forever on `read` (`-r` true for FIFOs);
  0-byte `-s`; BOM `\xef\xbb\xbf` on first line; `_OS_ROOT="/"` concat.

## Task list (each with VERIFY GATE: bats green + bash -n + shellcheck clean)

### T1 SSOT detection-field names
- Add `declare -ra _OS_FIELDS=(...)` (15 names) and `_OS_RESET_FIELDS`
  (identity subset) after `_OS_VERSION`, guarded by `declare -p`.
- Rewrite `_os_readonly_collision` to iterate `_OS_FIELDS` membership; rewrite
  `_os_dump_state` to iterate `_OS_FIELDS`; reset loop in `detect_os` iterates
  `_OS_RESET_FIELDS` (special-casing OS_DETECTED/FALLBACK/CONTAINER).

### T2 Readonly-collision parse fix + guarded `_DETECT_OS_SOURCED`
- Accept `readonly NAME` / `readonly NAME=value` lines in the collision scan
  (posix/bash 4.0-4.4 format) in addition to `declare -r` lines.
- Guard `_DETECT_OS_SOURCED=1`: only assign when `declare -p` succeeds-less.

### T3 ID-less os-release deferral (flagship)
- `_os_read_os_release`: skip empty files (`-s`); parse /etc then /usr/lib
  (takeover+reset unchanged); return 0 only when an actual ID was parsed;
  otherwise CLEAR partial identity fields and return 1 so the ladder continues.
- Strip BOM in os-release/lsb-release parse loops and `_os_first_line`.
- Change tests at lines 74, 102. New tests: 0-byte defers to uname; ID-less
  /etc + arch-release -> arch with OS_NAME cleared; BOM stripped.

### T4 Display-field sanitizer
- Add `_os_sanitize_display` (strip `\e` + `[[:cntrl:]]`).
- Apply to every assignment of OS_PRETTY_NAME/OS_NAME/OS_VERSION/
  OS_VERSION_CODENAME/OS_ID_LIKE (os-release, lsb file, lsb cmd, legacy,
  fedora-family, system-release, SuSE, catch-all).
- New tests: ESC in PRETTY_NAME/NAME/VERSION/CODENAME/ID_LIKE stripped;
  legacy release file ESC stripped; `os_distro` never contains ESC.

### T5 ID_LIKE presets for amzn/ol
- legacy branch: system-release -> Amazon sets `OS_ID_LIKE="rhel fedora"`;
  oracle-release/system-release -> Oracle sets `OS_ID_LIKE="rhel centos fedora"`.
- Assertions added to tests at lines 168 and 184.

### T6 `_OS_ROOT` isolation + slash-safe join (+ lsb_cmd skip)
- `_os_file_probe`: join root and path with a collapsible single `/`; handle
  `_OS_ROOT="/"`, trailing slash, relative root.
- `_os_run_lsb_cmd`: return 1 immediately when `_OS_ROOT` is set.
- Container probes switch `-e` -> `-f`.
- Tests 405/413/422: `unset _OS_ROOT` before exercising the lsb_cmd path.
- New test: empty fake root + host `lsb_release` returning a distro still
  yields ID=linux from uname (no host contamination).

### T7 `-f` regular-file guards
- Read-probe sites get `-f` (plus readability) before reading: os-release,
  lsb-release, all legacy markers, fedora-family files, and container markers.
- New tests: FIFO at os-release and lsb-release never block (timeout-wrapped),
  falls through to uname; os-release symlink to directory skipped.

### T8 Empty-tool-slot warning + PATH-pin docs
- After the tool loop: if `_OS_UNAME` empty, source-time `_os_warn`.
- README PATH PINNING + cheatsheet notes updated; test documented.

### T9 Docs + version bump 1.3.0
- `readonly _OS_VERSION="1.3.0"`.
- README: ladder (ID-less => defer; ID=linux only from uname), OS_ID table row,
  `_OS_ROOT` hook row (lsb cmd skipped), sanitization note, test count.
- cheatsheet: ladder + globals footnotes.

### T10 Full verification battery
- `bats test/detect_os.bats` all green (README count updated).
- `bash -n fx-detect-os.sh`.
- `shellcheck -S style -x fx-detect-os.sh test/detect_os.bats`.
- Live smoke on host; record actual output.

## Verification (expected, updated after run)
```
bats test/detect_os.bats        -> N/N ok
bash -n fx-detect-os.sh         -> OK
shellcheck -S style -x ...      -> clean
live: detected=1 id=cachyos ... ver=1.3.0
```

## Notes (recorded during execution)
- bats `setup()` keeps the existing lsb_release/timeout shims; the 3 lsb-cmd
  tests now `unset _OS_ROOT` first.
- `readonly -p NAME` does NOT filter by name in bash 5.3 (verified empty), so
  the collision scan still iterates the full `readonly -p` output and matches
  against `_OS_FIELDS`.
- `_OS_RESET_FIELDS` covers the 9 identity fields + OS_DISTRO + OS_SOURCE;
  OS_DETECTED/OS_FALLBACK_USED/OS_CONTAINER set explicitly after the reset.
## Verification record (2026-09-16)
- `bats test/detect_os.bats` → **58/58 pass** (46 pre-existing + 12 new: BOM,
  0-byte deferral, 0-byte+arch, ID-less clearing, POSIX readonly, readonly-empty
  _DETECT_OS_SOURCED, C3 host-lsb isolation, 2x FIFO hang-guards, symlink-to-dir,
  ESC display, ESC legacy).
- `bash -n fx-detect-os.sh` → SYNTAX OK. (bats files are not plain bash; linted
  via shellcheck instead.)
- `shellcheck -S style -x` → 0 findings on the .sh; bats file cleared (the new
  child-payload `$vars` are guarded with inline `# shellcheck disable=SC2016`.
- Live smoke: `set -euo pipefail` + source + `detect_os` → `ver=1.3.0
  detected=1 id=cachyos src=/etc/os-release fb=0 distro=CachyOS arch=x86_64`;
  repeated `detect_os` in the same shell re-detects cleanly (reset verified).
- Deviation found & fixed during execution: the SSOT lists were first declared
  `declare -ra _OS_FIELDS=...`; when the library is sourced inside a function
  (as bats' `lib()` does), `declare` becomes function-local and the arrays were
  destroyed on return — the per-run reset silently no-oped, so a second
  `detect_os` in one shell re-flagged the previous `OS_ID` as an os-release
  "hit". Fixed by declaring them `readonly -a` (verified: `readonly` class vars
  keep global scope under in-function sourcing, `declare` does not) and pinned
  with a 54-line bug test (the "debian_version codename/sid" two-cycle test).

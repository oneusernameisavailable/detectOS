# Design — OSDetect hardening v1.7.0 (red-team round-6 findings)

Status: APPROVED
Date: 2026-09-17. No git (approved: "no git for now"). Baseline:
fx-detect-os.sh 1.6.0 (104 bats tests passing). Full adversarial review
performed (RedTeam ParallelAnalysis, 24 agents); this spec fixes the
severity-ranked findings under scope B + pulled-in deferred items (decision:
"keep, all").

## Problem summary (severity-ranked findings addressed)

1. CRITICAL — no trust annotation on OS_* globals; rc 0 is identical for an
   os-release hit vs a `uname` last resort, so consumers cannot tell how
   authoritative an ID is.
2. HIGH — release-file reads have no size/line-length bound; a crafted giant
   os-release can OOM the caller (`read -r` of a multi-GB single line).
3. HIGH — catch-all `/etc/*-release` glob accepts any remaining file as
   identity; its results are indistinguishable in confidence from a named
   legacy source.
4. MEDIUM — a caller-supplied `_OS_LOG_FILE` with group/world-readable mode is
   accepted silently.
5. MEDIUM — missing `env` at source time silently degrades redaction pass 2.
6. MEDIUM — double-source guard can be bypassed by pre-defining the helper
   marker function + `_DETECT_OS_SOURCED`.
7. LOW — lsb_release step is bounded per-call at 5s across four invocations,
   so worst case is ~20s, not 5s.
8. Test gaps: `_os_unquote`, `_os_field_listed`, `_os_is_readonly`,
   `OS_CONTAINER=containers`, `sles` branch, `_release` suffix catch-all,
   `SCRIPT_DEBUG=1`, `${TMPDIR:-/tmp}` error-log fallback, `_os_redact` with
   `env` absent, `OS_NAME+OS_VERSION_ID` distro composition, fuzz coverage.

## Decisions (user-approved)

- **A1 trust taxonomy = Option 2**: new `OS_TRUST_LEVEL` global, four values
  `high|medium|low|none` (os-release / named legacy+lsb / catch-all+uname /
  unresolved). Additive, non-breaking.
- **B4 guard = Option 2**: EOF marker function `_os_loaded`, required by the
  source guard alongside the existing flag + helper. Closes the plausible
  accident; a deliberate forger who pre-owns the shell remains out of scope.
- **B3 kept**: `stat` is pinned as a 10th tool slot solely to *warn* on a
  world-readable caller-supplied `_OS_LOG_FILE`; no chmod behavior change.
- **E1 + D2 pulled in**: lsb_release gets a single shared 5s deadline (no new
  tool); property/fuzz tests are added.

## Change (fx-detect-os.sh only)

### A1 — OS_TRUST_LEVEL

1. `_OS_FIELDS` += `OS_TRUST_LEVEL` (appended after `OS_FALLBACK_USED`). The
   readonly-collision scan and STATE DUMP iterate `_OS_FIELDS`, gaining it
   for free.
2. `_OS_RESET_FIELDS` += `OS_TRUST_LEVEL` (cleared every `detect_os`).
3. `_os_failure_record` finals loop (`for fname in OS_ID ... OS_SOURCE`)
   += `OS_TRUST_LEVEL` (emits JSON key `TRUST_LEVEL`).
4. Set in each winning ladder step:
   - `_os_read_os_release` (ID parsed): `OS_TRUST_LEVEL=high`.
   - `_os_parse_lsb_release` (ID parsed): `OS_TRUST_LEVEL=medium`.
   - `_os_run_lsb_cmd` (ID parsed): `OS_TRUST_LEVEL=medium`.
   - `_os_parse_legacy`: every named branch (`debian_version`, `arch-release`,
     `gentoo-release`, `alpine-release`, `oracle-release`, fedora-family,
     `system-release`, `SuSE-release`) → `medium`; the catch-all branch →
     `low`.
   - `_os_uname_fallback` (ID emitted): `OS_TRUST_LEVEL=low`.
   - On unresolved: `OS_TRUST_LEVEL=none` (in the rc-1 branch of `detect_os`).
5. New accessor `os_trust_level()` echoing `${OS_TRUST_LEVEL:-}`; update the
   header "Field accessor functions" block and the GLOBALS WRITTEN doc.

### B1 — file-size guard

1. Tool slot `_OS_WC:wc` added to the pin loop. Silent degrade: when `wc` is
   absent the library uses the existing `-f -r -s` checks only (no behavior
   change, no new warning — matches the mktemp/chmod degrade precedent).
2. New helper `_os_file_ok <path> [max_bytes]`: rc 0 iff the path is a
   regular readable non-empty file **and** its byte count from `wc -c` is
   `<= max_bytes` (default `262144`). With `wc` unavailable, returns rc 0 on
   the `-f -r -s` checks alone.
3. Call sites replaced (os-release /etc + /usr/lib reads, lsb-release read,
   containerenv read, every legacy named probe, and the catch-all `-f`
   check). Oversize semantics = *defer*, matching today's ID-less behavior:
   os-release → next ladder step; containerenv → no-container; legacy file →
   skipped. The containerenv read uses a smaller cap (4096).

### B2 — env absence warning

Mirror the `uname` source-time warning block: when `_OS_ENV` is empty, print
once to stderr that redaction value-pass 2 is disabled. (README documents the
LD_PRELOAD/`env` trust boundary.)

### B3 — world-readable caller log warning

1. Tool slot `_OS_STAT:stat` added to the pin loop (silent degrade).
2. In `_os_ensure_log_file` caller-supplied branch, after `: >>`, when
   `_OS_STAT` is available: `mode="$(stat -c %a "$f")"; case "$mode" in
   *[167]*|*[2356]*) warn ;;` — warn when group or other bits are set. Never
   chmod (policy unchanged).

### B4 — EOF marker guard

1. Define `_os_loaded() { :; }` as the last line of the library.
2. Source guard condition becomes:
   `[ -n "${_DETECT_OS_SOURCED:-}" ] && declare -F _os_debug_active >/dev/null 2>&1 && declare -F _os_loaded >/dev/null 2>&1`.
   Update the guard comment: an accidental pre-definition of one helper name
   can no longer fake a load; a forger who pre-owns the shell remains out of
   scope (documented in README).

### C2 — catch-all trust + ordering regression

Coverage semantics unchanged; the catch-all branch sets `OS_TRUST_LEVEL=low`
(A1). Two new tests pin (a) catch-all → `low` while named legacy → `medium`,
(b) competing `*-release` files cannot force a wrong family ID for the named
legacy distros.

### E1 — lsb_release shared deadline

Replace the two `_os_lsb` definitions with a shared budget:

```
local -i deadline
deadline=$(( SECONDS + 5 ))
_os_lsb() {
    local -i rem=$(( deadline - SECONDS ))
    if [ "$rem" -le 0 ]; then return 1; fi
    _os_runx "$_OS_TIMEOUT" "$rem" "$@"
}
```

Used only when `_OS_TIMEOUT` is set; otherwise `_os_lsb()` remains a plain
`_os_runx` wrapper. Worst case ≈ 5s total across the four probes (was ~20s).
`unset -f _os_lsb` already happens in both return paths.

## Tests (test/detect_os.bats, +~18 → ~122)

1. trust: os-release → `high`; legacy lsb file → `medium`; lsb command →
   `medium` (stub path); debian_version → `medium`; catch-all `nobara-release`
   → `low`; `uname` fallback → `low`; unresolved → `none`; reset between runs
   clears it; failure-log `finals` carries `"TRUST_LEVEL"`.
2. B1: giant single-line os-release (>cap) defers to next step / unresolved;
   oversize containerenv ignored; oversize lsb defers.
3. B2: `_OS_ENV=""` pre-declared at source → warning on stderr.
4. B3: caller log chmod 0644 → warning fires (skip when `stat` absent).
5. B4: forged `_DETECT_OS_SOURCED` + pre-defined `_os_debug_active` alone does
   NOT no-op on first source; a genuine re-source still no-ops.
6. D1 gaps: `_os_unquote` (paired/embedded quotes, `\'`, empty);
   `_os_field_listed` (in vocab, near-miss, scratch); `_os_is_readonly`
   (`declare -ra`, `-A -r` forms); containerenv `engine=` absent →
   `OS_CONTAINER=containers`; `sles` branch (SuSE-release no Tumbleweed/Leap/
   openSUSE); `_release` suffix catch-all; `SCRIPT_DEBUG=1` alone; error-log
   `${TMPDIR:-/tmp}` fallback with XDG and HOME unset; `_os_redact` with env
   absent (pre-declared `readonly _OS_ENV=` before source, test:76 pattern);
   `OS_DISTRO` composed from `OS_NAME+OS_VERSION_ID`.
7. D2 fuzz: a bounded loop (~200 cases, `$RANDOM`-seeded) asserting sanitizer
   invariants (allowlist charset, non-empty→non-empty, no newlines), rc ∈
   {0,1}, `OS_TRUST_LEVEL` ∈ valid set, and that random-size release files
   never hang or crash chip detection.

## Docs + version

- `readonly _OS_VERSION="1.7.0"`.
- README: field table + `OS_TRUST_LEVEL` semantics + trust ladder table; tool
  list += `wc`, `stat`; size-cap note; env-warning note; `readonly
  OS_ID=$(detect_os)` warning (C1); "OS_ID is shell-safe, not path-safe" (C3);
  LD_PRELOAD/`env` trust boundary (C4); `_os_loaded` guard note; test count →
  `# 129 tests`.
- `docs/cheatsheet.md`: trust ladder row + tool list sync.
- Source doc comments updated at each touched block.

## Acceptance criteria

- `bash -n fx-detect-os.sh` SYNTAX OK.
- `shellcheck -S style -x` clean on both files (no new warnings beyond the
  known SC2016 at test line 1129).
- Full `bats test/detect_os.bats` PASS (~122), 104 existing verbatim.
- Live spot-check: `_OS_ROOT` fixture with os-release → `os_trust_level` =
  `high`; naked (no release files, uname pinned) → `low`; empty root +
  `/nonexistent` PATH → `none` + rc 1.

## Out of scope

- Any chmod of caller-supplied `_OS_LOG_FILE` / `_OS_ERROR_LOG`.
- Wider changes to catch-all acceptance (deny-list, gating) beyond trust=low.
- `_os_failure_record` SSOT refactor (finals list stays hand-synced; noted).
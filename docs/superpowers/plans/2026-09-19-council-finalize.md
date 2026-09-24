# fx-detect-os.sh — Council-Finalize Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development, then superpowers:executing-plans to implement task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Date:** 2026-09-19
**Origin:** Council DEBATE (4 custom agents, 3 rounds) over the open RedTeam/eval tails left by the unreleased Sep-18 hardening round.
**Goal:** Close the five consensus-agreed findings, resync docs to the 159-test reality, bump `_OS_VERSION` 1.7.0 -> 1.8.0, and leave the project in a verified, releasable state.

**Architecture:** Source-only bash library, bash >= 4.0. All behavioral changes are TDD (failing bats test first). Two of the five findings are real bugs caught because the council demanded tests; one is a contract-lie deletion; two are untested-but-correct paths that get pinned.

## Global Constraints
- Do NOT add `set -e`/`set -u`/`pipefail` or traps (sourced-library contract).
- Do NOT use `eval`, process substitution, or `ls` parsing (`-d ''` on `read` is fine; do not switch to a pipeline).
- All new stderr diagnostics must use `_os_warn` (prints `osdetect: ...`).
- Preserve: `bash -n` clean, `shellcheck -S style -x` rc 0, all prior tests pass.
- Test file: `test/detect_os.bats` (147 today, finals 159). Source: `fx-detect-os.sh`. Docs: `README.md`, `docs/cheatsheet.md`.
- Baseline commands (before this plan's changes):
  - `bats test/detect_os.bats` -> 147/147 pass
  - `shellcheck -S style -x fx-detect-os.sh test/detect_os.bats` -> rc 0
  - `bash -n fx-detect-os.sh` -> rc 0
- Repository is NOT a git repo: no commit steps; use the verification checkpoints below.

## Consensus Triage (from the debate — authoritative)
1. **Fixing required (TDD):**
   - **F#1/#4a (CODE BUG):** stat-mode check at `fx-detect-os.sh:402` uses `${emode: -2:1}` — bash-4.2+ negative-offset substring, breaches the documented bash >= 4.0 contract. The identical pattern was already fixed at `:300-305`; this site was missed.
   - **F#4b (CODE BUG):** `_os_file_ok` bounded-read fallback (`:983`) uses `read -r -n N`, which returns rc 0 on the FIRST newline — so the stat+wc-less path rejects every well-formed multi-line release file. Fix reads with `-d ''` (NUL delimiter) so a buffer fill means true oversize and EOF means fits. Add a code comment about multibyte char-vs-byte over-read (~4x cap, stat/wc-less path only; cap remains a DoS bound, not an attack).
   - **A2 (CONTRACT LIE):** `*-release-cpe` exclusion arm at `:1526` is unreachable dead code — the catch-all globs (`*-release`, `*_release`) can never produce a `<x>-release-cpe` basename. Keeping it invites a future "helpful" glob widening to `*-release*`. DELETE the arm + one-line comment (`# CPE metadata files are not glob-visible; the arm is intentionally absent`) + parametrized loop test over the REACHABLE exclusion arms.
   - **#3 (UNPINNED SECURITY FEATURE):** `_os_redact_shapes` (value-shape pass: Authorization/Bearer, AKIA/ASIA, JWT eyJ, PEM banner, JSON cred pair) has zero direct tests. Add 6 focused + 1 integration test.
   - **#5 (UNPINNED PATH):** rootless podman `/run/user/<uid>/.containerenv` detection sets `OS_CONTAINER=containers` (never fabricated `podman`). Plant and assert, one presence test.
   - **D3 (SILENT FAIL-OPEN):** `_OS_ENV` exec failure at `:580` (`envout="$("$_OS_ENV")" 2>/dev/null || envout=""`) silently disables name-based redaction while a caller believes secrets are scrubbed. Add one-shot `_os_warn` mirroring the :246 source-time warning. (Only if `_OS_ENV` is set; empty stays silent.)
2. **Documentation-only (8 items after the code lands):** rewrite `_OS_ENV` README row from phantom "name list" to tool-path semantics; test count 133->159 (README:373, cheatsheet:105) + sweep stale counts; "Two redaction passes" -> "three passes" + describe shape pass; container row gets the full `docker|podman|oci|containers|none` set + rootless `/run/user` marker; cap-qualifier sentence; step-ladder CPE-scope note; audit intact rows.
3. **Mandatory regardless:** version `_OS_VERSION` 1.7.0 -> 1.8.0 at `:163`; full gate; verification record; `progress.md` note.

---

### Task 1: Findings #1/#4 — two bash bugs (line 402 + bounded-read fallback)

**Files:** `fx-detect-os.sh:398-407`, `fx-detect-os.sh:978-987`; `test/detect_os.bats` (append).

 - [x] **Step 1: Write the failing tests** (append to `test/detect_os.bats`)

```bash
@test "bash4.0: error-log mode check never uses negative-offset substring (R18-402)" {
    grep -n '${emode: -' fx-detect-os.sh >/dev/null && return 1 || return 0
}

@test "cap-probe: read -d NUL keeps multi-line files below cap acceptable when stat+wc absent" {
    local f="$BATS_TEST_TMPDIR/multiline"
    printf 'ID=debian\nVERSION_ID="12"\nNAME="Debian"\n' > "$f"
    PATH=/nonexistent lib
    _OS_STAT= _OS_WC=
    run _os_file_ok "$f"
    [ "$status" -eq 0 ]
}

@test "cap-probe: oversized file still rejected when stat+wc absent" {
    local f="$BATS_TEST_TMPDIR/big"
    { printf '%s\n' 'ID=huge'; head -c 300000 /dev/zero | tr '\0' 'A'; } > "$f"
    PATH=/nonexistent lib
    _OS_STAT= _OS_WC=
    run _os_file_ok "$f" 262144
    [ "$status" -eq 1 ]
}
```

> The second/third tests need the lib to NOT resolve stat/wc. Because `fx-detect-os.sh` pins external tools at source time (PATH scan), run under `PATH=/nonexistent` so `_OS_STAT`/`_OS_WC` come up empty — OR unset the pinned vars after `lib` if they are exported (they are ordinary globals; unset is fine). Confirm which holds at implementation time.

 - [x] **Step 2: Run to verify they fail** (`bats -f "cap-probe" test/detect_os.bats`; the multiline test fails today — read rc 0 on newline).

 - [x] **Step 3: Implement fix 402** — mirror the `:300-305` pattern:

```bash
l2="${emode#"${emode%??}"}"
egroup="${l2%?}"
eother="${l2#?}"
case "${egroup}${eother}" in
```

 - [x] **Step 4: Implement bounded-read fix** — NUL delimiter so newline no longer ends the probe:

```bash
if IFS= read -r -d '' -n "$(( max + 1 ))" _os_cap_probe < "$f" 2>/dev/null; then
    return 1
fi
```

Update the comment block at `:979-982` and the `:955-961` doc comment to state the char-vs-byte over-read in the tool-less path (~4x cap worst case; byte-exact when stat/wc run; cap stays a DoS bound).

- [x] **Step 5:** `bash -n`, `shellcheck -S style -x`, `bats` — all pass, no prior regression.

### Task 2: A2 — delete the dead `*-release-cpe` arm + pin the reachable exclusion arms

**Files:** `fx-detect-os.sh:1521-1528`; `test/detect_os.bats`.

 - [x] **Step 1: Failing test** — parametrized loop; for each known-name release file a malformed-but-readable content must NOT be claimed at low trust:

```bash
@test "catch-all exclusion arms: malformed known-family files are never re-claimed low (R18-A2)" {
    for base in redhat-release centos-release fedora-release rocky-release \
                almalinux-release system-release lsb-release; do
        _OS_ROOT="$BATS_TEST_TMPDIR/t_$base"
        mkdir -p "$_OS_ROOT/etc"
        printf '%s\n' 'not a recognized vendor string' > "$_OS_ROOT/etc/$base"
        _OS_ROOT="$BATS_TEST_TMPDIR/t_$base" run bash -c \
            'lsb_release(){ return 1; }; timeout(){ shift; "$@"; };
             . "'"$BATS_TEST_DIRNAME"'/../fx-detect-os.sh"; detect_os; \
             printf "%s|%s|%s" "$OS_SOURCE" "$OS_ID" "$OS_TRUST_LEVEL"'
        # Exclusion arm held: falls through to uname (low), never claims <id>.
        [[ "$output" == "uname|linux|low" ]] || return 1
    done
}
```

> Note: `detect_os` with only these files and no os-release ends at uname -> `OS_SOURCE=uname OS_ID=linux OS_TRUST_LEVEL=low`. Deletion of the dead arm must NOT be what makes the test pass — the loop's arms are all reachable, so they were already working; this test pins the guard so a future per-arm typo (dropped `centos-release` line) fails loudly.

- [x] **Step 2:** verify it FAILS when the exclusion list is broken (temporarily remove one arm) — then restore.

 - [x] **Step 3: Implement** — delete `|*-release-cpe)` line at `:1526`; add after the case-close comment: `# CPE metadata files (<id>-release-cpe) are not glob-visible here (globs are *-release/*_release); the arm is intentionally absent — do NOT broaden the glob to re-add it.` Update the `:1510-1515` catch-all doc comment to say known-family exclusions are glob-visible only.

- [x] **Step 4:** full check.

### Task 3: #3 — pin `_os_redact_shapes` (6 + 1 tests)

**Files:** `test/detect_os.bats` (append near the redaction block).

 - [x] **Step 1: Tests**

```bash
@test "shape: Authorization: Bearer header token redacted (R18-S1)" {
    lib; run _os_redact_shapes 'curl -H "Authorization: Bearer eyJhbGciOi.eyJzdWIiOiJP.6mM8hzQYMi"'
    [ "$status" -eq 0 ]; [[ "$output" == *"Bearer [REDACTED]"* ]]; [[ "$output" != *"eyJhbGci"* ]]
}
@test "shape: bare Bearer token >=20 chars redacted (R18-S2)" {
    lib; run _os_redact_shapes 'using Bearer token 1234567890abcdefghijk in url'
    [ "$status" -eq 0 ]; [[ "$output" == *"Bearer [REDACTED]"* ]]; [[ "$output" != *"1234567890abcdefghijk"* ]]
}
@test "shape: AWS AKIA access-key id redacted (R18-S3)" {
    lib; run _os_redact_shapes 'key=AKIAIOSFODNN7EXAMPLE rest'
    [ "$status" -eq 0 ]; [[ "$output" != *"AKIAIOSFODNN7EXAMPLE"* ]]; [[ "$output" == *"[REDACTED]"* ]]
}
@test "shape: JWT eyJ blob redacted (R18-S4)" {
    lib; run _os_redact_shapes 'token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
    [ "$status" -eq 0 ]; [[ "$output" != *"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"* ]]
}
@test "shape: PEM private-key banner collapses whole line (R18-S5)" {
    lib; run _os_redact_shapes '-----BEGIN RSA PRIVATE KEY----- MIIEow ...'
    [ "$status" -eq 0 ]; [ "$output" = "[REDACTED]" ]
}
@test "shape: JSON credential pair redacted (R18-S6)" {
    lib; run _os_redact_shapes '{"api_key":"sk-1234567890abcdef"}'
    [ "$status" -eq 0 ]; [[ "$output" == *'"api_key":"[REDACTED]"'* ]]; [[ "$output" != *'sk-1234'* ]]
}
@test "shape: value-shape pass fires through _os_redact e2e (R18-S7)" {
    lib; run _os_redact 'loaded token AKIAIOSFODNN7EXAMPLE into cfg'
    [ "$status" -eq 0 ]; [[ "$output" != *'AKIAIOSFODNN7EXAMPLE'* ]]
}
```

- [x] **Step 2:** verify bar is real (each fails with `_os_redact_shapes` returning input). All should PASS immediately if the shipment is already correct — that is the "unpin" case; the tests then guard future regressions. Confirm each passes.

- [x] **Step 3:** doc note — README "Two redaction passes" -> "three passes" happens in Task 5.

### Task 4: #5 + D3 — container presence test + `_os_ENV` exec-failure warning

**Files:** `fx-detect-os.sh:578-581`; `test/detect_os.bats`.

 - [x] **Step 1: Tests**

```bash
@test "container: rootless podman /run/user marker resolves containers, never fabricated podman (R18-C1)" {
    mkdir -p "$_OS_ROOT/run/user/1000"
    : > "$_OS_ROOT/run/user/1000/.containerenv"
    lib; detect_os
    [ "$OS_CONTAINER" = "containers" ]
    [ "$OS_ID" = "linux" ] || [ -n "$OS_ID" ]
}

@test "redaction: set-but-broken _OS_ENV warns once, value-pass stays off (R18-D3)" {
    _OS_ENV=/nonexistent/env-tool lib
    run _os_redact 'cfg token=abc123 rest'
    [ "$status" -eq 0 ]
    [ -n "$STDERR" ] 2>/dev/null || bash -c 'true'   # placeholder, see step 2
    [[ "$output" == *"cfg [REDACTED] rest"* ]]
}
```

> The D3 test asserts stderr carries the one-time `osdetect:` warning. In bats, capture stderr with `run -u` (bats >= 1.5) or redirect `2>"$BATS_TEST_TMPDIR/err"` inside a `bash -c` and grep. Pick the idiom the existing suite already uses (search for `stderr` / `-u` in the file first) and match it.

- [x] **Step 2:** run — C1 should already pass (unpin); D3 should FAIL (no warning today).

 - [x] **Step 3: Implement D3** at `fx-detect-os.sh:578-581`:

```bash
    if [ -n "$_OS_ENV" ]; then
        envout="$("$_OS_ENV")" 2>/dev/null || {
            envout=""
            # One-shot: a set-but-broken _OS_ENV silently disables name-based
            # redaction while the caller believes secrets are scrubbed. The
            # :246 source-time warning only fires when _OS_ENV is unset.
            ! [ "${_os_env_failed:-0}" = 1 ] && _os_env_failed=1 \
                && _os_warn "caller-supplied _OS_ENV command failed — name-based env redaction is OFF; the shape pass is still active"
        }
    fi
```

> `_os_warn` is defined at `:834`, after this source-order point, but is only CALLED at runtime (inside `_os_redact`), when it exists — same safe pattern the plan headers already rely on. Ensure `_os_env_failed` starts unset (no explicit init needed; `:-0` guards).

- [x] **Step 4:** full check.

### Task 5: Docs resync + version bump (8 doc-only items + 1.8.0)

**Files:** `fx-detect-os.sh:163`; `README.md`; `docs/cheatsheet.md`.

 - [x] **Step 1: Version.** `readonly _OS_VERSION="1.7.0"` -> `"1.8.0"`.

 - [x] **Step 2: README test count.** `:365` put `bats test/detect_os.bats   # 159 tests`. Sweep whole README + cheatsheet for stale counts -> 159.

 - [x] **Step 3: `_OS_ENV` row rewrite (README table).** Replace the phantom "name list (colon/space separated)..." row with tool-path semantics: `_OS_ENV` = pinned `env(1)` tool path (tool-pinning map; invoked as a command; empty/missing at source time disables value-pass with a one-time `osdetect:` warning; a set-but-broken path warns at first redaction and shape-pass remains active). Remove the "Set it to a restricted list" promise.

 - [x] **Step 4: "Two redaction passes" -> "three passes" + shape-pass sentence.** In the debug-vocabulary paragraph, describe the third shape-driven pass (Authorization/Bearer, AKIA/ASIA, JWT eyJ, PEM banner, JSON credential pairs) — only after Task 3 tests land.

 - [x] **Step 5: container rows.** cheatsheet `:37` and README `:275` region: enumerate `docker | podman | oci | containers | none` and add the rootless `/run/user/<uid>/.containerenv` marker -> `containers` (no engine line -> never fabricate `podman`). cheatsheet `:83` container sentence too.

 - [x] **Step 6: cap qualifier.** README `:258-260` and cheatsheet `:28-30` size-cap wording gains one sentence: byte-exact via stat/wc; char-counted (<= ~4x cap) in the tool-less fallback; never slurped whole.

 - [x] **Step 7: step-ladder note.** README step-4/catch-all: add "(known-family exclusion arms apply to glob-visible names; CPE metadata files are out of glob scope)".

 - [x] **Step 8: audit-verify kept rows** (`_OS_LOG_FILE`/`_OS_ERROR_LOG` mode warnings, ">=4 chars, longest first") — no text change expected; confirm only.

- [x] **Step 9:** re-run full gate.

---

## Verification Checkpoints
 - [x] **CP-A:** `bash -n fx-detect-os.sh` -> rc 0
 - [x] **CP-B:** `shellcheck -S style -x fx-detect-os.sh test/detect_os.bats` -> rc 0 (keep the SC-disabling header pattern for any new guards)
 - [x] **CP-C:** `bats test/detect_os.bats` -> line-count shows `^@test` = 159 (147 prior + 12 new); all pass
 - [x] **CP-D:** live smoke (`_OS_DEBUG=1 bash -c '. ./fx-detect-os.sh; detect_os; ...'`) clean; no unexpected `osdetect:` warnings on a default (unset `_OS_ENV`) run
 - [x] **CP-E:** README/cheatsheet contain no "133"/"58"/"68" counts; version string 1.8.0 in script + docs
 - [x] **CP-F:** verification record appended to plan; `progress.md` gains a final entry

## Verification Record (2026-09-19)

Executed after all five findings fixed and docs resynced.

| Checkpoint | Result |
| ---------- | ------ |
| CP-A `bash -n fx-detect-os.sh` | rc 0 |
| CP-B `shellcheck -S style -x fx-detect-os.sh test/detect_os.bats` | rc 0 on both (added documented disables: SC2016 at the two `bash -c` fixture stubs; SC2034 for the readonly-declaration test subjects via a header SC2317/SC2034/SC1003/SC2016 entry; repurposed the `! rg` assertion in D3 to an `if rg …; then return 1` idiom — no flag form needed) |
| CP-C `bats test/detect_os.bats` | `^@test` = 159 (147 prior + 12 new); **159/159 pass, rc 0** |
| CP-D live smoke (`_OS_DEBUG=1 bash -c '. ./fx-detect-os.sh; detect_os; …'` on this host, `_OS_ENV` unset) | rc 0, `OS_ID=cachyos`, `OS_CONTAINER=none`; stderr carries only the expected debug-log path line, no `osdetect:` warnings |
| CP-E stale counts + version | README/cheatsheet contain no "133"/"58"/"68"/"146" counts; `_OS_VERSION="1.8.0"` at `fx-detect-os.sh:163` |
| CP-F records | this table + `progress.md` entry |

Also noted while gating: the full-suite wall-time is dominated by the pre-existing
bats `DEBUG`-trap overhead (~30-50x per command), which makes the 200-iteration
fuzz test alone take ~50s; the suite is not a regression source. The earlier
`157/157` figure in the working notes predates the final two tests (D3, R18-C5);
the authoritative count is 159.

## Definition of Done
All five consensus findings resolved (two bugs fixed via TDD, dead arm deleted, shapes + container + env-warn pinned), docs truthful, 159 tests green, lint clean, smoke clean, version 1.8.0. Project finalized, no remaining open eval/tail findings.
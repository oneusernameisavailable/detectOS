# fx-detect-os.sh — Adversarial Eval Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Fix the HIGH/MEDIUM/LOW findings from the adversarial eval without regressing the 129-test suite.

**Architecture:** Source-only bash library. All fixes are localized: two source-time hoists/warnings, one policy-mirror in the failure log, plus doc/indent/redaction corrections. Every behavioral change gets a failing bats test first.

**Tech Stack:** Bash >= 4.0, bats-core, shellcheck.

## Global Constraints
- Do NOT add `set -e`/`set -u`/`pipefail` or traps (sourced-library contract).
- Do NOT use `eval`, process substitution, or `ls` parsing (library design rules).
- All new stderr diagnostics must use `_os_warn` (prints `osdetect: ...`).
- Preserve: `bash -n` clean, `shellcheck -S style -x` rc 0, all prior tests pass.
- Test files: `test/detect_os.bats`. Source: `fx-detect-os.sh`. Docs: `README.md`, `docs/cheatsheet.md`.
- Baseline commands:
  - `bats test/detect_os.bats` -> currently 129/129 pass
  - `shellcheck -S style -x fx-detect-os.sh test/detect_os.bats` -> rc 0
  - `bash -n fx-detect-os.sh` -> rc 0
- Repository is NOT a git repo: no commit steps; use the verification checkpoints.

> **Note:** `_os_warn` (line 579) is defined after `_os_ensure_log_file` (line 218), but both exist at call time, so calling `_os_warn` from the earlier function is safe.

---

### Task 1: F2 (HIGH) — stop `_os_run_lsb_cmd` from destroying a caller-owned `_os_lsb`

**Files:**
- Modify: `fx-detect-os.sh:978-1037`
- Test: `test/detect_os.bats` (append)

**Interfaces:**
- Produces: source-time `_os_lsb deadline_secs args...`; `_os_run_lsb_cmd` calls it with a local `_os_lsb_deadline`. No `unset -f` remains.

- [ ] **Step 1: Write the failing test** (append to `test/detect_os.bats`)

```bash
@test "command-step run does not unset _os_lsb (F2)" {
    run bash -c '
        lsb_release() { printf "ubuntu\n"; return 0; }
        . "$1"
        unset _OS_ROOT
        before=$(declare -F _os_lsb >/dev/null 2>&1 && echo yes || echo no)
        _os_run_lsb_cmd >/dev/null 2>&1 || true
        after=$(declare -F _os_lsb >/dev/null 2>&1 && echo yes || echo no)
        printf "before=%s after=%s\n" "$before" "$after"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"before=yes"* ]]
    [[ "$output" == *"after=yes"* ]]
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `bats -f "does not unset _os_lsb" test/detect_os.bats`
Expected: FAIL — `before=no after=no` (function only defined inside the call today).

- [ ] **Step 3: Implement the fix**

Insert this function immediately above the `_os_run_lsb_cmd` comment block (before line 978):

```bash
# NAME  _os_lsb
# ARGS  deadline_epoch_seconds  lsb_release args...
# WHAT  runs the pinned lsb_release under the caller's shared 5s budget when
#       coreutils timeout is present at source time, else unbounded. Defined
#       ONCE at source time (like every other _os_ helper), so no function is
#       created or unset mid-call: a caller-owned name in the _os_ namespace is
#       replaced by sourcing (the documented contract) but is never destroyed
#       during detect_os.
_os_lsb() {
    local -i _os_lsb_deadline="$1"; shift
    if [ -n "$_OS_TIMEOUT" ]; then
        local -i _os_lsb_rem=$(( _os_lsb_deadline - SECONDS ))
        [ "$_os_lsb_rem" -le 0 ] && return 1
        _os_runx "$_OS_TIMEOUT" "$_os_lsb_rem" "$@"
    else
        _os_runx "$@"
    fi
}
```

Then replace the body of `_os_run_lsb_cmd` from the budget comment through `return 1` (lines 999-1036) with:

```bash
    # Bound lsb_release with coreutils `timeout` when present at source time —
    # it can hang on broken systems. Absent timeout -> unbounded legacy
    # behavior. A run killed by timeout (rc 124) is treated exactly like a
    # missing command. All four probes share ONE 5-second budget (SECONDS =
    # shell runtime) via the source-time _os_lsb helper.
    local -i _os_lsb_deadline=$(( SECONDS + 5 ))
    v="$(_os_lsb "$_os_lsb_deadline" "$_OS_LSBRELEASE" -is 2>/dev/null)" || v=""
    [ -n "$v" ] && OS_ID="$(_os_sanitize_id "$v")"
    v="$(_os_lsb "$_os_lsb_deadline" "$_OS_LSBRELEASE" -rs 2>/dev/null)" || v=""
    [ -n "$v" ] && OS_VERSION_ID="$(_os_sanitize_version "$v")"
    v="$(_os_lsb "$_os_lsb_deadline" "$_OS_LSBRELEASE" -cs 2>/dev/null)" || v=""
    [ -n "$v" ] && OS_VERSION_CODENAME="$(_os_sanitize_display "$v")"
    v="$(_os_lsb "$_os_lsb_deadline" "$_OS_LSBRELEASE" -ds 2>/dev/null)" || v=""
    [ -n "$v" ] && OS_PRETTY_NAME="$(_os_sanitize_display "$v")"
    if [ -n "${OS_ID:-}" ]; then
        OS_SOURCE="lsb_release-command"
        OS_TRUST_LEVEL=medium
        _os_exit; return 0
    fi
    _os_last_detail="lsb_release ran but produced no ID"
    OS_VERSION_ID="" OS_VERSION_CODENAME="" OS_PRETTY_NAME=""
    OS_TRUST_LEVEL=none
    _os_exit
    return 1
```

- [ ] **Step 4: Verify target test + the lsb tests**

Run: `bats -f "_os_lsb" -f "lsb_release" -f "timeout" test/detect_os.bats`
Expected: PASS — including tests 706 (`EXEC: timeout 5 lsb_release`), 715 (rc 124), 725 (unbounded), 1351 (stub medium).

- [ ] **Step 5: Full suite + lint**

Run: `bats test/detect_os.bats && shellcheck -S style -x fx-detect-os.sh test/detect_os.bats && bash -n fx-detect-os.sh`
Expected: all pass, rc 0.

---

### Task 2: F1 (MEDIUM) — make debug-log OFF degradation non-silent

**Files:**
- Modify: `fx-detect-os.sh:218-259`
- Test: `test/detect_os.bats` (append)

- [ ] **Step 1: Write the failing test**

```bash
@test "debug requested with no log target warns once (F1)" {
    run bash -c '
        export PATH=""
        export _OS_DEBUG=1
        . "$1"
        _os_ensure_log_file
        _os_ensure_log_file
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [ "$(printf '%s\n' "$output" | grep -c 'debug log is OFF')" -eq 1 ]
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `bats -f "warns once (F1)" test/detect_os.bats`
Expected: FAIL — no warning emitted today.

- [ ] **Step 3: Implement the fix** in `_os_ensure_log_file`

Replace the caller-path branch opening and the final guard:

```bash
    else
        _os_log_file="$_OS_LOG_FILE"
        if ! : >> "$_os_log_file" 2>/dev/null; then
            _os_warn "debug requested but caller-supplied _OS_LOG_FILE is not writable — debug log is OFF"
            _os_log_file=""
            return 0
        fi
        if [ -n "$_OS_STAT" ]; then
```

and replace `[ -n "$_os_log_file" ] || return 0` with:

```bash
    if [ -z "$_os_log_file" ]; then
        _os_warn "debug requested but no writable log target (mktemp unavailable and no _OS_LOG_FILE) — debug log is OFF"
        return 0
    fi
```

- [ ] **Step 4: Verify target + affected tests**

Run: `bats -f "F1" -f "degrades to off" -f "strict-mode caller survives an unwritable" -f "keeps its mode" -f "world-visible caller log" test/detect_os.bats`
Expected: PASS (tests 358, 346, 742, 1449 still green; assertions are substring-based).

- [ ] **Step 5: Full suite + lint**.

---

### Task 3: F3 (MEDIUM) — warn on world-visible caller-supplied failure log

**Files:**
- Modify: `fx-detect-os.sh:319-342`
- Test: `test/detect_os.bats` (append)

- [ ] **Step 1: Write the failing test**

```bash
@test "world-visible caller error log warns but keeps its mode (F3)" {
    lib
    [ -n "$_OS_STAT" ] || skip "stat not available"
    local log="$BATS_TEST_TMPDIR/fw.log"
    : > "$log"
    chmod 0644 "$log"
    export _OS_ERROR_LOG="$log"
    run _os_ensure_error_log
    [ "$status" -eq 0 ]
    [[ "$output" == *"world-visible mode"* ]]
    [ "$(stat -c %a "$log")" = "644" ]
    chmod 0600 "$log"
    run _os_ensure_error_log
    [[ "$output" != *"world-visible"* ]]
    rm -f "$log"
}
```

- [ ] **Step 2: Verify it fails**

Run: `bats -f "world-visible caller error log" test/detect_os.bats`
Expected: FAIL — no warning today.

- [ ] **Step 3: Implement the fix** in `_os_ensure_error_log`

Replace the chmod block + `printf` at the end:

```bash
    : >> "$target" 2>/dev/null || return 1
    if [ -z "${_OS_ERROR_LOG:-}" ]; then
        [ -n "$_OS_CHMOD" ] && "$_OS_CHMOD" 600 "$target" 2>/dev/null || :
    elif [ -n "$_OS_STAT" ]; then
        local emode egroup eother
        emode="$("$_OS_STAT" -c %a "$target" 2>/dev/null)" || emode=""
        egroup="${emode: -2:1}"; eother="${emode: -1}"
        case "${egroup}${eother}" in
            00) : ;;
            *) _os_warn "caller-supplied _OS_ERROR_LOG has group/world-visible mode $emode (left unchanged per policy)" ;;
        esac
    fi
    printf '%s\n' "$target"
```

- [ ] **Step 4: Verify target + existing error-log tests**

Run: `bats -f "error log" -f "F3" -f "_os_ensure_error_log" test/detect_os.bats`
Expected: PASS (526, 539, 512 unaffected).

- [ ] **Step 5: Full suite + lint**.

---

### Task 4: F5 + F4 (LOW) — indentation and stale comment

**Files:**
- Modify: `fx-detect-os.sh:843` (indent), `fx-detect-os.sh:158-166` (comment)

- [ ] **Step 1: Fix line 843** — add 4-space indentation to `OS_PRETTY_NAME="$(_os_sanitize_display "$line")"`.
- [ ] **Step 2: Correct the `_OS_INTERNAL_SCRATCH` comment** to state that `_os_last_detail/_os_log_file/_os_log_ready` are globals, while `_os_steps` is written by `detect_os` as a local read by `_os_failure_record` via bash dynamic scope, and is reserved only so a direct-call caller-owned `_os_steps` is not clobbered.
- [ ] **Step 3: Verify**

Run: `bash -n fx-detect-os.sh && shellcheck -S style -x fx-detect-os.sh && bats test/detect_os.bats`
Expected: all pass (no behavioral change).

---

### Task 5: F6 + F7 (LOW) — document tool-loop scratch; redact digit-leading names

**Files:**
- Modify: `fx-detect-os.sh:171-184` (comment), `fx-detect-os.sh:439` (regex)
- Test: `test/detect_os.bats` (append)

- [ ] **Step 1: Write the failing test for F7**

```bash
@test "redaction: digit-leading secret names redact in NAME=value form (F7)" {
    lib
    run _os_redact 'cfg 3DES_KEY=value123 tail'
    [ "$status" -eq 0 ]
    [ "$output" = "cfg [REDACTED] tail" ]
}
```

- [ ] **Step 2: Verify it fails**

Run: `bats -f "digit-leading secret" test/detect_os.bats`
Expected: FAIL — output keeps `3DES_KEY=value123`.

- [ ] **Step 3: Broaden the pass-1 identifier class** at line 439: change `([A-Za-z_][A-Za-z0-9_]*)` to `([A-Za-z0-9_][A-Za-z0-9_]*)`.
- [ ] **Step 4: Add the F6 doc note** to the captured-tool-paths comment: `_os_tool`/`_os_var`/`_os_cmd` are transient source-time scratch names unset after the loop; since `_os_` is library-owned, a caller owning them loses them at source time. (No code change.)
- [ ] **Step 5: Verify**

Run: `bats -f "redaction" test/detect_os.bats && bats test/detect_os.bats && shellcheck -S style -x fx-detect-os.sh`
Expected: all pass.

---

### Task 6: Docs — behavior notes + test count

**Files:**
- Modify: `README.md:6-13`, `README.md:264`, `README.md:340`, `docs/cheatsheet.md:102`, header `fx-detect-os.sh:55-67`

- [ ] **Step 1:** Change "silently degrades to OFF" -> "warns once (`osdetect:`) and degrades to OFF" in header DEBUGGING and README/cheatsheet.
- [ ] **Step 2:** Document the failure-log world-visible warning next to the debug-log warning in `_OS_ERROR_LOG`'s row.
- [ ] **Step 3:** Update the reserved-namespace note to mention the `_os_` function namespace (including `_os_lsb`).
- [ ] **Step 4:** Update test counts in `README.md:340` and `docs/cheatsheet.md:102` from `129` to the actual final count (`bats --count test/detect_os.bats`).
- [ ] **Step 5: Verify**

Run: `bash -n fx-detect-os.sh && shellcheck -S style -x fx-detect-os.sh test/detect_os.bats && bats test/detect_os.bats`
Expected: all pass; count matches docs.

---

## Self-Review

**Spec coverage:** F2 -> Task 1, F1 -> Task 2, F3 -> Task 3, F4/F5 -> Task 4, F6/F7 -> Task 5, doc drift -> Task 6.

**Placeholder scan:** none.

**Type consistency:** `_os_lsb` signature used consistently at all four call sites; `_os_lsb_deadline` local in `_os_run_lsb_cmd`; `emode/egroup/eother` mirror the existing debug-log naming.

**Risk notes:** F2 is behavior-preserving for tests 706/715/725/1351. F1/F3 only add stderr lines. F7 broadens a capture class whose non-secret matches are re-emitted unchanged.

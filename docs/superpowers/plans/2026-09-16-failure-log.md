# Permanent AI-readable failure log Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When `detect_os` cannot resolve an OS identity (rc 1), append one NDJSON line to `OSDetectFailureLog/osdetect-failures.jsonl` describing the full ladder trace so an AI can batch-troubleshoot failures.

**Architecture:** Three new helpers (`_os_json_escape`, `_os_ensure_error_log`, `_os_failure_record`) plus a ladder-capture array (`_os_steps`) and a per-helper `_os_last_detail` scratch string wired into the five ladder functions. `detect_os` builds step records as it runs; on identity-unresolved it calls `_os_failure_record`, which serializes one redacted NDJSON line. Success runs write nothing. Unwritable log paths are fail-open.

**Tech Stack:** Bash >= 4.2; bats-core; shellcheck.

## Global Constraints

- No git — no commit steps. Every task ends with VERIFY GATE: `bats test/detect_os.bats` + `bash -n fx-detect-os.sh` + `shellcheck -S style -x fx-detect-os.sh test/detect_os.bats`.
- No process substitution (file-header promise). `env` into here-strings only.
- No top-level `declare` — `local`/`local -a`/`local -A` inside functions only.
- All log output redacted via `_os_redact` before write (S5 rule applies to the permanent log).
- Mode `0600` for all log files. Never chmod a caller-supplied path.
- Current baseline: `readonly _OS_VERSION="1.5.0"` at `fx-detect-os.sh:111`; 71 bats tests pass.

---

## Task 1: `_os_json_escape` helper

**Files:**
- Modify: `fx-detect-os.sh` (insert after `_os_ensure_log_file` block, before `_os_secret_name` at current line ~211)
- Modify: `test/detect_os.bats` (insert new test before `@test "direct execution refuses with exit 2"`)

**Interfaces:**
- Consumes: one positional arg (raw string).
- Produces: JSON-safe string on stdout. No side effects.

- [ ] **Step 1: Write the failing test**

Insert before `@test "direct execution refuses with exit 2"` in `test/detect_os.bats`:

```bash
@test "_os_json_escape escapes backslash, quote, and control chars" {
    lib
    run _os_json_escape 'a\b"c'
    [ "$status" -eq 0 ]
    [ "$output" = 'a\\b\"c' ]

    run _os_json_escape $'line1\nline2'
    [ "$status" -eq 0 ]
    [ "$output" = 'line1\nline2' ]

    run _os_json_escape "tab-->	here"
    [ "$status" -eq 0 ]
    [ "$output" = 'tab-->\t here' ]
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bats test/detect_os.bats`
Expected: new test FAIL (function not yet defined); all existing tests still pass.

- [ ] **Step 3: Implement `_os_json_escape`**

Insert in `fx-detect-os.sh` after the `_os_ensure_log_file` block (after its closing `}` and a blank line) and before `_os_secret_name`:

```bash
# NAME  _os_json_escape
# ARGS  string
# WHAT  prints the string JSON-safe (escape \, ", and control chars <0x20).
#       No external dependencies (pure bash, no process substitution).
_os_json_escape() {
    local s="$1" out="" c i code hex
    local LC_ALL=C
    for (( i = 0; i < ${#s}; i++ )); do
        c="${s:i:1}"
        case "$c" in
            '\\')  out+='\\\\' ;;
            '"')   out+='\\"' ;;
            $'\n') out+='\\n' ;;
            $'\r') out+='\\r' ;;
            $'\t') out+='\\t' ;;
            *)
                code="$(printf '%d' "'$c")"
                if [ "$code" -lt 32 ]; then
                    printf -v hex '%04x' "$code"
                    out+="\\u$hex"
                else
                    out+="$c"
                fi
                ;;
        esac
    done
    printf '%s\n' "$out"
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bats test/detect_os.bats`
Expected: new test PASS; all existing tests still pass.

- [ ] **Step 5: VERIFY GATE**

Run:
```bash
bats test/detect_os.bats
bash -n fx-detect-os.sh
shellcheck -S style -x fx-detect-os.sh test/detect_os.bats
```
Expected: 72/72 PASS, no syntax errors, no shellcheck findings.

---

## Task 2: `_os_error_log_path` + `_os_ensure_error_log`

**Files:**
- Modify: `fx-detect-os.sh` (insert after `_os_json_escape`, before `_os_secret_name`)
- Modify: `test/detect_os.bats` (insert two tests after the `_os_json_escape` test)

**Interfaces:**
- `_os_error_log_path` — consumes: none (reads `_OS_ERROR_LOG` / `BASH_SOURCE[0]`). Produces: path string on stdout.
- `_os_ensure_error_log` — consumes: `_OS_ERROR_LOG` env. Produces: path string on stdout; side effect: creates dir+file (mode 0600 when default path, no chmod when `_OS_ERROR_LOG` set). Returns 1 on unwritable targets.

- [ ] **Step 1: Write the failing tests**

Insert after the `_os_json_escape` test:

```bash
@test "_os_error_log_path defaults to OSDetectFailureLog/ next to the library" {
    lib
    run _os_error_log_path
    [ "$status" -eq 0 ]
    [[ "$output" == */OSDetectFailureLog/osdetect-failures.jsonl ]]
    [[ "$output" != */tmp/* ]]
}

@test "_os_ensure_error_log creates default dir+file with mode 0600 (and cleans up)" {
    local default_path mode
    lib
    default_path="$(_os_error_log_path)"
    rm -rf "${default_path%/*}"          # avoid any pre-existing artifact
    run _os_ensure_error_log
    [ "$status" -eq 0 ]
    [ -f "$default_path" ]
    mode=$(stat -c '%a' "$default_path")
    [ "$mode" = "600" ]
    rm -rf "${default_path%/*}"          # leave the repo clean
}

@test "_os_ensure_error_log does not chmod a caller-supplied path" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/custom.log"
    lib
    touch "$_OS_ERROR_LOG"
    chmod 644 "$_OS_ERROR_LOG"
    run _os_ensure_error_log
    [ "$status" -eq 0 ]
    local mode
    mode=$(stat -c '%a' "$_OS_ERROR_LOG")
    [ "$mode" = "644" ]
    rm -f "$_OS_ERROR_LOG"
}

@test "_os_ensure_error_log returns 1 when target is an existing directory (fail-open)" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/root"    # a directory
    lib
    run _os_ensure_error_log
    [ "$status" -eq 1 ]
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `bats test/detect_os.bats`
Expected: 4 new tests FAIL; all existing tests still pass.

- [ ] **Step 3: Implement `_os_error_log_path` and `_os_ensure_error_log`**

Insert in `fx-detect-os.sh` immediately after `_os_json_escape`:

```bash
# NAME  _os_error_log_path
# ARGS  none
# WHAT  echoes the error log path: _OS_ERROR_LOG when set, otherwise the
#       default OSDetectFailureLog/osdetect-failures.jsonl next to the library.
_os_error_log_path() {
    if [ -n "${_OS_ERROR_LOG:-}" ]; then
        printf '%s\n' "$_OS_ERROR_LOG"
    else
        printf '%s\n' "${BASH_SOURCE[0]%/*}/OSDetectFailureLog/osdetect-failures.jsonl"
    fi
}

# NAME  _os_ensure_error_log
# ARGS  none
# WHAT  idempotently creates the failure log dir+file (mode 0600) and echoes
#       its path. Never chmods a caller-supplied _OS_ERROR_LOG path (same
#       policy as _OS_LOG_FILE). Fail-open: returns 1 on unwritable targets.
_os_ensure_error_log() {
    local target dir
    target="$(_os_error_log_path)"
    case "$target" in
        */*) dir="${target%/*}" ;;
        *)   dir="." ;;
    esac
    mkdir -p "$dir" 2>/dev/null || return 1
    : >> "$target" 2>/dev/null || return 1
    if [ -z "${_OS_ERROR_LOG:-}" ]; then
        chmod 600 "$target" 2>/dev/null || :
    fi
    printf '%s\n' "$target"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `bats test/detect_os.bats`
Expected: 76/76 PASS.

- [ ] **Step 5: VERIFY GATE**

Run:
```bash
bats test/detect_os.bats
bash -n fx-detect-os.sh
shellcheck -S style -x fx-detect-os.sh test/detect_os.bats
```
Expected: 76/76 PASS, no syntax errors, no shellcheck findings.

---

## Task 3: `_os_failure_record` + ladder capture integration

**Files:**
- Modify: `fx-detect-os.sh` — three edit sites:
  1. Insert `_os_failure_record` helper after `_os_ensure_error_log` (before `_os_log_raw`)
  2. Add `_os_last_detail=` assignments in each of the 5 ladder helpers (at their respective return-1 paths)
  3. Replace the ladder block in `detect_os` (`fx-detect-os.sh:950-995`) with the capture version + `_os_failure_record` call
- Modify: `test/detect_os.bats` — insert 6 integration tests before `@test "direct execution refuses with exit 2"`

**Interfaces:**
- Consumes: run-scoped `_os_steps` array (triples: source, rc, detail), current `OS_*` globals, `_os_last_detail` scratch (set by each ladder helper at its return-1 path).
- Produces: one NDJSON line appended to the error log. `_os_steps` array is not cleared (function ends immediately after).

- [ ] **Step 1: Add `_os_last_detail` to each ladder helper**

Edit `fx-detect-os.sh` — five small insertions:

**`_os_read_os_release` (line ~636):** insert before `_os_exit` / `return 1` (the existing line `OS_ID="" OS_ID_LIKE="" ...`), after the reset line:

```bash
    local de du
    de="absent"; du="absent"
    [ -f "$f_e" ] && de="present"
    [ -f "$f_u" ] && du="present"
    _os_last_detail="/etc/os-release $de (no ID), /usr/lib/os-release $du (no ID)"
```

**`_os_parse_lsb_release` (line ~670):** insert before `_os_exit` / `return 1` (just after the existing reset line or before `_os_exit`):

```bash
    local ld
    ld="absent"
    [ -f "$f" ] && ld="present (no DISTRIB_ID)"
    _os_last_detail="/etc/lsb-release $ld"
```

**`_os_run_lsb_cmd` — three insertions:**

At line ~683 (after `[ -z "$_OS_LSBRELEASE" ]` guard, before `_os_exit; return 1`):

```bash
        _os_last_detail="lsb_release command not found on PATH"
```

At line ~691 (after `[ -n "${_OS_ROOT:-}" ]` guard, before `_os_exit; return 1`):

```bash
        _os_last_detail="lsb_release command disabled under _OS_ROOT (host isolation)"
```

At line ~713 (before `_os_exit` / `return 1`, i.e. the "no ID after all calls" path):

```bash
    _os_last_detail="lsb_release ran but produced no ID"
```

**`_os_parse_legacy` (line ~851):** insert before `_os_exit` / `return 1`:

```bash
    _os_last_detail="no legacy release file matched in /etc"
```

**`_os_uname_fallback` (line ~871):** insert before `_os_exit` / `return 1`:

```bash
    _os_last_detail="uname produced no usable ID"
```

- [ ] **Step 2: Run tests to verify no regressions**

Run: `bats test/detect_os.bats`
Expected: 76/76 PASS (no behaviour change yet).

- [ ] **Step 3: Insert `_os_failure_record` helper**

Insert in `fx-detect-os.sh` immediately after `_os_ensure_error_log` (before `_os_log_raw`):

```bash
# NAME  _os_failure_record
# ARGS  none (reads run-scoped _os_steps array + OS_* globals)
# WHAT  appends one NDJSON identity-unresolved event to the failure log.
#       All values are redacted before JSON-encoding. Fail-open: an
#       unwritable log never changes detect_os rc or prints to stderr.
_os_failure_record() {
    local target src rc detail steps_json j
    local e s fval fs finals_json fname
    target="$(_os_ensure_error_log)" || return 0
    steps_json=""
    for (( j = 0; j < ${#_os_steps[@]}; j += 3 )); do
        src="$(_os_redact "${_os_steps[j]}")"; src="${src%$'\n'}"
        rc="${_os_steps[j+1]}"
        detail="$(_os_redact "${_os_steps[j+2]}")"; detail="${detail%$'\n'}"
        s="$(_os_json_escape "$src")"
        e="$(_os_json_escape "$detail")"
        [ -n "$steps_json" ] && steps_json+=","
        steps_json+="{\"source\":\"$s\",\"rc\":$rc,\"detail\":\"$e\"}"
    done
    finals_json=""
    for fname in OS_ID OS_ID_LIKE OS_NAME OS_VERSION OS_PRETTY_NAME OS_SOURCE; do
        fval="$(_os_redact "${!fname:-}")"; fval="${fval%$'\n'}"
        fs="$(_os_json_escape "$fval")"
        [ -n "$finals_json" ] && finals_json+=","
        finals_json+="\"${fname#OS_}\":\"$fs\""
    done
    finals_json+=",\"FALLBACK\":$([ "${OS_FALLBACK_USED:-0}" = "1" ] && printf '%s' true || printf '%s' false)"
    local line=""
    line+="{\"ts\":\"$(_os_json_escape "$(date -u '+%FT%TZ')")\""
    line+=",\"pid\":$$"
    line+=",\"caller\":\"$(_os_json_escape "$0")\""
    line+=",\"lib\":\"${BASH_SOURCE[0]##*/}\""
    line+=",\"version\":\"$_OS_VERSION\""
    line+=",\"_os_root\":$([ -n "${_OS_ROOT:-}" ] && printf '%s' true || printf '%s' false)"
    line+=",\"uname\":$([ -n "$_OS_UNAME" ] && printf '%s' true || printf '%s' false)"
    line+=",\"outcome\":\"identity-unresolved\""
    line+=",\"steps\":[$steps_json]"
    line+=",\"finals\":{$finals_json}"
    line+="}"
    printf '%s\n' "$line" >> "$target" 2>/dev/null || :
    return 0
}
```

- [ ] **Step 4: Replace the `detect_os` ladder block**

In `fx-detect-os.sh`, replace lines 950-971 (from `OS_DETECTED=0` through the end of the `fi` closing the ladder) with:

```bash
    OS_DETECTED=0
    OS_FALLBACK_USED=0
    {
        local name
        for name in "${_OS_RESET_FIELDS[@]}"; do
            printf -v "$name" ''
        done
    }
    OS_CONTAINER="none"

    local -a _os_steps=()
    _os_last_detail=""   # global scratch: the ladder helpers write it, detect_os reads it
    _os_stage "identity-detection"
    if _os_read_os_release; then
        _os_steps+=("os-release" "0" "$_os_last_detail")
    else
        _os_steps+=("os-release" "1" "$_os_last_detail")
        if _os_parse_lsb_release; then
            OS_FALLBACK_USED=1
            _os_steps+=("lsb-release" "0" "$_os_last_detail")
        else
            _os_steps+=("lsb-release" "1" "$_os_last_detail")
            if _os_run_lsb_cmd; then
                OS_FALLBACK_USED=1
                _os_steps+=("lsb_release-cmd" "0" "$_os_last_detail")
            else
                _os_steps+=("lsb_release-cmd" "1" "$_os_last_detail")
                if _os_parse_legacy; then
                    OS_FALLBACK_USED=1
                    _os_steps+=("legacy" "0" "$_os_last_detail")
                else
                    _os_steps+=("legacy" "1" "$_os_last_detail")
                    if _os_uname_fallback; then
                        OS_FALLBACK_USED=1
                        _os_steps+=("uname-fallback" "0" "$_os_last_detail")
                    else
                        _os_steps+=("uname-fallback" "1" "$_os_last_detail")
                    fi
                fi
            fi
        fi
    fi
```

Then in the same function, replace the unresolved block (the `OS_DETECTED=0` / `return 1` section after the resolved check) with:

```bash
    OS_DETECTED=0
    _os_log "!! ERROR identity could not be resolved"
    _os_dump_state
    _os_failure_record
    _os_exit
    return 1
```

(i.e., insert one line `_os_failure_record` before `_os_exit` in the unresolved path).

- [ ] **Step 5: Run tests to verify no regressions**

Run: `bats test/detect_os.bats`
Expected: 76/76 PASS (ladder capture is wired but no test checks the file yet).

- [ ] **Step 6: Write the integration tests**

Insert before `@test "direct execution refuses with exit 2"` in `test/detect_os.bats`:

```bash
@test "identity-unresolved appends one NDJSON event to the error log" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/failures.jsonl"
    run bash -c '
        export PATH=/nonexistent
        . "$1"
        export PATH=/usr/bin:/bin
        detect_os
        printf "rc=%s\n" "$?"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"rc=1"* ]]
    [ -f "$_OS_ERROR_LOG" ]
    local lines
    lines=$(wc -l < "$_OS_ERROR_LOG")
    [ "$lines" -eq 1 ]
    if command -v jq >/dev/null 2>&1; then
        jq -e . < "$_OS_ERROR_LOG" >/dev/null
    else
        run grep -F '{' "$_OS_ERROR_LOG"
        [ "$status" -eq 0 ]
        run grep -F '}' "$_OS_ERROR_LOG"
        [ "$status" -eq 0 ]
    fi
    run grep -F '"outcome":"identity-unresolved"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    run grep -F '"source":"os-release"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    run grep -F '"source":"uname-fallback"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    rm -f "$_OS_ERROR_LOG"
}

@test "identity-resolved does NOT create the error log" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/failures-ok.jsonl"
    printf '%s\n' 'NAME="Suc"' 'ID=suc' > "$_OS_ROOT/etc/os-release"
    lib
    detect_os
    [ "$OS_ID" = "suc" ]
    [ ! -f "$_OS_ERROR_LOG" ]
}

@test "failure log honors _OS_ERROR_LOG override" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/override-log.txt"
    run bash -c '
        export PATH=/nonexistent
        . "$1"
        export PATH=/usr/bin:/bin
        detect_os
        printf "rc=%s\n" "$?"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [ -f "$_OS_ERROR_LOG" ]
    run grep -F '"outcome":"identity-unresolved"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    rm -f "$_OS_ERROR_LOG"
}

@test "unwritable error log path does not change detect_os rc (fail-open)" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/root"    # an existing directory: append fails
    run bash -c '
        export PATH=/nonexistent
        . "$1"
        export PATH=/usr/bin:/bin
        detect_os
        printf "rc=%s\n" "$?"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"rc=1"* ]]
}

@test "error log redacts space-containing secret values in event fields (S5 guard)" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/redact-err.jsonl"
    export SECRET_PROBE='probe val=1=x'
    lib
    # Direct helper call: detect_os resets OS_* fields before _os_failure_record runs,
    # so injection goes through the detail string, which is exactly what redaction guards.
    _os_steps=("os-release" "1" "commit SECRET_PROBE=probe val=1=x tail msg=probe val=1=x")
    _os_failure_record
    [ -f "$_OS_ERROR_LOG" ]
    run grep -F 'val=1=x' "$_OS_ERROR_LOG"
    [ "$status" -eq 1 ]
    run grep -F '[REDACTED]' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    run grep -F '"outcome":"identity-unresolved"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    rm -f "$_OS_ERROR_LOG"
}

@test "error log records os-release and legacy step details for legacy-only failure" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/legacy-err.jsonl"
    printf '%s\n' 'NAME="NoID Distro"' > "$_OS_ROOT/etc/os-release"
    printf '%s\n' 'Unknown Linux' > "$_OS_ROOT/etc/system-release"
    run bash -c '
        export PATH=/nonexistent
        . "$1"
        export PATH=/usr/bin:/bin
        detect_os
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ -f "$_OS_ERROR_LOG" ]
    run grep -F '"source":"os-release"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    run grep -F '"source":"legacy"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    run grep -F '/etc/os-release' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    rm -f "$_OS_ERROR_LOG"
}
```

- [ ] **Step 7: Run all tests to verify PASS**

Run: `bats test/detect_os.bats`
Expected: 82/82 PASS.

- [ ] **Step 8: VERIFY GATE**

Run:
```bash
bats test/detect_os.bats
bash -n fx-detect-os.sh
shellcheck -S style -x fx-detect-os.sh test/detect_os.bats
```
Expected: 82/82 PASS, no syntax errors, no shellcheck findings.

---

## Task 4: Version bump + docs + final VERIFY GATE

**Files:**
- Modify: `fx-detect-os.sh:111` — version
- Modify: `README.md` — env-var table, new failure-log paragraph, layout block, test count
- Modify: `docs/cheatsheet.md` — one failure-log line in Debug section

- [ ] **Step 1: Bump version**

In `fx-detect-os.sh`, replace line 111:

```bash
# Current:     readonly _OS_VERSION="1.5.0"
# New:
    readonly _OS_VERSION="1.6.0"
```

- [ ] **Step 2: Add `_OS_ERROR_LOG` to the README env-var table**

In `README.md`, after the `_OS_LOG_FILE` row in the Configuration variables table, insert:

```markdown
| `_OS_ERROR_LOG`  | NDJSON failure-log path (default: `<repo>/OSDetectFailureLog/osdetect-failures.jsonl`); set before `detect_os`. Created mode `0600` on first failure; a caller-supplied path is never chmod'd. Success runs write nothing. |
```

- [ ] **Step 3: Add the failure-log paragraph to README**

In `README.md`, after the existing debug-log vocabulary paragraph (ending with "must survive.") and before the `---` separator, insert:

```markdown
When `detect_os` cannot resolve an OS identity (rc 1), one NDJSON line is
appended to `OSDetectFailureLog/osdetect-failures.jsonl` (created mode
`0600` on first failure). The path is overridable via `_OS_ERROR_LOG`.
Each line records the full detection ladder (`steps[]` array), the final
`OS_*` field state (`finals{}`), and environment context; all values are
redacted before write. Parse with: `jq . OSDetectFailureLog/osdetect-failures.jsonl`.
```

- [ ] **Step 4: Update the README repository layout block**

In the README layout code block (around line 251), add the new directory:

```markdown
```
fx-detect-os.sh              # the library (source-only)
README.md                    # this file
docs/cheatsheet.md           # quick run/debug reference
OSDetectFailureLog/          # NDJSON failure log (created on first failure)
test/detect_os.bats          # bats-core integration suite (fixtures behind _OS_ROOT)
```
```

- [ ] **Step 5: Update the README test count**

In `README.md`, replace:

```bash
# Current:  bats test/detect_os.bats                      # 71 tests
# New:
bats test/detect_os.bats                      # 82 tests
```

- [ ] **Step 6: Add failure-log line to cheatsheet**

In `docs/cheatsheet.md`, after the existing redaction note in the Debug section, insert:

```markdown
Failure log: `OSDetectFailureLog/osdetect-failures.jsonl` (NDJSON, identity-unresolved only, `_OS_ERROR_LOG` override, `jq .` to parse).
```

- [ ] **Step 7: VERIFY GATE (final)**

Run:
```bash
bats test/detect_os.bats
bash -n fx-detect-os.sh
shellcheck -S style -x fx-detect-os.sh test/detect_os.bats
```
Expected: 82/82 PASS, version reads `1.6.0`, no shellcheck findings.

- [ ] **Step 8: Record in ledger**

Append a round-6 section to `.superpowers/sdd/progress.md` with: scope (failure log NDJSON), version 1.5.0 → 1.6.0, 71 → 82 tests, files changed, verification results.

---

## Self-Review Notes

**Spec coverage check:**
- ✅ NDJSON format — `_os_failure_record` writes JSON per spec schema
- ✅ `OSDetectFailureLog/` subfolder — `_os_error_log_path` default
- ✅ `_OS_ERROR_LOG` override — honored, never chmod'd
- ✅ Mode 0600 — `_os_ensure_error_log` sets when using default path
- ✅ Fail-open — `_os_failure_record` short-circuits on `_os_ensure_error_log` failure
- ✅ All values redacted — `_os_redact` on every source, detail, and finals field
- ✅ `_os_json_escape` dep-free — pure bash
- ✅ Capture table: all 5 ladder steps with descriptive `detail`
- ✅ 6 bats tests covering all spec test cases
- ✅ Version 1.6.0, README + cheatsheet updated

**No placeholders found. All code blocks complete. Type consistency verified across tasks.**

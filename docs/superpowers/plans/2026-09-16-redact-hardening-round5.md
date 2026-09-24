# Redaction S5 Fix (round-5) Implementation Plan

Status: EXECUTED
Date: 2026-09-16. No git (approved: "no git for now"). Plan location approved.
Target version: 1.5.0. Scope: T1-T3.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the round-4 S5 leak — a space-containing secret in `NAME=value` form leaked everything after its first space (`[REDACTED] val=1=x`) — and ship v1.5.0.

**Architecture:** Make pass 1 of `_os_redact` env-aware. The env scan already collects wordlist-matched exported values into `vals` (pass 2); additionally record `conf[${name,,}]="$val"` for every wordlist-named env var of any length. In pass 1's matched-name branch, build `full="${name}=${conf[${name,,}]-}"`; only when `full` is longer than the regex match AND the line at the match offset genuinely begins with `full`, redact the whole region; otherwise fall back to today's truncated-token redaction. The length-guard guarantees no-space values and divergent text take the identical round-4 path — byte-for-byte behavior preservation. Wordlist, pass 2, ≥4 floor, exported-only boundary: all unchanged.

**Tech Stack:** bash (≥4.2 regex/`${var,,}`/associative arrays), bats-core, shellcheck.

**Design doc:** `docs/superpowers/specs/2026-09-16-redact-hardening-round5-design.md` (APPROVED by user 2026-09-16).

## Global Constraints

- **No git** (user-approved "no git for now") → every task ends with VERIFY GATE: `bats test/detect_os.bats` + `bash -n fx-detect-os.sh` + `shellcheck -S style -x fx-detect-os.sh test/detect_os.bats`. No commit steps.
- Keep the file header promise: **no process substitution** in `fx-detect-os.sh`.
- All 68 round-4 tests pass **verbatim** (behaviors pinned: wordlist tiers, token scan, pass-2 longest-first, ≥4 embedded floor, unexported-name redaction). The S5 change must not alter a single output the round-4 tests already assert.
- Only `local` / `local -a` / `local -A` inside functions — no top-level `declare` (test harness sources the lib inside each test).
- `local -A` requires bash ≥4 (assoc arrays); project floor is ≥4.2 — satisfied.
- `fx-detect-os.sh` executable bit must remain `755` throughout (round-4 lesson: env drift stripped it).
- The matched-name branch that already emits `[REDACTED]` must NOT change its output text — only the consumption of `rest` (offset advance) may grow when the guarded full-value case wins.

---

### T1: S5 regression tests (write failing tests)

**Files:**
- Modify: `test/detect_os.bats` — insert 3 `@test` blocks after line 467 (the closing `}` of the `"redaction: debug log redacts '='-value and short psk through _os_log"` block), before line 469 (`@test "direct execution refuses with exit 2"`).

- [ ] **Step 1: Insert the three `@test` blocks exactly as below.**

```bats
@test "redaction: token value containing a space redacts whole (S5)" {
    lib
    SECRET_PROBE='probe val=1=x' run _os_redact "handling SECRET_PROBE=probe val=1=x now"
    [ "$status" -eq 0 ]
    [ "$output" = "handling [REDACTED] now" ]
    [[ "$output" != *"val=1=x"* ]]
}

@test "redaction: token falls back when line lacks the full env value (S5)" {
    lib
    TOKEN='probe val=1=x' run _os_redact "TOKEN=probe OTHER"
    [ "$status" -eq 0 ]
    [ "$output" = "[REDACTED] OTHER" ]
}

@test "redaction: _os_log catches space-containing secret value in log (S5 e2e)" {
    printf '%s\n' 'ID=e2e5' > "$_OS_ROOT/etc/os-release"
    export _OS_DEBUG=1 _OS_LOG_FILE="$BATS_TEST_TMPDIR/e2e5.log"
    export SECRET_PROBE='probe val=1=x'
    lib
    _os_log "cfg SECRET_PROBE=probe val=1=x tail"
    run grep -F 'val=1=x' "$_OS_LOG_FILE"
    [ "$status" -eq 1 ]
    run grep -F '[REDACTED]' "$_OS_LOG_FILE"
    [ "$status" -eq 0 ]
    rm -f "$_OS_LOG_FILE"
}
```

- [ ] **Step 2: VERIFY GATE (red — expected failures).**  Install the OS-Detect test harness (`bats test/detect_os.bats`). Expected: **2 FAIL, 69 PASS** — tests 1 and 3 FAIL on round-4 code (leak leaves ` val=1=x` → `[REDACTED]`) and actually fail; the fallback pin (test 2) ALREADY passes (`TOKEN=probe OTHER` → `[REDACTED] OTHER` on round-4 code) — it is a guard against over-redaction by the new branch, not a red test. Then `bash -n fx-detect-os.sh` (no syntax errors) and `shellcheck -S style -x fx-detect-os.sh test/detect_os.bats` (no new findings). Record results and deviations in the ledger (`.superpowers/sdd/progress.md`).

  Run: `bats test/detect_os.bats`
  Expected: 69 PASS (68 round-4 verbatim + the fallback pin), 2 FAIL (new S5 leak tests).

---

### T2: env-aware pass 1 (close the leak)

**Files:**
- Modify: `fx-detect-os.sh:250` (local decls), `fx-detect-os.sh:256-262` (env scan), `fx-detect-os.sh:249-300` (pass 1 branch), `fx-detect-os.sh:236-241` (pass 1 doc line).

**Interfaces:**
- Consumes: T1's three tests; `_os_secret_name` (unchanged, `fx-detect-os.sh:211-232`).
- Produces: `_os_redact` keeps its `printf '%s\n' "$line"` contract — tests call it via `run _os_redact "…"` and assert on `$output`; `_os_log` keeps passing its line through `_os_redact`.

- [ ] **Step 1: Add `full` and the associative map to the local declarations** (replace line 250-251).

Current (line 250-251):
```bash
    local line="$1" name val envline envout rest out m pre begin previous
    local -a vals=()
```
New:
```bash
    local line="$1" name val envline envout rest out m pre begin previous full
    local -a vals=()
    local -A conf=()
```

- [ ] **Step 2: Record every wordlist-named env value into `conf`, keyed case-folded** (replace lines 256-262).

Current:
```bash
    while IFS= read -r envline; do
        name="${envline%%=*}"
        val="${envline#*=}"
        if _os_secret_name "$name" && [ "${#val}" -ge 4 ]; then
            vals+=( "$val" )
        fi
    done <<< "$envout"
```
New:
```bash
    while IFS= read -r envline; do
        name="${envline%%=*}"
        val="${envline#*=}"
        if _os_secret_name "$name"; then
            conf[${name,,}]="$val"
            if [ "${#val}" -ge 4 ]; then
                vals+=( "$val" )
            fi
        fi
    done <<< "$envout"
```

- [ ] **Step 3: Guarded full-value redaction in pass 1's matched-name branch** (replace lines 285-292).

Current:
```bash
        if { [ "$begin" -eq 0 ] || [[ "$previous" != [A-Za-z0-9_] ]]; } \
            && _os_secret_name "${BASH_REMATCH[1]}"; then
            out+="[REDACTED]"
        else
            out+="${BASH_REMATCH[1]}=${BASH_REMATCH[2]}"
        fi
        rest="${rest:begin+${#m}}"
```
New:
```bash
        if { [ "$begin" -eq 0 ] || [[ "$previous" != [A-Za-z0-9_] ]]; } \
            && _os_secret_name "${BASH_REMATCH[1]}"; then
            out+="[REDACTED]"
            full="${BASH_REMATCH[1]}=${conf[${BASH_REMATCH[1],,}]-}"
            if [ "${#full}" -gt "${#m}" ] \
                && [[ "${rest:begin:${#full}}" == "$full" ]]; then
                rest="${rest:begin+${#full}}"
            else
                rest="${rest:begin+${#m}}"
            fi
        else
            out+="${BASH_REMATCH[1]}=${BASH_REMATCH[2]}"
            rest="${rest:begin+${#m}}"
        fi
```

- [ ] **Step 4: Update the pass-1 doc line** (replace lines 238-241).

Current:
```bash
#         1. NAME=value tokens at a whitespace boundary whose name matches
#            the wordlist are replaced in full by [REDACTED] — any value
#            length, so a secret stored as a short (<4-char) value is caught
#            when written as NAME=value.
```
New:
```bash
#         1. NAME=value tokens at a whitespace boundary whose name matches
#            the wordlist are replaced in full by [REDACTED] — any value
#            length, so a secret stored as a short (<4-char) value is caught
#            when written as NAME=value. When the checked env value (exported,
#            keyed by lowercased NAME) is in the line in full — including a
#            value containing spaces — the whole NAME=value region is
#            replaced; otherwise the truncated token is, as before.
```

- [ ] **Step 5: VERIFY GATE (green).** Run the battery and static checks. Expected: **71/71 PASS** (68 verbatim + 3 new), `bash -n` SYNTAX OK, shellcheck 0 findings, `fx-detect-os.sh` still `755`. Record results and deviations in the ledger.

  Run:
  ```bash
  bash -n fx-detect-os.sh && echo SYNTAX_OK
  shellcheck -S style -x fx-detect-os.sh test/detect_os.bats && echo SHELLCHECK_CLEAN
  bats test/detect_os.bats
  stat -c %a fx-detect-os.sh
  ```
  Expected: `SYNTAX_OK`, `SHELLCHECK_CLEAN`, **71 PASS / 0 FAIL**, `755`.

---

### T3: version bump + docs + S5 live smoke + verification record

**Files:**
- Modify: `fx-detect-os.sh:111` (version), `README.md:208-215` (redaction paragraph), `README.md:257` (test count), `docs/cheatsheet.md:54-58` (redaction footnote), `docs/superpowers/plans/2026-09-16-redact-hardening-round5.md` (Status → EXECUTED + verification record).

- [ ] **Step 1: Bump version** (line 111).

Current: `    readonly _OS_VERSION="1.4.0"`
New: `    readonly _OS_VERSION="1.5.0"`

- [ ] **Step 2: Update the README redaction paragraph** (lines 208-215).

Current:
```markdown
`jdbc_url`, … — matched case-insensitively): a `NAME=value` token at a
whitespace boundary whose name matches becomes `[REDACTED]` in full (any
value length, so short values are covered), and the values of
wordlist-named **exported** env vars (≥4 chars) are replaced wherever they
appear, longest value first. Values <4 chars embedded in prose stay
untouched so a common token like `/` or `1` cannot corrupt a line. Broad
`*url*`/`*uri*` patterns are deliberately not matched — public fields like
`HOME_URL` must survive.
```
New:
```markdown
`jdbc_url`, … — matched case-insensitively): a `NAME=value` token at a
whitespace boundary whose name matches becomes `[REDACTED]` in full (any
value length, so short values are covered; a value containing spaces is
matched in full via the checked env value), and the values of
wordlist-named **exported** env vars (≥4 chars) are replaced wherever they
appear, longest value first. Values <4 chars embedded in prose stay
untouched so a common token like `/` or `1` cannot corrupt a line. Broad
`*url*`/`*uri*` patterns are deliberately not matched — public fields like
`HOME_URL` must survive.
```

- [ ] **Step 3: Update the test-count line** (line 257).

Current: `bats test/detect_os.bats                      # 68 tests`
New: `bats test/detect_os.bats                      # 71 tests`

- [ ] **Step 4: Update the cheatsheet redaction footnote** (lines 54-58).

Current:
```markdown
Log file: mode 0600, two redaction passes driven by a secret-name wordlist
(case-insensitive): `NAME=value` tokens at a boundary whose name matches
(e.g. `pass`, `psk`, `database_url`) become `[REDACTED]` (any value length);
values of wordlist-named exported env vars (≥4 chars) are replaced wherever
they appear, longest first.
```
New:
```markdown
Log file: mode 0600, two redaction passes driven by a secret-name wordlist
(case-insensitive): `NAME=value` tokens at a boundary whose name matches
(e.g. `pass`, `psk`, `database_url`) become `[REDACTED]` (any value length;
space-containing values matched in full via the checked env value);
values of wordlist-named exported env vars (≥4 chars) are replaced wherever
they appear, longest first.
```

- [ ] **Step 5: S5 live smoke through `_os_log`.**

Run:
```bash
cd /mnt/LinData/LD/1-Linux/scripts/0-functions/OSDetect
tmp=$(mktemp)
_OS_DEBUG=1 _OS_LOG_FILE="$tmp" bash -c '. ./fx-detect-os.sh
export SECRET_PROBE="probe val=1=x"
detect_os >/dev/null
_os_log "handling config SECRET_PROBE=probe val=1=x now"
tail -n 1 "$tmp"
grep -qF "val=1=x" "$tmp" && echo "LEAK rc=0" || echo "CLEAN rc=1"
grep -qF "[REDACTED]" "$tmp" && echo "REDACTED_SEEN rc=0" || echo "NO_REDACT rc=1"
rm -f "$tmp"
```
Expected: log line ends `handling config [REDACTED] now`; `CLEAN rc=1` (no `val=1=x` anywhere); `REDACTED_SEEN rc=0`.

- [ ] **Step 6: Run the implementation plan verification (IPV).** Output of
  `bats test/detect_os.bats` full run (71 tests, must list every S5 test
  by name and PASS), `bash -n` result, shellcheck result, the smoke output
  block above (verbatim, with `detected=1 distro=<id>` and version line
  `ver=1.5.0`), recorded in the **verification record** appended at the end
  of this file. Then flip line 3 (`Status: IN PROGRESS` → `Status: EXECUTED`),
  update README live, and record the whole round in the ledger.

  Run:
  ```bash
  bash -c '. ./fx-detect-os.sh; detect_os; echo "ver=$_OS_VERSION detected=$? distro=${ID} src=${_OS_RELEASE_FILE:-?}"'
  ```
  Expected: `ver=1.5.0 detected=1 distro=CachyOS src=/etc/os-release`.

---

## Verification record

- T1 (tests): 3 S5 blocks inserted after test 42 (lines 467-495 in `test/detect_os.bats`). RED gate: `bats test/detect_os.bats` → `1..71`, **69 PASS / 2 FAIL** exactly as planned. Failing: test 43 (`"token value containing a space redacts whole (S5)"` line 473 `[ "$output" = "handling [REDACTED] now" ]` failed — output was `handling [REDACTED] val=1=x now`) and test 45 (line 491 `[ "$status" -eq 1 ]` failed — grep found `val=1=x` in the e2e log). Fallback pin (test 44) passed pre-fix as predicted. `bash -n fx-detect-os.sh` SYNTAX_OK; shellcheck 0 findings.
  - Deviation: one duplicate-insertion artifact (the file briefly held two copies of the S5 blocks after a partial subagent write) was removed before the RED run; the RED run above reflects the deduplicated file. No net content change.
- T2 (env-aware pass 1): `fx-detect-os.sh` — added `full` to the local decls, `local -A conf=()` map, env-scan records `conf[${name,,}]="$val"` for every wordlist-named env var (vals array unchanged, still ≥4 gated), pass-1 matched branch now tries `${conf[${BASH_REMATCH[1],,}]-}`; when `full` is longer than the regex match AND `rest[begin:${#full}]` equals `full`, consumes the whole region, else falls back to the truncated token. Doc comment updated. GREEN gate: `bash -n` OK, shellcheck `-S style -x` 0 findings, `bats test/detect_os.bats` → `1..71` **71/71 PASS** (all 68 round-4 tests verbatim + 3 S5), mode bit `755`.
- T3 (version + docs + smoke): `readonly _OS_VERSION="1.5.0"` at line 111; README paragraph gains "a value containing spaces is matched in full via the checked env value" + `# 71 tests`; cheatsheet footnote gains the space-value clause. S5 live smoke through `_os_log`:

  ```
  log line:   2026-09-16 20:06:22 handling config [REDACTED] now
  CLEAN rc=1  (grep -qF "val=1=x" → 1, no leak)
  REDACTED_SEEN rc=0  (grep -qF "[REDACTED]" → 0)
  ```

  IPV probe: `bash -c '. ./fx-detect-os.sh; detect_os; echo "ver=$_OS_VERSION rc=$? OS_DETECTED=${OS_DETECTED:-?} OS_ID=${OS_ID:-?}"'` → `ver=1.5.0 rc=0 OS_DETECTED=1 OS_ID=cachyos`.
  - Note: the round-4 verification-record smoke string `detected=1 distro=...` used a `detect_os` supporting both a return-code embedding and `OS_ID`; the round-5 IPV uses the canonical `OS_DETECTED/OS_ID` outputs, which is the stable contract. The S5 leak repro from round-4 (`[REDACTED] val=1=x`) is now fully `[REDACTED]`.
- Status flipped to EXECUTED. Version 1.5.0 shipped.
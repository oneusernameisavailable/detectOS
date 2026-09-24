# Redaction Hardening (C7, round-4) Implementation Plan

Status: EXECUTED
Date: 2026-09-16. No git (approved: "no git for now"). Plan location approved.
Target version: 1.4.0. Scope: T1-T4.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden `_os_redact` in `fx-detect-os.sh` (wordlist gaps, short-value floor, exported-only boundary, longest-first ordering, exact `=`-parse) and ship v1.4.0.

**Architecture:** Replace `_os_redact`'s single substring-value pass with two name-driven passes — a boundary-checked `NAME=value` token scan (any value length, plugs the <4-char floor and unexported-name gap) plus a longest-first embedded-value scan over wordlist-matched exported env vars (≥4 chars, unchanged floor). One helper, `_os_secret_name`, is the wordlist SSOT for both passes.

**Tech Stack:** bash (≥4.2 regex/`${var,,}`/arrays), bats-core, shellcheck.

**Design doc:** `docs/superpowers/specs/2026-09-16-redact-hardening-design.md` (APPROVED by user 2026-09-16).

## Global Constraints

- **No git** (user-approved "no git for now") → every task ends with VERIFY GATE: `bats test/detect_os.bats` + `bash -n fx-detect-os.sh` + `shellcheck -S style -x fx-detect-os.sh test/detect_os.bats`. No commit steps.
- Keep the file header promise: **no process substitution** in `fx-detect-os.sh`.
- Existing tests 325 (canary), 371 (uppercase names), 380 (short common values) pass **verbatim** — the ≥4 embedded floor is unchanged.
- Wordlist tiers (case-folded): substring `*pass* *token* *secret* *key* *cred* *auth* *cookie* *psk* *bearer* *otp* *mfa* *dsn* *jdbc* *conn*string* *connstr*`; exact `database_url database_uri redis_url redis_uri mongo_url mongo_uri mongodb_url mongodb_uri postgres_url postgres_uri pg_url pguri mysql_url mysql_uri elasticsearch_url elasticsearch_uri amqp_url rabbitmq_url kafka_url`. NOT `*url*`/`*uri*`/`*host*`/`*user*` (HOME_URL/BUG_REPORT_URL must survive). `jdbc_url` lives ONLY in the substring tier (dead under `*jdbc*`).
- Token scan: leftmost *maximal* identifier run `[A-Za-z_][A-Za-z0-9_]*` before `=`, starts at a line/space boundary; matching names are fully name-driven (`xdMYTOKEN` and `MY_TOKEN` both redact). For values containing a space, the token value stops at the first space (documented limitation; ≥4 values still caught by the embedded pass).
- Test harness conventions: `lib()` sources inside the test → all new code must avoid top-level `declare` (use `local` inside functions; round-3 lesson). `$BASH_REMATCH` and `local -a` are function-scope safe.
- Shellcheck: keep the cloa `case` in one place per tier; no dead patterns (SC2221/2222).

---

### T1: redaction behavior tests (write failing tests)

**Files:**
- Modify: `test/detect_os.bats` — insert 10 `@test` blocks after the existing redaction tests (after line 385, the `"redaction: short common values never corrupt log lines"` block; before the `"direct execution refuses with exit 2"` test at line 387).

- [ ] **Step 1: Insert the ten `@test` blocks exactly as below.**

```bats
@test "redaction: psk/bearer/otp/mfa/dsn/jdbc values are redacted" {
    lib
    PSK='psk-abcd-123def' BEARER='bearer-tok-9876' OTP='398812' MFA='987654' DSN='dbname=x' JDBC_URL='jdbc:postgresql://h:5432' run _os_redact "cfg psk-abcd-123def bearer-tok-9876 398812 987654 dbname=x jdbc:postgresql://h:5432"
    [ "$status" -eq 0 ]
    [ "$output" = "cfg [REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED]" ]
}

@test "redaction: connection-string var values are redacted (DATABASE_URL)" {
    lib
    DATABASE_URL='postgres://u:pw@h/db' run _os_redact "loaded postgres://u:pw@h/db from cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "loaded [REDACTED] from cfg" ]
}

@test "redaction: public URL fields (HOME_URL/BUG_REPORT_URL) stay intact" {
    lib
    HOME_URL='https://x.example' BUG_REPORT_URL='https://bugs/x.example' run _os_redact "home: https://x.example  bugs: https://bugs/x.example"
    [ "$status" -eq 0 ]
    [ "$output" = "home: https://x.example  bugs: https://bugs/x.example" ]
}

@test "redaction: short values redact in NAME=value context, bare values stay" {
    lib
    TOKEN=abc run _os_redact "TOKEN=abc"
    [ "$status" -eq 0 ]
    [ "$output" = "[REDACTED]" ]
    run _os_redact "/a/abc/"
    [ "$status" -eq 0 ]
    [ "$output" = "/a/abc/" ]
}

@test "redaction: a secret word anywhere in the NAME drives redaction" {
    lib
    run _os_redact " xdMYTOKEN=abc MY_TOKEN=abc "
    [ "$status" -eq 0 ]
    [ "$output" = " [REDACTED] [REDACTED] " ]
}

@test "redaction: '=' inside values is parsed exactly (no trailing residue)" {
    lib
    TOKEN='abcdef=' run _os_redact "cfg abcdef= tail"
    [ "$status" -eq 0 ]
    [ "$output" = "cfg [REDACTED] tail" ]
}

@test "redaction: longest value wins, no [REDACTED]def residuum" {
    lib
    KEY=abc TOKEN=abcdef run _os_redact "conn abcdef ready"
    [ "$status" -eq 0 ]
    [ "$output" = "conn [REDACTED] ready" ]
    [[ "$output" != *"def"* ]]
}

@test "redaction: value embedded in a URL is still redacted" {
    lib
    TOKEN=xyz789 run _os_redact "https://u:xyz789@h"
    [ "$status" -eq 0 ]
    [ "$output" = "https://u:[REDACTED]@h" ]
}

@test "redaction: multiple secret names in one line all redact" {
    lib
    DATABASE_URL='postgres://u:pw@h/db' run _os_redact "alpha MY_TOKEN=abc beta; DATABASE_URL=postgres://u:pw@h/db xMY_TOKEN=zz"
    [ "$status" -eq 0 ]
    [ "$output" = "alpha [REDACTED] beta; [REDACTED] [REDACTED]" ]
}

@test "redaction: debug log redacts '='-value and short psk through _os_log" {
    printf '%s\n' 'ID=e2e' > "$_OS_ROOT/etc/os-release"
    export _OS_DEBUG=1 _OS_LOG_FILE="$BATS_TEST_TMPDIR/e2e.log"
    export TOKEN='pa=ss' _OS_PSK='xy'
    lib
    _os_log "line with pa=ss and PSK=xy token"
    run grep -F 'pa=ss' "$_OS_LOG_FILE"
    [ "$status" -eq 1 ]
    run grep -F 'PSK=xy' "$_OS_LOG_FILE"
    [ "$status" -eq 1 ]
    run grep -F '[REDACTED]' "$_OS_LOG_FILE"
    [ "$status" -eq 0 ]
    rm -f "$_OS_LOG_FILE"
}
```

- [ ] **Step 2: Run the suite to confirm the new tests fail where they pin new behavior.**

Run: `bats test/detect_os.bats`
Expected: 58 of 58 existing tests PASS; of the 10 new tests, **7 FAIL** —
"psk/bearer/otp/mfa/dsn/jdbc", "connection-string", "short values (NAME=value
context)", "a secret word anywhere in the NAME", "`=` inside values (trailing
residue)", "multiple secret names", "debug log through _os_log". Tests
"public URL fields stay intact", "longest value wins" and "value embedded in
a URL" already hold under the old floor/order and stay green — they are
regression pins for the rewrite.

---

### T2: `_os_secret_name` + `_os_redact` rewrite

**Files:**
- Modify: `fx-detect-os.sh` — insert the `_os_secret_name` function + doc comment directly above the `# NAME  _os_redact` comment block (line 211), and replace the whole `_os_redact` doc comment (211-219) and body (220-233) with the code below.

- [ ] **Step 3: Replace `_os_redact` and add the helper (single contiguous block from line 211).**

```bash
# NAME  _os_secret_name
# ARGS  variable name
# WHAT  rc 0 iff NAME matches the secret wordlist (case-insensitive). The
#       variable NAME is the enforcement key here, in two tiers:
#         - substring words (pass/token/psk/jdbc/...) match names that
#           contain them anywhere;
#         - exact whole names (database_url, postgres_url, ...) catch the
#           connection-string family whose name carries the secret even
#           though it contains no "secret" word.
#       Broad *url*/*uri* patterns are deliberately excluded: public
#       os-release fields HOME_URL/BUG_REPORT_URL/SUPPORT_URL would match
#       and their values would be eaten out of legitimate log lines.
_os_secret_name() {
    local name="${1,,}"
    case "$name" in
        *pass*|*token*|*secret*|*key*|*cred*|*auth*|*cookie*|*psk*|*bearer*|*otp*|*mfa*|*dsn*|*jdbc*|*conn*string*|*connstr*)
            return 0 ;;
        database_url|database_uri|redis_url|redis_uri|mongo_url|mongo_uri|mongodb_url|mongodb_uri|postgres_url|postgres_uri|pg_url|pguri|mysql_url|mysql_uri|elasticsearch_url|elasticsearch_uri|amqp_url|rabbitmq_url|kafka_url)
            return 0 ;;
    esac
    return 1
}

# NAME  _os_redact
# ARGS  one line of text
# WHAT  redacts secret material from the line and prints the (possibly
#       unchanged) line. Two passes, both name-driven via _os_secret_name:
#         1. NAME=value tokens at a whitespace boundary whose name matches
#            the wordlist are replaced in full by [REDACTED] — any value
#            length, so a secret stored as a short (<4-char) value is caught
#            when written as NAME=value.
#         2. The values of wordlist-matched env vars (>=4 chars) are replaced
#            wherever they appear, longest value first, so a short prefix
#            value cannot leave a [REDACTED]def residuum behind.
#       env() is exported-only; that is the documented enforcement boundary
#       (unexported shell vars are invisible here). Values shorter than 4
#       chars embedded in prose stay untouched so a common token like "/" or
#       "1" cannot corrupt every log line.
_os_redact() {
    local line="$1" name val envline envout rest out m pre begin previous
    local -a vals=()
    # env() is captured into a here-string instead of `done < <(env)`: the
    # header promises no process substitution, and the substitution would make
    # the loop a pipeline subshell, silently dropping the edits to `line`.
    envout="$(env)" 2>/dev/null || envout=""
    while IFS= read -r envline; do
        name="${envline%%=*}"
        val="${envline#*=}"
        if _os_secret_name "$name" && [ "${#val}" -ge 4 ]; then
            vals+=( "$val" )
        fi
    done <<< "$envout"
    # Insertion sort, longest value first.
    local i j current
    for (( i = 1; i < ${#vals[@]}; i++ )); do
        current="${vals[i]}"
        (( j = i - 1 ))
        while (( j >= 0 && ${#current} > ${#vals[j]} )); do
            vals[j+1]="${vals[j]}"
            (( j-- ))
        done
        vals[j+1]="$current"
    done
    # Pass 1: name-context token scan (leftmost maximal identifier run before
    # `=`; the run must start at a line/space boundary).
    rest="$line"
    out=""
    while [[ $rest =~ ([A-Za-z_][A-Za-z0-9_]*)=([^[:space:]]*) ]]; do
        m="${BASH_REMATCH[0]}"
        pre="${rest%%"$m"*}"
        begin=${#pre}
        previous=""
        [ "$begin" -gt 0 ] && previous="${rest:begin-1:1}"
        out+="$pre"
        if { [ "$begin" -eq 0 ] || [[ "$previous" != [A-Za-z0-9_] ]]; } \
            && _os_secret_name "${BASH_REMATCH[1]}"; then
            out+="[REDACTED]"
        else
            out+="${BASH_REMATCH[1]}=${BASH_REMATCH[2]}"
        fi
        rest="${rest:begin+${#m}}"
    done
    line="$out$rest"
    # Pass 2: embedded value replacement (>=4 chars), longest first.
    local v
    for v in "${vals[@]}"; do
        line="${line//"$v"/[REDACTED]}"
    done
    printf '%s\n' "$line"
}
```

- [ ] **Step 4: Run the full suite — all 68 tests pass.**

Run: `bats test/detect_os.bats`
Expected: **68/68 PASS** (58 pre-existing incl. 325/371/380 verbatim + 10 new).

- [ ] **Step 5: VERIFY GATE**

```bash
bash -n fx-detect-os.sh
# Expected: SYNTAX OK (no output, rc 0)

shellcheck -S style -x fx-detect-os.sh test/detect_os.bats
# Expected: 0 findings on both files (the .bats file clears at its top via
# the existing SC1091/SC2154/SC2030/SC2031 disables; the .sh code above was
# prototyped against shellcheck and is clean apart from no-file shebang noise
# which does not apply inside the library file).
```

---

### T3: version bump + docs

**Files:**
- Modify: `fx-detect-os.sh:111` — `readonly _OS_VERSION="1.4.0"`.
- Modify: `README.md:201-205` (redaction paragraph) and `README.md:247` (`# 58 tests`).
- Modify: `docs/cheatsheet.md:54-58` (redaction footnote).

- [ ] **Step 6: Version bump.**

`readonly _OS_VERSION="1.3.0"` → `readonly _OS_VERSION="1.4.0"`.

- [ ] **Step 7: README redaction paragraph (replace the block at lines 201-205).**

```markdown
Debug log vocabulary (greppable): `==== START`, `=== STAGE: <x>`,
`ENTER <fn>` / `EXIT <fn>`, `EXEC: <cmd>` / `RC=<n>`, `!! ERROR`,
`---- STATE DUMP` … `---- END STATE DUMP`. Two redaction passes run before
any line is written, both driven by a secret-name wordlist (substring words
`pass`, `token`, `secret`, `key`, `cred`, `auth`, `cookie`, `psk`, `bearer`,
`otp`, `mfa`, `dsn`, `jdbc`, `conn*string`, `connstr`; exact names
`database_url`, `postgres_url`, `redis_url`, `mongo_url`, `mysql_url`,
`jdbc_url`, … — matched case-insensitively): a `NAME=value` token at a
whitespace boundary whose name matches becomes `[REDACTED]` in full (any
value length, so short values are covered), and the values of
wordlist-named **exported** env vars (≥4 chars) are replaced wherever they
appear, longest value first. Values <4 chars embedded in prose stay
untouched so a common token like `/` or `1` cannot corrupt a line. Broad
`*url*`/`*uri*` patterns are deliberately not matched — public fields like
`HOME_URL` must survive.
```

- [ ] **Step 8: README test count.**

`bats test/detect_os.bats                      # 58 tests` → `# 68 tests`.

- [ ] **Step 9: cheatsheet footnote (replace lines 54-58).**

```markdown
Log file: mode 0600, two redaction passes driven by a secret-name wordlist
(case-insensitive): `NAME=value` tokens at a boundary whose name matches
(e.g. `pass`, `psk`, `database_url`) become `[REDACTED]` (any value length);
values of wordlist-named exported env vars (≥4 chars) are replaced wherever
they appear, longest first. Values <4 chars in prose are left alone so `/`
or `1` never corrupt a line. `*url*`/`*uri*` are not matched (`HOME_URL`
stays). Vocabulary: `==== START`, `=== STAGE: x`, `ENTER f`/`EXIT f`,
`EXEC:`/`RC=n`, `!! ERROR`, `---- STATE DUMP`.
```

- [ ] **Step 10: VERIFY GATE**

```bash
bats test/detect_os.bats        # -> 68/68 ok (README count matches)
grep -n '_OS_VERSION=' fx-detect-os.sh            # -> "1.4.0"
grep -n '68 tests' README.md                      # -> 1 hit
bash -n fx-detect-os.sh
shellcheck -S style -x fx-detect-os.sh test/detect_os.bats
```

---

### T4: full verification battery

- [ ] **Step 11: Full battery (round-3 gates).**

```bash
bats test/detect_os.bats                   # -> 68/68 ok
bash -n fx-detect-os.sh                    # -> SYNTAX OK
shellcheck -S style -x fx-detect-os.sh test/detect_os.bats   # -> clean
```

- [ ] **Step 12: Live smoke (host, not a fixture).**

```bash
_OS_DEBUG=1 bash -c '
  . ./fx-detect-os.sh
  export SECRET_PROBE="probe val=1=x"
  detect_os
  printf "ver=%s detected=%s distro=%s src=%s\n" "$_OS_VERSION" "$OS_DETECTED" "$OS_DISTRO" "$OS_SOURCE"
'
grep -F 'probe val=' "${_os_log_file:-}" 2>/dev/null
# Expected: ver=1.4.0 detected=1 distro=<host distro> src=<host src>; the
# grep for the probe string must return NOTHING (it reaches the log only as
# [REDACTED]), while os-release identity fields still appear in the dump.
```

- [ ] **Step 13: Record the verification record + mark plan EXECUTED.**

Append a `## Verification record (YYYY-MM-DD)` section to this plan (mirroring the round-3 plan, which recorded actual command outputs, the read-back of any discovered deviation, and set `Status: EXECUTED`). Then flip the `Status:` line at the top of this file to `EXECUTED`.

---

## Notes (recorded during design)

- Prototype validated in `/tmp` before writing this plan: all 10 tests' expected outputs reproduced exactly under `set -u`; `shellcheck -S style -x` clean on the implementation; `bash -n` SYNTAX OK.
- The spec's original "IFS read truncates `=` values" rationale was wrong (`read -r name val` with `IFS='='` actually recovers interior `=`, `A=b=c` → `val=b=c`); the real defect is at the trailing edge (`A=b=` → `val=b`, dropping the `=`). Spec amended; test 6 pins the trailing-edge behavior.
- `jdbc_url` removed from the exact-name tier in both spec and implementation (SC2221/2222: dead under `*jdbc*`).
- Token scan implements "name-driven": `xdMYTOKEN=…`, `MY_TOKEN=…`, `MYTOKEN=…` all redact because the maximal identifier contains a wordlist word; a bare value (no `NAME=`) is never a target of pass 1, and `/`/`1` floors are preserved by pass 2's ≥4 gate.
- Bash `=~` greediness pitfall (documented for the executor): a `(.*)` tail group or `(.*[[:space:]]|^)` greedy prefix makes `BASH_REMATCH[0]` absorb wrong text; the plan uses a no-tail-capture leftmost match + `${rest%%"$m"*}`-derived offset (quoted literal, safe with globs in values).

## Verification record (2026-09-16)

**Battery (Step 11) — actual outputs:**

- `bats test/detect_os.bats` → `1..68` … `ok 68`, **68/68 PASS**, rc 0. Breakdown: 58 pre-existing (incl. canary 325, uppercase 371, short-common 380 verbatim) + 10 new T1 blocks (tests 33-42) + prior rounds' additions. No failures, no skips.
- `bash -n fx-detect-os.sh` → no output, rc 0 (SYNTAX OK).
- `shellcheck -S style -x fx-detect-os.sh test/detect_os.bats` → no findings on either file, rc 0.

**Live smoke (Step 12) — adapted for log-path capture, actual outputs:**

The brief's trailing `grep -F 'probe val=' "${_os_log_file:-}"` searches an empty name because `_os_log_file` is assigned inside the `bash -c` subshell and is not visible in the outer shell. Adapted: the log path is announced inside the same `bash -c` (the library's own `osdetect debug log:` stderr line, plus an explicit `probe_log_path=` marker), and the probe grep runs against that captured path afterwards.

```
$ _OS_DEBUG=1 bash -c '
    . ./fx-detect-os.sh
    export SECRET_PROBE="probe val=1=x"
    detect_os
    printf "SMOKE_EOF probe_log_path=%s\n" "${_os_log_file:-<none>}" >&2
    printf "ver=%s detected=%s distro=%s src=%s\n" "$_OS_VERSION" "$OS_DETECTED" "$OS_DISTRO" "$OS_SOURCE"
  '
osdetect debug log: /tmp/osdetect.drH0MG
SMOKE_EOF probe_log_path=/tmp/osdetect.drH0MG
ver=1.4.0 detected=1 distro=CachyOS src=/etc/os-release
SMOKE_RC=0
```

- `grep -F 'probe val=' /tmp/osdetect.drH0MG` → **NOTHING, rc 1** (probe string absent from the log). Host run, real distro: `ver=1.4.0 detected=1 distro=CachyOS src=/etc/os-release` — matches expected host reality.
- State dump identity fields present in the log: `OS_ID=cachyos`, `OS_ID_LIKE=arch`, `OS_NAME=CachyOS Linux`, `OS_PRETTY_NAME=CachyOS`, `OS_DISTRO=CachyOS`, `OS_SOURCE=/etc/os-release` (`OS_VERSION` empty on this host). `[REDACTED]` count in the dump: **0** — during detection itself no logged line carries a secret value, so the probe never reaches the log on the plan's path (its absence is therefore trivially verified there).
- Supplementary probe-through-`_os_log` check (to make the "only as [REDACTED]" clause non-vacuous): fed `_os_log "handling config SECRET_PROBE=probe val=1=x now"` into a second host run → log line became `2026-09-16 00:49:13 handling config [REDACTED] val=1=x now`. Full probe string absent (rc 1) and `SECRET_PROBE=` absent (rc 1), but see finding S5 below — the first-space tail survives.

**Deviations read-back (from `progress.md` ledger + this round):**

1. **Ledger (T2, env drift):** `fx-detect-os.sh` lost its executable bit mid-session; restored to 755 as part of Task 2. Environment drift, not a code change.
2. **Ledger (T3):** README prose lists `jdbc_url` among the "exact names" while the code keeps it only in the substring tier via `*jdbc*` — behaviorally equivalent (still redacts), plan-mandated verbatim text.
3. **Ledger (review minors, plan-mandated):** T1 single cleanup path `test/detect_os.bats:467` (bats tmpdir auto-clears); T2 cosmetic pass-2 could re-wrap an already-printed literal `[REDACTED]` → `[[REDACTED]]`.
4. **Newly found during this verification (S5):** when a space-containing secret value is logged in `NAME=value` form, pass 1 (line 274-293) replaces only up to the first space *and mutates `line` before pass 2 runs* (`line="$out$rest"`, line 293); pass 2's literal value scan then cannot find the intact value, so the first-space tail persists in plaintext (`[REDACTED] val=1=x now`, leaking `val=1=x`). This contradicts the plan's documented claim "≥4 values still caught by the embedded pass" for the `NAME=value`+space combination, and is not covered by the test suite (tests 1 and 42 use values without spaces). **No code change made** — verification task, out of scope; flagged for a future round.

No git (user-approved): no commits; record kept in this plan + `.superpowers/sdd/`.
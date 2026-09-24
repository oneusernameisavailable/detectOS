# Design — Redaction S5 fix: space-containing secret values (round-5)

Status: APPROVED
Date: 2026-09-16. No git (approved: "no git for now"). Baseline: round-4
spec `docs/superpowers/specs/2026-09-16-redact-hardening-design.md` and the
round-4 plan (EXECUTED, verification record appended).
Target version: 1.5.0.

## Problem (S5, found by round-4 verification)

A secret whose value **contains a space**, logged in `NAME=value` form, leaks
everything after the first space:

```
$ _OS_DEBUG=1 bash -c '. ./fx-detect-os.sh; export SECRET_PROBE="probe val=1=x";
  _os_log "handling config SECRET_PROBE=probe val=1=x now"'
log line:
  handling config [REDACTED] val=1=x now     # tail "val=1=x" leaks plaintext
```

Cause, cut down to the mechanism: pass 1 truncates the value at the first
space (`[^[:space:]]*`, fx-detect-os.sh) and replaces `NAME=probe` with
`[REDACTED]`, mutating the line **before** pass 2 runs. Pass 2 is a literal
substitution of intact env values (`probe val=1=x`), and the intact value no
longer appears in the line, so pass 2 cannot re-find it; the remainder
` val=1=x` stays in plaintext.

The round-4 plan claimed "values containing a space… ≥4 values **still caught
by the embedded pass**"; that claim is false for the NAME=value + space
combination. Verified live; recorded as finding S5 in the round-4 plan's
verification record.

## Decision (user-approved)

**Approach A** — make pass 1 **env-aware**: when a boundary-clean token name
matches the wordlist, look up the checked env value for that name and replace
the **full** value (spaces included) instead of the truncated token, but only
when the line genuinely contains the full env value at the token position.
Approach B (running pass 2 before pass 1) was considered and rejected by the
user; behavior must otherwise remain byte-for-byte identical.

## Change (fx-detect-os.sh only)

1. Env scan: alongside the existing ≥4-char `vals` array (pass 2), build
   `conf[${name,,}]="$val"` for **every** wordlist-named env var, of any
   length — a case-folded name → value map used only by pass 1. Local to the
   function; `local -A` (associative array, bash 4+, already in the project's
   bash ≥4.2 floor). No top-level `declare` (harness constraint).

2. Pass 1, matched-name branch (boundary-clean AND wordlist match):
   - `full="${name}=${conf[${name,,}]-}"`
   - If `${#full}` is **greater than** the regex match length (`$m`) **and**
     the line at offset `begin` starts with `full` exactly
     (`[[ "${rest:begin:${#full}}" == "$full" ]]`), then redact the whole
     region: `out+="[REDACTED]"`, `rest="${rest:begin+${#full}}"`.
   - Else fall back to today's behavior: `out+="[REDACTED]"`,
     `rest="${rest:begin+${#m}}"` (the truncated token).
   - Non-matching names: unchanged (echo `name=value`, advance by `$m`).

Semantics guaranteed by the guard:
- No-space value: `full` equals `$m`; `full` not longer → identical path to
  today. Zero behavior change for all round-4 tests.
- Space value present verbatim in the line at the right place: whole
  `NAME=full value` redacted; nothing leaks.
- Space value NOT present (line shows a different value, or text diverges
  after the first space): truncated-token fallback — never over-redacts
  prose, never eats characters that aren't really the secret value.
- Different case in line vs env (`secret_probe=` line, `SECRET_PROBE` env):
  `conf` key is `name,,` normalised, so the lookup is case-insensitive; the
  emitted `full` uses the token's own case from the line.
- Name not in env (unexported or non-secret-shaped): `${conf[...]-}` yields
  empty → `full` is just `"name="`, shorter than `$m` → fallback. Existing
  unexported behavior (round-4 test "a secret word anywhere in the NAME")
  unchanged.

## Tests (test/detect_os.bats, +3 → 68 → 71)

1. **Token S5** — `SECRET_PROBE='probe val=1=x' run _os_redact "handling SECRET_PROBE=probe val=1=x now"`:
   `[ "$status" -eq 0 ]`, `[ "$output" = "handling [REDACTED] now" ]`,
   `[[ "$output" != *"val=1=x"* ]]`.
2. **Fallback pin** — `TOKEN='probe val=1=x' run _os_redact "TOKEN=probe OTHER"`:
   `[ "$status" -eq 0 ]`, `[ "$output" = "[REDACTED] OTHER" ]` (line does not
   contain the full env value → no over-redaction, truncated token redacted).
3. **`_os_log` e2e (practical proof)** — mirror round-4 test 42 staging:
   `printf '%s\n' 'ID=e2e5' > "$_OS_ROOT/etc/os-release"`;
   `export _OS_DEBUG=1 _OS_LOG_FILE="$BATS_TEST_TMPDIR/e2e5.log"`;
   `export SECRET_PROBE='probe val=1=x'`; `lib`; `_os_log "cfg SECRET_PROBE=probe val=1=x tail"`;
   `run grep -F 'val=1=x' "$_OS_LOG_FILE"` → rc 1; `run grep -F '[REDACTED]' "$_OS_LOG_FILE"` → rc 0;
   `rm -f "$_OS_LOG_FILE"`.

## Docs + version

- `fx-detect-os.sh`: `readonly _OS_VERSION="1.5.0"`.
- `_os_redact` doc comment: update pass-1 description ("a `NAME=value` token
  at a boundary whose name matches is replaced in full — the checked env
  value when the line contains it (covers values containing spaces), else
  the truncated token").
- README redaction paragraph + cheatsheet footnote: one clause noting
  space-containing `NAME=value` secrets are caught in full via the checked
  env value.
- README test count → `# 71 tests`.
- Plan header gets its own round-5 Status: line.

## Acceptance criteria

- 71/71 bats PASS (68 round-4 verbatim + 3 new).
- S5 live repro (the failing smoke from round-4 verification) now logs the
  whole probe as `[REDACTED]` — i.e. `grep -F 'val=1=x'` on the log returns
  rc 1 and `grep -F '[REDACTED]'` on the log returns rc 0.
- `bash -n fx-detect-os.sh` SYNTAX OK; `shellcheck -S style -x` clean on
  both files.
- No change to: wordlist tiers, pass-2 algorithm, ≥4 floor, exported-only
  boundary, harness constraints (no process substitution, no top-level
  `declare`).

## Out of scope

- Approach B / any pass reordering.
- The `[REDACTED]`-literal re-wrap cosmetic (round-4 plan verification
  record minor).
- Any wordlist additions.
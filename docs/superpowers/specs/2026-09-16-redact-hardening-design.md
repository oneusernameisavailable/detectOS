# Design — Hardening `_os_redact` (C7, round-4)

Status: APPROVED (design read-back accepted by user)
Date: 2026-09-16. No git (user-approved "no git for now").
Target version: 1.4.0 (additive hardening, non-breaking).

## Problem

`fx-detect-os.sh` redacts secret values from the debug log via `_os_redact`
(fx-detect-os.sh:220). Round-3 RedTeam flagged three gaps (C7, explicitly
deferred until now):

1. **Wordlist gaps** — secrets in vars whose name doesn't contain
   `pass|token|secret|key|cred|auth|cookie` leak. Notably connection strings
   like `DATABASE_URL='postgres://user:pass@host/db'` never redact because the
   var *name* doesn't match and the embedded password is never seen.
2. **Short-value floor** — values shorter than 4 chars are never replaced, so
   a 1-3 char secret escapes. The floor exists so common tokens (`/`, `1`)
   cannot corrupt every log line; it is kept, but a name-context rule plugs the
   leak.
3. **Exported-only enumeration** — the scan reads `env`, so unexported shell
   vars are invisible.

Plus two mechanical smells found while reading the current code:

4. Replacement order is not longest-first: with `KEY=abc` and `TOKEN=abcdef`
   both exported, replacing `abc` first corrupts `abcdef` to `[REDACTED]def`.
5. `IFS='=' read -r name val` truncates env values that contain `=`
   (`A=b=c` parses as name=A, val=b; the `=c` is dropped).

## Scope decisions (user-approved)

- Strength: **balanced** — keep the ≥4 embedded floor; add name-context rule
  for short values; curated wordlist; fix mechanical issues.
- Enumeration: **exported-env is the boundary** (Q2-A). No `declare -p`
  parsing of unexported vars (fragile quoting/newline forms). Documented
  boundary.
- Wordlist: **curated low-FP additions only** (Q3-A). Broad `*url*` / `*uri*`
  patterns rejected explicitly (`HOME_URL`, `BUG_REPORT_URL`, `SUPPORT_URL`
  are public os-release fields; value-replacement of those values would corrupt
  legitimate log fragments).

## Design

### 1. `_os_redact` core upgrades (single function)

Rewrite of `_os_redact` body; signature, stdout line, and rc 0 contract are
unchanged. New pipeline:

1. **Capture env** — `envout="$(env)"` (unchanged; no process substitution per
   the file's header promise).
2. **Accurate parse + collect** — per env line: `name="${line%%=*}";
   val="${line#*=}"`. `IFS='=' read` is edge-lossy here (trailing `=` and
   empty-value shapes round-trip ambiguously); the parameter-expansion parse
   is exact. When `name` matches `_os_secret_name`, record the value as an
   embedded-replacement candidate.
3. **Name-context scan (token-based)** — walk the line for identifier tokens
   `(^|[[:space:]])[A-Za-z_][A-Za-z0-9_]*=` and replace each whole
   `ID=value` token whose ID matches `_os_secret_name` with `[REDACTED]`,
   any value length. Implementation: a bash-regex while loop over
   `(^|[[:space:]])([A-Za-z_][A-Za-z0-9_]*)=([^[:space:]]*)(.*)`; the matched
   ID is tested via `_os_secret_name` (no user-value interpolation into the
   pattern, so no regex-escaping helper is needed). This is what plugs the
   short-value floor *and* the unexported gap (Q2-A): any wordlist-named
   variable written as `NAME=value` in a line is redacted whether or not an
   env variable of that name exists.
   - Boundary semantics: the token's `ID=` prefix must start at a line/space
     boundary (`xMY_TOKEN=…` *is* a whole identifier starting at a boundary,
     so it is still redacted — the match is name-driven, not value-driven);
     a bare value with no preceding wordlist-named identifier is never
     touched by this pass.
   - Limitation (documented): the token value ends at the next whitespace, so
     an exotic value containing a space inside a line-written `NAME=value`
     redacts up to that space only (≥4-char values are still fully caught by
     the embedded scan below, which is space-agnostic).
4. **Longest-first embedded replacement** — process recorded values in
   descending length order; for values with length ≥ 4 do the existing
   `${line//"$val"/[REDACTED]}` substring replacement (space-agnostic, catches
   values buried in URLs/prose).
5. Print the (possibly changed) line. rc 0.

Helper extraction (one new function, `_os_`-prefixed):
- `_os_secret_name NAME` — rc 0 iff the (case-folded) name matches the
  wordlist (Section 2). SSOT for the list, used by both the env-collect pass
  and the name-context scan.

### 2. Wordlist SSOT in `_os_secret_name`

Case-folded (`$name` lowercased). Two tiers in one `case` on `$name`:

- Substring patterns (existing six + new low-FP forms):
  `*pass* *token* *secret* *key* *cred* *auth* *cookie*`
  `*psk* *bearer* *otp* *mfa* *dsn* *jdbc* *conn*string* *connstr*`
- Exact whole-name additions (bare names match exactly):
  `database_url database_uri redis_url redis_uri mongo_url mongo_uri
  mongodb_url mongodb_uri postgres_url postgres_uri pg_url pguri mysql_url
  mysql_uri elasticsearch_url elasticsearch_uri amqp_url
  rabbitmq_url kafka_url`
  (`jdbc_url` intentionally lives only in the substring tier: `*jdbc*`
  already covers it, and listing it again is dead code.)

Not added (deliberately): `*url*` / `*uri*` / `*host*` / `*user*`.

### 3. Corruption guarantees

- ≥4 char embedded floor unchanged; existing test "redaction: short common
  values never corrupt log lines" passes verbatim.
- Name-context redaction fires only on a wordlist-matching identifier
  (`ID=value` token); a bare embedded value is never a target of this pass
  (long bare values are still handled by the embed scan, short ones left
  alone — the floor's original corruption protection).
- Longest-first ordering prevents a short prefix value from truncating a
  longer brother secret.
- `=`-in-value parsed exactly, so `TOKEN=pa=ss` yields value `pa=ss` (never
  truncated to `pa`), and embedded redaction removes the whole value.

### 4. Tests (bats, ~10 new)

Run through `lib` + `_os_redact` / `_os_log`:

1. `PSK=...` `BEARER=...` `OTP=...` `MFA=...` `DSN=...` `JDBC_URL=...` values
   redacted when present in a line (≥4 char).
2. `DATABASE_URL='postgres://user:pass@host/db'` value redacted when it appears
   in a line.
3. Exact-name FP guard: `HOME_URL` / `BUG_REPORT_URL` (broad-url names NOT in
   list) values are left intact even when present in a line.
4. Short name-context redaction: exported `TOKEN=abc`, line `TOKEN=abc` →
   `[REDACTED]`; line `/a/abc/` (no `NAME=` token, bare value) → unchanged.
5. Token semantics: `MYTOKEN=abc` (ID contains `token`) → redacted;
   `MY_TOKEN=abc` → redacted; `xMY_TOKEN=abc` → redacted (whole-identifier
   match, name-driven); `HOME_URL=v` → unchanged (broad `*url*` rejected).
6. `=`-in-value parse is exact at the trailing edge (where `IFS='=' read`
   drops a trailing `=`): exported `TOKEN='abcdef='`, line `cfg abcdef= tail`
   → `cfg [REDACTED] tail` (an old parse yields the wrong `cfg [REDACTED]=
   tail`).
7. Longest-first: `KEY=abc` + `TOKEN=abcdef`, line contains `abcdef` →
   `[REDACTED]`, no `def` residuum in output.
8. Embedded-URL redaction still works (`TOKEN=xyz789`,
   line `https://u:xyz789@h` → `[REDACTED]`).
9. End-to-end `_os_log`: `_OS_DEBUG=1` + exported `SECRET_*` canary value
   written into a real log file → file contains `[REDACTED]`, not the canary
   (existing canary test stays green, so this is additive coverage of the
   `=`-in-value + longest-first paths through the real logger).
10. Existing tests 371/380 unchanged and still green.

Expected count: 58 + 10 = 68 (confirm exact number after implementation).

### 5. Version + docs

- Version bump to 1.4.0 at the `_OS_VERSION` site.
- README: rewrite the redaction note in "Debug log vocabulary": wordlist
  patterns + exact-name tier, ≥4 embedded floor (+ name-context exception),
  longest-first ordering, exported-env boundary, and the `HOME_URL`-not-redacted
  rationale. Update validation test count.
- docs/cheatsheet.md: update the redaction footnote (same substance, shorter).

### Out of scope

- Unexported-variable enumeration via `declare -p` (rejected, Q2-A).
- Broad `*url*`/`*uri*`/`*host*`/`*user*` patterns (rejected, Q3-A).
- Any change to collision/dump/ladder machinery.

## Acceptance criteria

- `bats test/detect_os.bats` all green (58 existing + ~10 new).
- `bash -n fx-detect-os.sh` clean; `shellcheck -S style -x` clean on .sh and
  .bats (same gates as round 3).
- Live smoke: `_OS_DEBUG=1`, source, `detect_os`, then grep the log for a
  canary value in an exported `SECRET_*` name with a `=` inside it and confirm
  `[REDACTED]`; confirm normal paths (`/etc/os-release`) intact.
- Existing log-corruption test (380) passes verbatim.
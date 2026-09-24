# Design — Permanent AI-readable failure log (round-6)

Status: APPROVED
Date: 2026-09-16. No git (approved: "no git for now"). Baseline: v1.5.0
`fx-detect-os.sh` (rounds 1-5 EXECUTED). Target version: 1.6.0.

## Problem

When `detect_os` fails to resolve an OS identity (rc 1, `OS_ID` empty), the
reason is visible only inside the debug trace (temp file, off unless
`_OS_DEBUG=1`). There is no permanent, descriptive, machine-readable record
that explains the failure trail for later batch troubleshooting by an AI.

## Decision (user-approved, brainstorming round-6)

Write an NDJSON failure log: one JSON object per failed `detect_os` run,
only for the `identity-unresolved` outcome. Success runs write nothing.
Readonly-collision aborts are NOT logged (for now). No size cap (failures
expected to be rare). Format NDJSON because the reader is an AI (jq and
line-grep parse it trivially); schema below is small and extensible.

Every log line must be safe to hand to an AI: all values are passed through
`_os_redact` before JSON-encoding (permanent log, secrets must never land).

## File location

- Default: `<repo>/OSDetectFailureLog/osdetect-failures.jsonl`
  resolved as `"$(dirname "${BASH_SOURCE[0]}")/OSDetectFailureLog/osdetect-failures.jsonl"`
  so it works regardless of which consumer sourced the library.
- Override: `_OS_ERROR_LOG=/path/to/file` (relative paths resolved against
  the caller's cwd). Bare `_OS_ERROR_LOG=` (empty) keeps the default.
- Created lazily on the first recorded failure: `mkdir -p` the directory
  and create the file with mode 0600. Never chmod a caller-supplied path
  (same policy as `_OS_LOG_FILE`).
- Append one line per event; no rotation, no cap, no re-parse.

## Capture (detect_os, fx-detect-os.sh:960-995)

While the ladder runs, collect one step record per source into a
run-scoped local array. Record even step-by-step rc, plus a descriptive
`detail` giving the AI the place to look:

| step source        | detail content (what the AI should go check)            |
|--------------------|---------------------------------------------------------|
| `os-release`       | `f_e` and `f_u` effective paths + which yielded/denied  |
| `lsb-release`      | effective path; absent vs present-but-NoID              |
| `lsb_release-cmd`  | `_OS_LSBRELEASE` present? `_OS_ROOT` guard? run rc      |
| `legacy`           | whether `/etc/*-release` files existed & matched        |
| `uname-fallback`   | `$_OS_UNAME` present? reached (no prior hit)? rc        |

Each detail string names the actual paths/probes consulted so the AI knows
where to look to troubleshoot. On unresolved (`[ -z "${OS_ID:-}" ]` after
the ladder), emit the event; otherwise discard the collected array.

## Event schema (one line)

```json
{"ts":"2026-09-16T20:06:22Z","pid":1234,"caller":"/a/b/install.sh",
 "lib":"fx-detect-os.sh","version":"1.6.0","_os_root":false,"uname":true,
 "outcome":"identity-unresolved",
 "steps":[
   {"source":"os-release","rc":1,"detail":"/etc/os-release none, /usr/lib/os-release no ID"},
   {"source":"lsb-release","rc":1,"detail":"/etc/lsb-release absent"},
   {"source":"lsb_release-cmd","rc":1,"detail":"command missing from PATH at source time"},
   {"source":"legacy","rc":1,"detail":"no /etc/*-release file matched"},
   {"source":"uname-fallback","rc":1,"detail":"last resort: ID=linux also not claimed"}],
 "finals":{"ID":"","ID_LIKE":"","NAME":"","VERSION":"","PRETTY_NAME":"",
           "SOURCE":"","FALLBACK":false}}
```

- `ts` — `date -u '+%FT%TZ'`. `pid` — `$$`. `caller` — `$0`.
- `lib` — `${BASH_SOURCE[0]:-?}` basename. `version` — `$_OS_VERSION`.
- `_os_root` — whether `_OS_ROOT` was set (fixture/host-isolation context).
- `uname` — whether `$_OS_UNAME` was found at source time (drives the
  last-resort ladder step + kernel metadata).
- `steps[].rc` — the source's `detect_os`-observed rc (0 hit, 1 no-ID).
- `finals` — the `OS_*` fields at failure time (sanitized/redacted), so an
  AI can see partial state and what was already observed.

## New helpers (fx-detect-os.sh)

- `_os_json_escape` — print a JSON-safe string (escape backslash, `"`,
  and control chars <0x20; emit `\n` `\t` `\r` named escapes). Dep-free
  (no jq). Pure bash, no process substitution, `local` only (harness rules).
- `_os_ensure_error_log` — idempotent; resolves default/`_OS_ERROR_LOG`
  path, `mkdir -p` + touch mode 0600, echoes path. Guarded like
  `_os_ensure_log_file`.
- `_os_failure_record` — takes the event fields, runs each string value
  through `_os_redact`, builds one NDJSON object, appends with
  `>> file 2>/dev/null || :`. **Fail-open**: an unwritable log never
  changes `detect_os` rc and never prints to stderr.

No top-level `declare`; no process substitution; bash >= 4.2 (`local -a`,
`${x,,}`).

## Docs

- README: note the failure log (path, when written, `_OS_ERROR_LOG`
  override, one-line-per-event NDJSON, AI-parseable with `jq .`).
- cheatsheet: one line in Debug section.
- Version bump to 1.6.0.
- README test count update (bats → N).

## Tests (bats, detect_os.bats)

1. All ladder steps fail → file created. Default path resolves from
   `BASH_SOURCE[0]` dir (the repo), NOT `_OS_ROOT`. Tests set
   `_OS_ERROR_LOG` to a `BATS_TEST_TMPDIR` path to avoid writing into the
   repo during the suite; a dedicated test also exercises the real pipeline
   with an overridden path. Assert: file exists, mode 0600, single line,
   `jq -e .`-parseable (skip gracefully if `jq` absent — fall back to a
   structural balance check), `"outcome":"identity-unresolved"`, `"rc"`
   per step, redaction leaves no secret residue.
2. Success run → no file created.
3. `_OS_ERROR_LOG` override honored (relative + absolute).
4. All-ladder-fail through `detect_os` keeps rc 1 even with an unwritable
   `_OS_ERROR_LOG` target (fail-open) — detection behavior unchanged.
5. `_os_failure_record` redacts a space-containing `NAME=value` secret in a
   field value (S5 guard applies to the permanent log too).
6. Legacy-only failure records the legacy step + `os-release`/`lsb-release`
   NoID detail (partial state captured before the failing step).

## Acceptance criteria

- 1.6.0 shipped; failure write happens exactly on `identity-unresolved`.
- File mode 0600; every line is one valid JSON object; fields redacted.
- `_OS_ERROR_LOG` override honored; caller-supplied path never chmod'd.
- Unwritable log path cannot change `detect_os` rc or emit stderr.
- 71 existing tests + new ones pass verbatim; shellcheck clean; mode 755.

## Out of scope

- Readonly-collision events, per-step success telemetry, rotation/cap,
  jq as a runtime dependency.
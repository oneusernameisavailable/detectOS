# fx-detect-os.sh — run / debug cheatsheet

```
. ./fx-detect-os.sh     # define functions (no side effects)
detect_os               # run the ladder, fill OS_* globals (rc 0/1)
echo "$OS_ID $OS_DISTRO"
```

## Detection ladder (first hit wins)

1. `/etc/os-release` → `/usr/lib/os-release` (`-f -r -s` guards **plus a byte
   count cap**: a FIFO, 0-byte, ID-less, or oversized release file **defers**
   and clears any partial fields — it never claims `linux`; a `/usr/lib`
   takeover resets partial fields from `/etc` so fields never mix)
2. `/etc/lsb-release` (parsed directly, no command needed; `-f -r` + size-cap
   guards)
3. `lsb_release -is/-rs/-cs/-ds` pinned at source; wrapped in `timeout(1)` — a
   shared 5s budget across all four probes — when present; **skipped when
   `_OS_ROOT` is set** so host identity never leaks into a fixture/chroot
4. legacy files: `debian_version`, `arch-release`, `gentoo-release`,
   `alpine-release`, `redhat-release`/`centos-release`, `system-release`
   (Amazon→`amzn`, Oracle→`ol`), `SuSE-release`, then a catch-all for any
   other `<id>-release`/`<id>_release`. The catch-all glob deliberately does
   **not** match `<id>-release-cpe` (CPE metadata carries no identity and is
   never a distribution claim — narrowing the glob back to `*-release*`
   would make it one)
5. `uname -s` last resort (Linux → `ID=linux`) — the **only** step that ever
   emits `ID=linux`, so a fallback claim can never look like an os-release hit

Every file check runs through `_os_file_ok <path> [max]` (regular + readable +
byte count ≤ 262144 default / 4096 for container markers); empty files count
as present (0-byte `arch-release` is by design). Oversize → defer to next
step, never slurp. `wc` failure at runtime degrades to "accept"; the cap is
byte-exact via stat/wc, character-counted (≤ ~4× cap) in the tool-less
fallback, never a whole-file slurp. Container markers same guard.

**Trust ladder** (`OS_TRUST_LEVEL`, one of `high|medium|low|none`):
os-release `high`; lsb-file/lsb-cmd/named-legacy `medium`; catch-all glob +
uname `low`; unresolved `none`. Reset per run — a stale `high` never bleeds
into a later `low`/`none`. Accessor: `os_trust_level`.

Container metadata (`/.dockerenv`→`docker`, `/run/.containerenv` with
`engine="podman"|"crun"`→`podman`, other engine→`oci`; a `.containerenv`
under `/run/user/<uid>/` = rootless podman → `containers`, as is a
`/run/.containerenv` with no engine line). Never blocks distribution
detection.

Display strings (PRETTY_NAME/NAME/VERSION/CODENAME/ID_LIKE, lsb
description/codename, release-file lines) are allowlist-scrubbed to
`[A-Za-z0-9]` + space + `. _ : / , + = ( ) @ % ^` (bytes ≥0x80/UTF-8 kept);
quotes, backslash, backtick, glob/brace/redirection metachars, `;`, `$`,
control bytes and DEL are removed.
os-release/lsb-release tolerate a UTF-8 BOM.

## Globals set by detect_os

`OS_DETECTED OS_ID OS_ID_LIKE OS_NAME OS_VERSION OS_VERSION_ID
OS_VERSION_CODENAME OS_PRETTY_NAME OS_DISTRO OS_ARCH OS_KERNEL
OS_KERNEL_RELEASE OS_CONTAINER OS_SOURCE OS_FALLBACK_USED OS_TRUST_LEVEL`

## Field functions (echo empty string when unset)

`os_id os_like os_name os_version os_version_full os_codename os_pretty
os_distro os_arch os_kernel os_kernel_release os_container os_source
os_trust_level`

Guard form: `if os_detected; then ...` (rc 0 = detected).

## Debug

```
_OS_DEBUG=1 . ./fx-detect-os.sh      # or SCRIPT_DEBUG=1
detect_os
less "${_OS_LOG_FILE:-<mktemp path; warns once and degrades to OFF when unavailable>}"
```

Log file: mode 0600, three redaction passes (two name-driven, one
shape-driven) on a secret-name wordlist (case-insensitive): substring words
(`pass`, `token`, `secret`, `cred`, `psk`, `jdbc`, …) match anywhere;
`key`/`auth` match only at a name-separator boundary (`API_KEY`,
`AUTH_TOKEN` redacted; `MONKEY`, `KEYRING`, `GIT_AUTHOR_NAME` untouched);
exact connection-string names (`database_url`, …) also match. `NAME=value`
tokens at a boundary whose name matches become `[REDACTED]` (any value
length; space-containing values matched in full via the checked env value);
values of wordlist-named exported env vars (≥4 chars) are replaced wherever
they appear, longest first; a third shape pass redacts credential VALUES
with innocuous names (Authorization/Bearer headers, AKIA/ASIA ids, JWTs,
PEM banners, JSON `"key":"value"` pairs). Values <4 chars in prose are left
alone so `/` or `1` never corrupt a line. `*url*`/`*uri*` are not matched
(`HOME_URL` stays). Vocabulary:
`==== START`, `=== STAGE: x`, `ENTER f`/`EXIT f`, `EXEC:`/`RC=n`, `!! ERROR`,
`---- STATE DUMP`.

Drivers: `_OS_LOG_FILE` — when set, used as-is (never chmod'd); if world-visible
(group/other bits), a one-time warning goes to stderr. `_OS_ENV` — pinned path
to the `env(1)` tool backing the redaction value-pass; *empty* (or missing env
tool at source time) disables value-pass with a one-time warning; a
set-but-broken path warns once at redaction and value-pass stays OFF (name
pass stays active). Log-path echo on enable is redacted.

Failure log: `${XDG_STATE_HOME:-$HOME/.local/state}/osdetect/osdetect-failures.jsonl` (NDJSON, identity-unresolved only, `_OS_ERROR_LOG` override, `jq .` to parse).

## Testing / faking a root

Environ `_OS_ROOT=/some/prefix` retargets every read path (and disables the
`lsb_release` command step), so you can test against a fixture filesystem
without touching the host `/etc`:

```
export _OS_ROOT="$PWD/root"; mkdir -p "$_OS_ROOT/etc"
printf 'ID=debian\nVERSION_ID="12"\n' > "$_OS_ROOT/etc/os-release"
. ./fx-detect-os.sh; detect_os; echo "$OS_ID"
```

bats suite: `test/detect_os.bats` (159 tests, needs
[bats-core](https://bats-core.github.io/)).

## Lint / syntax

```
bash -n fx-detect-os.sh
shellcheck -S style fx-detect-os.sh    # if shellcheck installed
```
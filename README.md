# fx-detect-os.sh — Linux distribution detection library

A source-only bash library that detects the current Linux distribution and
exposes it as globals plus per-field functions. Sourced by other build
scripts ("subsequent scripts are **bash**"). Safe under caller strict mode
(`set -euo pipefail`). No external command is required at runtime: `uname`, `mktemp`, `timeout`,
`lsb_release`, `env`, `date`, `mkdir`, `chmod`, `wc` and `stat` are used
opportunistically, and their paths are pinned once at source time (so a later
PATH change cannot swap what the library runs). When a pinned tool is absent at
source time the library degrades gracefully (redaction falls back to
wordlist-only, timestamps render empty, failure-log creation is skipped, and
the file-size guard silently accepts files when `wc` is gone) rather than
resolving the tool from PATH at call time.

```sh
. "$(dirname "$0")/fx-detect-os.sh"
detect_os                     # rc 0 = detected, 1 = unresolved
printf 'platform: %s/%s on %s\n' "$OS_ID" "$OS_ARCH" "$OS_DISTRO"
```

> **Call `detect_os` before reading any `OS_*` global.** Sourcing only
> defines functions. Calling `detect_os` again re-runs the whole ladder and
> overwrites every global.

---

## API contract

All field functions echo their value on stdout with rc 0. They echo an empty
string when the field was not detected (never trip `set -u`).

| Function          | stdout                          | rc            |
| ----------------- | ------------------------------- | ------------- |
| `detect_os`       | (nothing)                       | `0` detected, `1` unresolved (`OS_DETECTED=0`, kernel fields still set) |
| `os_id`           | `OS_ID`                         | `0` always    |
| `os_like`         | `OS_ID_LIKE`                    | `0` always    |
| `os_name`         | `OS_NAME`                       | `0` always    |
| `os_version`      | `OS_VERSION_ID` (script-safe)   | `0` always    |
| `os_version_full` | `OS_VERSION` (human string)     | `0` always    |
| `os_codename`     | `OS_VERSION_CODENAME`           | `0` always    |
| `os_pretty`       | `OS_PRETTY_NAME`                | `0` always    |
| `os_distro`       | `OS_DISTRO` (composed display)  | `0` always    |
| `os_arch`         | `OS_ARCH`                       | `0` always    |
| `os_kernel`       | `OS_KERNEL`                     | `0` always    |
| `os_kernel_release` | `OS_KERNEL_RELEASE`           | `0` always    |
| `os_container`    | `OS_CONTAINER`                  | `0` always    |
| `os_source`       | `OS_SOURCE`                     | `0` always    |
| `os_trust_level`  | `OS_TRUST_LEVEL`                | `0` always    |
| `os_detected`     | (nothing) — use as guard        | `0` iff `OS_DETECTED=1` |

Nowhere do globals and functions overlap in meaning: functions are the only
stable interface; `OS_*` globals are the raw storage.

Exit codes outside the API:
- script sourced a second time → no-op, rc `0`. The no-op guard requires the
  load flag **plus** two function markers — `_os_debug_active` (top of file)
  and `_os_loaded` (last line). A leftover/forged flag alone, or one lone
  helper function with the flag, cannot silently turn a needed reload into a
  no-op: the library counts as "loaded" only once the whole file really ran.
- executed directly (`bash fx-detect-os.sh`) → usage hint on stderr, **exit 2**

---

## Output contract — every value the library can produce

### `OS_ID` — the complete vocabulary

`OS_ID` is always lowercase, restricted to `[0-9a-z._-]` (anything else is
mapped to `_`). The library resolves to exactly one value:

| Value(s)                                  | When detected                           | Step  |
| ----------------------------------------- | --------------------------------------- | ----- |
| any `ID=` value from `/etc/os-release` (or `/usr/lib/os-release`) | standard distros | os-release |
| `linux`                                   | nothing distro-specific found — **uname last resort only**; an ID-less/0-byte os-release **defers** and never claims `linux` | uname |
| any `DISTRIB_ID` from `/etc/lsb-release`  | legacy Ubuntu/Debian LSB file           | lsb file |
| any `lsb_release -is` output              | `lsb_release` present at source time     | lsb cmd |
| `debian`                                  | `/etc/debian_version`                   | legacy  |
| `arch`                                    | `/etc/arch-release` (empty marker)      | legacy  |
| `gentoo`                                  | `/etc/gentoo-release`                   | legacy  |
| `alpine`                                  | `/etc/alpine-release`                   | legacy  |
| `fedora` / `centos` / `rocky` / `almalinux` / `rhel` | content of `/etc/redhat-release` or `/etc/centos-release` | legacy |
| `amzn` / `ol`                             | `/etc/system-release` (Amazon / Oracle); `ol` also from `/etc/oracle-release` directly | legacy  |
| `fedora` / `centos` / `rocky` / `almalinux` / `rhel` | unknown-vendor `/etc/system-release` matching family text | legacy |
| `opensuse-tumbleweed` / `opensuse-leap` / `opensuse` / `sles` | content of `/etc/SuSE-release` | legacy |
| `<id>`  (e.g. `nobara`, `mageia`)         | any remaining `/etc/<id>-release` / `/etc/<id>_release` basename | catch-all |
| kernel name from `uname -s` (Linux ⇒ `linux`) | last resort, even when nothing distro-specific exists | uname |

Output can therefore be **any** of the above or a distro's own `ID` string —
write consumers as a `case` with a `*)` default, never a blocklist.

> **Caller readonly collisions.** `detect_os` writes the `OS_*` globals. If a
> caller has already declared any of them `readonly` (set or unset), `detect_os`
> refuses up front with rc 1 and an `osdetect:` warning on stderr; nothing is
> written, and a stale `OS_DETECTED=1` from an earlier successful run is cleared
> so rc 1 and `OS_DETECTED` always agree. Readonly OS_* bindings are never
> silently clobbered — a caller that wants the library's values must not
> pre-declare the names.
>
> **`_os_` namespace reservation.** The `_os_` prefix is library-owned, in both
> the variable and function namespaces. The internal globals `_os_last_detail`,
> `_os_log_file`, `_os_log_ready`, and `_os_steps` are treated exactly like OS_*
> destination fields by the collision scan: a caller-owned readonly binding of
> any of them makes `detect_os` refuse (rc 1), because writing a readonly name
> would abort the caller's shell. The source-time tool-path loop also reassigns
> and then unsets the transient scratch names `_os_tool`, `_os_var`, `_os_cmd`,
> so a caller-owned copy of those is overwritten and lost at source time, and a
> `readonly` one aborts sourcing. Callers should not define any `_os_*`
> variables or functions.
>
> **Generic-name function preflight.** The entry point `detect_os` and the
> `os_*` accessors are generic names that live in the *caller's* function
> namespace. At source time the library scans `declare -F` over those names; a
> caller that already owns one gets a loud `osdetect:` warning and `detect_os`
> refuses to run (rc 1, like the readonly-collision path). The colliding names
> are overwritten regardless — bash cannot restore a clobbered function — which
> is exactly why the ladder refuses rather than run on a namespace it already
> damaged.

> enforcement is fight-or-flight: either the caller pre-owns readonly bindings
> of the OS_* / `_os_` names (warned + refused, rc 1) or the library writes
> them. A caller's own mute/exit traps or `readonly` mutations apply as the
> caller wrote them; the library never installs or overrides a trap.

### `OS_TRUST_LEVEL` — how trustworthy is the identity?

`detect_os` records which ladder step won so consumers can gate policy:

| Level    | Winning step(s)                                                            |
| -------- | -------------------------------------------------------------------------- |
| `high`   | freedesktop `/etc/os-release` (or `/usr/lib/os-release`) spec read         |
| `medium` | `/etc/lsb-release`, the `lsb_release` command, named legacy family files   |
| `low`    | catch-all `/etc/<id>-release` basename, `uname` last resort                |
| `none`   | identity unresolved (`OS_DETECTED=0`, rc 1) — also recorded on failure     |

Reset on every and each step; cleared between `detect_os` runs, so a stale
`high` from an earlier detection never bleeds into a later `low`/`none`.
Example gating: `[ "$OS_TRUST_LEVEL" = high ] || die "untrustworthy OS_ID"`.
Accessor `os_trust_level`.

> **Security boundary (C4).** The trust ladder is about *which source provided
> the bytes*, not about defending against an attacker who controls the shell.
> The library pins tool paths and skips the LSB command under `_OS_ROOT`, but a
> hostile environment (`LD_PRELOAD`, a forged PATH at source time, exported
> env overrides) can still steer what those binaries report. Treat the
> environment as part of the trust foundation: the library's guarantee is
> "each value is sanitized and provenance-annotated", not "untrusted"
> sandbox-proof. `OS_ID` values are shell-safe (charset `[0-9a-z._-]`) but —
> catch-all basenames in particular — are **not** validated path components;
> interpolate them into filesystem paths with care (C3).

### `OS_ID_LIKE`

- the `ID_LIKE`/`id_like` value from os-release (arbitrary space-separated
  list, e.g. `rhel fedora`), or
- family preset: `rhel fedora` (CentOS, Amazon Linux), `rhel centos fedora`
  (Rocky/AlmaLinux, Oracle Linux), or
- empty string (most legacy-only detections).

### Version fields

- `OS_VERSION_ID` (script-safe): `VERSION_ID` → `DISTRIB_RELEASE` →
  `lsb_release -rs` → first dotted numeric token in a release line
  (e.g. `9.3` from `release 9.3 (Plano)`) → always plain, no shell metachars
  guaranteed; **empty on rolling releases** (Arch, Tumbleweed).
- `OS_VERSION` (human): the raw `VERSION`/`VERSION_ID`-preference string.
- `OS_VERSION_CODENAME`: `VERSION_CODENAME` → `DISTRIB_CODENAME` → empty.

### `OS_DISTRO` — exact composition rule

1. `OS_PRETTY_NAME` if set (usually the richest display string), else
2. `OS_NAME OS_VERSION` (or `OS_NAME OS_VERSION_ID`), else
3. `OS_NAME` alone, else
4. bare `OS_ID` (`Linux` when empty).

`OS_PRETTY_NAME` itself comes from `PRETTY_NAME`, `DISTRIB_DESCRIPTION`,
`lsb_release -ds`, or the release-file content line.

Every display string the library emits is sanitized before storage: `PRETTY_NAME`,
`NAME`, `VERSION`, `VERSION_CODENAME`, `ID_LIKE`, lsb
`DISTRIB_CODENAME`/`DISTRIB_DESCRIPTION`, `lsb_release` `-cs`/`-ds` output, and
legacy release-file lines are all allowlist-scrubbed. Only ASCII letters,
digits, space and `. _ : / , + = ( ) @ % ^` survive; every quote, backslash,
backtick, glob/brace/redirection metachar, `;`, `$`, all control bytes and DEL
are removed. Bytes ≥ 0x80 pass through untouched, so multibyte UTF-8 (accented
distro names) keeps its display fidelity. No emitted value can embed a terminal
escape, a shell metachar, a glob pattern, or an unquoted-for-loop word.
os-release/lsb-release parsing also tolerates a UTF-8 BOM before the first key.

### `OS_SOURCE` — provenance (`OS_SOURCE="..."`)

One of:
- an absolute **file path** actually read: e.g. `/etc/os-release`,
  `/usr/lib/os-release`, `/etc/lsb-release`, `/etc/arch-release`, …
  (including any `_OS_ROOT` prefix used for testing),
- the literal `lsb_release-command`, or
- the literal `uname`.

Combine with `OS_FALLBACK_USED` (`0` = os-release path won, `1` = any
fallback step won) to reason about detection quality.

### Container metadata — `OS_CONTAINER`

Set independently of distro ID and never blocks distro detection:

| Value       | Trigger                                       |
| ----------- | --------------------------------------------- |
| `none`      | neither marker file present (default)         |
| `docker`    | `/.dockerenv` exists                          |
| `podman`    | `/run/.containerenv` with `engine="podman"` or `engine="crun"` |
| `oci`       | `/run/.containerenv` with any other engine (incl. `runc`)      |
| `containers`| `/run/.containerenv` with no engine line, **or** any `.containerenv` under `/run/user/<uid>/` (rootless podman — presence reveals containment but not the runtime) |

Set independently of distro ID and never blocks distro detection. Markers are
read after the ladder, independently; each path still passes the size cap
(4096 for container markers).

### Kernel metadata

`OS_ARCH` (`uname -m`), `OS_KERNEL` (`uname -s`), `OS_KERNEL_RELEASE`
(`uname -r`) — any string the kernel reports, or the literal `unknown` when
uname is unavailable. If `uname` is missing from PATH at source time, one
`osdetect:` warning is printed on stderr; `detect_os` then returns rc 1 with
`OS_DETECTED=0` and the metadata fields reading `unknown`.

### Flags

- `OS_DETECTED`: `1` resolved, `0` unresolved (kernel fields still filled).
- `OS_FALLBACK_USED`: `0` os-release won, `1` a fallback step won.

---

## Detection ladder (first hit wins, then stop)

```
1. /etc/os-release           -> /usr/lib/os-release     (-f -r -s guards + byte-count
                                                          cap: a FIFO, 0-byte, ID-less,
                                                          or oversized file DEFERS,
                                                          clears any partial fields,
                                                          and claims nothing; /usr/lib
                                                          takes over (reset) only when
                                                          /etc had no ID)
2. /etc/lsb-release                                     (parsed directly, no command;
                                                          -f -r + size-cap guards)
3. lsb_release -is/-rs/-cs/-ds                          (pinned at source; wrapped in
                                                          timeout(1) 5s when present;
                                                          SKIPPED when _OS_ROOT is set,
                                                          so host identity can never
                                                          leak into a fixture/chroot)
4. legacy files: debian_version, arch-release, gentoo-release, alpine-release,
   oracle-release (always -> ol, beats any RHEL-compatible redhat-release),
   redhat-release / centos-release, system-release (Amazon->amzn, Oracle->ol,
   else family text), SuSE-release, then catch-all <id>-release/<id>_release
   (known-family exclusion arms apply to glob-visible names only; `<id>-release-cpe`
   CPE metadata files are out of the glob's scope and are never identity claims)
5. uname -s                                             (Linux => ID=linux; the ONLY
                                                          step that ever emits it,
                                                          so a fallback paternity
                                                          claim can never disguise
                                                          itself as an os-release hit)
```

Every file check — os-release, lsb-release, legacy named files, the catch-all
glob, and the container markers — runs through one `_os_file_ok <path> [max]`
guard: readable regular file, byte count ≤ cap (default 262144; container
markers 4096). Oversize defers to the next ladder step instead of being
slurped (a hostile/huge release file can't force 256 KB+ into the parser); an
empty release file still counts as *present* (`arch-release` is 0 bytes by
design). `wc` failure at runtime degrades the check to "accept" rather than
crash strict-mode callers. The cap is byte-exact when `stat`/`wc` are pinned;
in the tool-less fallback the bounded read counts **characters**, so a
multibyte file may over-read up to ~4× the cap there — the cap stays a DoS
bound (the file is still slurped-never; oversize always defers), not an exact
byte gate.

Container metadata (`/.dockerenv`, `/run/.containerenv`, and the rootless
`/run/user/<uid>/.containerenv` marker) is read after the ladder,
independently.

---

## Environment hooks

| Variable        | Effect                                                        |
| --------------- | ------------------------------------------------------------- |
| `_OS_ROOT`      | prefix for **every** path read → fixture-test against a fake filesystem, never touch the host `/etc`. Also disables the `lsb_release` **command** step (its binary would answer for the host, leaking host identity into the fixture); the file-based probes still detect. |
| `_OS_ENV`       | path to the `env(1)` tool the redactor invokes for the value-pass, pinned at source time (tool-pinning map). When it is unset/empty at source time, the embedded-value scrub is **disabled** with a one-time `osdetect:` warning on stderr (the name-context token pass still runs); a caller-supplied non-empty path that **fails to run** at redaction time warns once and value-pass degrades to OFF while the name pass stays active. |
| `_OS_DEBUG` / `SCRIPT_DEBUG` | set to `1` to enable the trace log. Evaluated **per call**, so it can be turned on mid-session, after sourcing. |
| `_OS_LOG_FILE`  | debug log path (default: a `mktemp` name next to `${TMPDIR:-/tmp}`), created mode `0600`, path echoed to stderr (redacted) when enabled. When `_OS_LOG_FILE` is set the file is used as-is and its mode is never changed; a caller-supplied path keeps whatever permissions the caller left — if that log turns out **world-visible** (group or other bits on), the library prints a one-time `osdetect:` warning on stderr so a caller can still mode it down without the library silently writing secrets into a 644 file. If neither a usable `mktemp` nor a writable `_OS_LOG_FILE` exists, the debug log prints a one-time `osdetect:` warning and degrades to OFF rather than writing to a guessable `/tmp/osdetect.<pid>` path. |
| `_OS_ERROR_LOG`  | NDJSON failure-log path (default: `${XDG_STATE_HOME:-$HOME/.local/state}/osdetect/osdetect-failures.jsonl`, or `${TMPDIR:-/tmp}/osdetect/osdetect-failures.jsonl` when `HOME` is unset); set before `detect_os`. Created mode `0600` on first failure; a caller-supplied path is never chmod'd — but if it turns out **world-visible**, the library prints a one-time `osdetect:` warning (same policy as `_OS_LOG_FILE`). Success runs write nothing. |

Debug log vocabulary (greppable): `==== START`, `=== STAGE: <x>`,
`ENTER <fn>` / `EXIT <fn>`, `EXEC: <cmd>` / `RC=<n>`, `!! ERROR`,
`---- STATE DUMP` … `---- END STATE DUMP`. Three redaction passes run before
any line is written, two driven by a secret-name wordlist (substring words
`pass`, `token`, `secret`, `cred`, `cookie`, `psk`, `bearer`, `otp`, `mfa`,
`dsn`, `jdbc`, `conn*string`, `connstr` match anywhere in the name; the
collision-prone `key` and `auth` match only at a name-separator boundary
(underscore, hyphen, or a name edge), so `API_KEY` / `ACCESS_KEY` / `KEY_ID` /
`AUTH_TOKEN` stay redacted while `MONKEY`, `KEYBOARD`, `KEYRING`, `TURKEY`,
`KEYMAP` and `GIT_AUTHOR_NAME`, `AUTHOR` are not mistaken for secrets and eaten
out of legitimate log lines; exact names `database_url`, `postgres_url`,
`redis_url`, `mongo_url`, `mysql_url`, `jdbc_url`, … (matched
case-insensitively) cover the connection-string family. A `NAME=value` token at
a whitespace boundary whose name matches becomes `[REDACTED]` in full (any
value length, so short values are covered; a value containing spaces is
matched in full via the checked env value), and the values of wordlist-named
**exported** env vars (≥4 chars) are replaced wherever they appear, longest
value first. A third, shape-driven pass redacts credential **values** whose
names are innocuous: `Authorization`/`Bearer` headers, `AKIA`/`ASIA` access-key
ids, JWT `eyJ*` blobs, PEM private-key banners, and JSON `"key":"value"`
pairs. Values <4 chars embedded in prose stay untouched so a common token
like `/` or `1` cannot corrupt a line. Broad `*url*`/`*uri*` patterns are
deliberately not matched — public fields like `HOME_URL` must survive.

When `detect_os` cannot resolve an OS identity (rc 1), it prints a loud
`osdetect:` diagnostic to stderr (one for the resolution failure, a second
naming the failure-log path) and one NDJSON line is appended to the failure
log (created mode `0600` on first failure). The path
defaults to `${XDG_STATE_HOME:-$HOME/.local/state}/osdetect/osdetect-failures.jsonl`
and is overridable via `_OS_ERROR_LOG`; it never defaults inside the source tree
(a read-only install directory would otherwise drop telemetry silently), and if
the resolved target is still unwritable the library fails open without changing
`detect_os` rc. Each line records the full detection ladder (`steps[]` array),
the final `OS_*` field state (`finals{}`), and environment context; all values —
including the `caller` and `lib` fields — are redacted before write. Parse with:
`jq . "$HOME/.local/state/osdetect/osdetect-failures.jsonl"`.

---

## Consumer patterns

Dispatch an install action per distro; never trust an ID without a trust floor —
`detect_os` rc 0 includes the uname last resort (`ID=linux`, trust `low`), which
is a *placeholder*, not a distro, and dispatching a package manager from it
would install the wrong one:

```sh
. "$(dirname "$0")/fx-detect-os.sh"
detect_os || exit 1

case "$OS_TRUST_LEVEL" in
    high|medium) ;;
    *) echo "identity too weak to pick a package manager: $OS_ID (trust=$OS_TRUST_LEVEL)" >&2; exit 1 ;;
esac

case "$OS_ID" in
    arch|manjaro|endeavouros|arcolinux)                    pm=pacman ;;
    debian|ubuntu|linuxmint|pop)                           pm=apt    ;;
    fedora|rhel|centos|rocky|almalinux|ol)                 pm=dnf    ;;
    suse|opensuse|opensuse-leap|opensuse-tumbleweed|sles)  pm=zypper ;;
    alpine)                                                pm=apk    ;;
    nixos)                                                 pm=nix-env ;;
    * ) echo "unsupported distro: $OS_ID" >&2; exit 1 ;;
esac
echo "using $pm on $OS_DISTRO ($OS_ARCH)"
```

Guard for OS families and container context:

```sh
if os_detected && [[ " $OS_ID_LIKE " == *" rhel "* ]]; then
    echo "enterprise-family"; fi
[ "$OS_CONTAINER" = docker ] && echo "inside Docker"
```

---

## Repository layout & validation

```
fx-detect-os.sh       # the library (source-only)
README.md             # this file
docs/cheatsheet.md    # quick run/debug reference
.gitignore            # ignores state/failure-log and test/eval artifacts
test/detect_os.bats   # bats-core integration suite (fixtures behind _OS_ROOT)
```

```sh
bats test/detect_os.bats                      # 159 tests
shellcheck -S style -x fx-detect-os.sh test/detect_os.bats
bash -n fx-detect-os.sh
```

Tooling (Arch/CachyOS): `sudo pacman -S bats-core shellcheck`.
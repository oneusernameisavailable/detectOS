#!/usr/bin/env bash
#
# fx-detect-os.sh — Linux distribution detection library (source-only)
#
# PURPOSE
#   Detect the current Linux distribution and expose it as shell variables
#   plus per-field functions for other build scripts to consume. This is a
#   LIBRARY: sourcing it defines functions, nothing else.
#
# REQUIREMENTS
#   bash >= 4.0 (${var,,}, ${!name}, [[ =~ ]] are in use; bash 5 ships on all
#   current Linux distros). `uname`, `mktemp`, `timeout`, `lsb_release`,
#   `env`, `date`, `mkdir`, `chmod`, `wc` and `stat` are used opportunistically
#   and degrade gracefully when absent. Their paths are
#   resolved ONCE at source time (see PATH PINNING below); a later PATH change
#   never swaps what the library runs.
#
# USAGE
#   . /path/to/fx-detect-os.sh
#   detect_os            # fills OS_* globals; returns 0 on success, 1 if unresolved
#   detect_os            # call again to refresh — it re-runs the detection ladder
#   printf '%s\n' "$OS_ID $OS_VERSION_ID $OS_DISTRO"
#   or use the field functions: os_id / os_like / os_pretty / os_distro /
#   os_trust_level ...
#
#   Calling detect_os OVERWRITES every OS_* global. Field functions echo an
#   empty string (rc 0) when a field was not detected, so callers never trip
#   over unset variables.
#
# DETECTION LADDER  (first step that yields an ID wins)
#   1. /etc/os-release  ->  /usr/lib/os-release      (freedesktop spec)
#   2. /etc/lsb-release                             (legacy LSB file)
#   3. lsb_release -is/-rs/-cs/-ds                  (command, if present)
#   4. legacy release files: debian_version, arch-release, gentoo-release,
#      alpine-release, redhat-release, centos-release, system-release (Amazon
#      Linux / Oracle), SuSE-release, then a catch-all for any remaining
#      /etc/*-release or /etc/*_release whose basename yields a usable ID.
#   5. uname -s  (last resort; os-release's own spec default is ID=linux)
#   Container metadata (/.dockerenv, /run/.containerenv) is read
#   independently and never blocks distribution detection.
#
#   OS_TRUST_LEVEL mirrors which step won: high for the freedesktop os-release
#   spec step, medium for the named legacy/LSB sources, low for the catch-all
#   legacy glob and the uname last resort, none when identity could not be
#   resolved. Consumers can gate policy on it (e.g. refuse OS_TRUST_LEVEL=low
#   fields).
#
# SOURCING DISCIPLINE / EXPOSED STATE
#   Sourced files run inside the caller's shell. Therefore this library
#   deliberately does NOT set -e / set -u / pipefail, does not install traps,
#   and does not create temp files — the CALLER owns strict mode, traps, and
#   cleanup. (See # OVERRIDE entries below.) All expansions are quoted, all
#   reads use -r, no ls parsing, no process substitution, and no eval — with
#   exactly ONE exception: the exported-array secret scan reads components via
#   eval on a regex-validated shell identifier (no caller text reaches the
#   evaluator); see _os_redact's pass-2a.
#
# DEBUGGING
#   Set _OS_DEBUG=1 (or SCRIPT_DEBUG=1) to enable a trace log. This is
#   evaluated per call, so you can turn it on at any time — before OR after
#   sourcing, even mid-session. Log path: ${_OS_LOG_FILE:-a mktemp name next to
#   ${TMPDIR:-/tmp}>}, created with mode 0600 (mktemp itself) or used as the
#   caller left it (when _OS_LOG_FILE is set), path echoed to stderr (redacted)
#   when enabled. An unwritable caller-supplied _OS_LOG_FILE, or an absent one
#   when mktemp is unavailable, emits a one-time osdetect: warning and the debug
#   log degrades to OFF rather than reverting to a guessable "osdetect.<pid>"
#   path in /tmp. The log then carries the standard vocabulary:
#       ==== START / === STAGE: x / ENTER f / EXIT f / EXEC: ... / RC=n /
#       !! ERROR / ---- STATE DUMP
#   To run detection against a fake root (tests, chroot analysis) export
#   _OS_ROOT=/some/prefix; every path read becomes ${_OS_ROOT}/etc/... .
#
# EXIT CODES
#   detect_os  -> 0 detected (OS_DETECTED=1), 1 unresolved (OS_DETECTED=0)
#   outer shell -> sourced with _DETECT_OS_SOURCED set  : no-op return 0
#                   executed directly (bash fx-detect-os.sh): exit 2  (usage)
#
# OVERRIDES (protocol deviations, each with the concrete reason)
#   # OVERRIDE: strict-mode-at-top — a sourced file must not leak set -e/-u/
#     pipefail into its caller; the library uses ${VAR:-} defaults and always
#     guards failing commands with || so callers MAY run strict mode. Date 2026-09-13
#   # OVERRIDE: traps/mktemp — libraries must not clobber caller traps and
#     need no temp files; cleanup is a caller concern. Log make is confined to
#     the debug-enable path. The log's mode 0600 is enforced only on files the
#     library itself mktemps; a caller-supplied _OS_LOG_FILE keeps its mode.
#     Date 2026-09-13
#   # OVERRIDE: PATH pinning / usage() / getopts / exit-code registry — CLI
#     concepts inapplicable to a sourced library; external command paths are
#     captured once at source time (readonly _OS_UNAME/_OS_MKTEMP/_OS_LSBRELEASE/
#     _OS_TIMEOUT), so a poisoned or mutated caller PATH cannot redirect the
#     commands the library runs. Date 2026-09-14

# ---------------------------------------------------------------------------
# Source guard (double-source is a no-op)
# ---------------------------------------------------------------------------
# The guard requires the load flag plus TWO function markers: _os_debug_active
# (defined early) and _os_loaded (defined on the LAST line of the file). A
# caller that accidentally pre-defines one plausible helper name (say
# _os_debug_active) together with the documented _DETECT_OS_SOURCED flag can
# no longer make sourcing silently no-op — the load is only complete once the
# whole file ran. A deliberate forger who pre-defines every name and the flag
# still bypasses this, but that attacker already controls the shell before the
# library ever loads, which is out of scope (documented in README).
if [ -n "${_DETECT_OS_SOURCED:-}" ] \
    && declare -F _os_debug_active >/dev/null 2>&1 \
    && declare -F _os_loaded >/dev/null 2>&1; then
    # SC2317: the `exit 0` branch is the fallback when this file is sourced in
    # a context where `return` is rejected (e.g. eval/`bash -c`); it is
    # intentionally unreachable in normal `.` sourcing.
    # A pre-set _DETECT_OS_SOURCED alone is never trusted: without the function
    # marker the library is not actually loaded, so a forged/leftover flag
    # cannot silently turn sourcing into a no-op.
    # shellcheck disable=SC2317
    return 0 2>/dev/null || exit 0
fi
# Assigning a pre-declared `readonly _DETECT_OS_SOURCED` would abort the
# caller's shell even under relaxed settings. Only a caller that does not
# already own the name gets the flag written; a pre-declared readonly-empty
# binding is honored as-is (the function-marker guard above keeps double-source
# semantics safe without needing the flag).
if ! declare -p _DETECT_OS_SOURCED >/dev/null 2>&1; then
    _DETECT_OS_SOURCED=1
fi

# ---------------------------------------------------------------------------
# Function-namespace preflight
# ---------------------------------------------------------------------------
# The library defines a handful of GENERIC-name functions (detect_os and the
# os_* accessors) that live in the CALLER's namespace — the heavily-overloaded
# variable side of this library refuses to write a caller-owned name (readonly
# collision guard), and the function side must refuse too. A caller that
# already owns one of these names would otherwise have it silently overwritten
# at source time. Any pre-existing generic-name function is reported loudly
# and detect_os is disabled (rc 1): running the ladder on a namespace this
# library already clobbered would only compound the damage. The scan runs
# before any library function is defined (and only once, guarded by the source
# guard above), so declare -F reflects only the caller's own state.
_os_fn_collision=0
_os_fn_collided=""
for _os_fn_candidate in detect_os os_id os_like os_name os_version \
        os_version_full os_codename os_pretty os_distro os_arch os_kernel \
        os_kernel_release os_container os_source os_trust_level os_detected; do
    # `declare -F` in an `if` condition is errexit-safe: a name that is not a
    # function (the common case) returns 1 without aborting a strict caller.
    if declare -F "$_os_fn_candidate" >/dev/null 2>&1; then
        _os_fn_collision=1
        _os_fn_collided="${_os_fn_collided:-} $_os_fn_candidate"
    fi
done
if [ "$_os_fn_collision" = "1" ]; then
    printf '%s\n' "osdetect: function-namespace collision at source time — pre-existing generic function(s):$_os_fn_collided" >&2
    printf '%s\n' "osdetect: those names are now overwritten; detect_os refuses to run (rc 1). Re-source in a shell where they are free." >&2
fi

# ---------------------------------------------------------------------------
# Constants & debug state
# ---------------------------------------------------------------------------
# A version stamp a caller may already own. If the name is already declared
# (readonly or not), leave the caller's binding untouched — re-assigning a
# readonly name aborts even under `set -e`, and the collision is never this
# library's business to override.
if ! declare -p _OS_VERSION >/dev/null 2>&1; then
    readonly _OS_VERSION="1.8.0"
fi

# ---------------------------------------------------------------------------
# Single source of truth for the OS_* field vocabulary (SSOT)
# ---------------------------------------------------------------------------
# Every place that must name the OS_* globals (readonly-collision scan, STATE
# DUMP, per-run reset) iterates these arrays instead of a hand-synced list, so
# a field can never be added, dumped, or guarded in one place and drift in
# another. Guarded so a caller that already owns the names keeps its bindings.
# (readonly -a, NOT declare -a: `declare` is scoped to the enclosing function
# when the library is sourced inside a function, which would silently destroy
# the SSOT list — readonly arrays keep global scope in that context.)
if ! declare -p _OS_FIELDS >/dev/null 2>&1; then
    readonly -a _OS_FIELDS=(OS_DETECTED OS_ID OS_ID_LIKE OS_NAME OS_VERSION
                            OS_VERSION_ID OS_VERSION_CODENAME OS_PRETTY_NAME
                            OS_DISTRO OS_ARCH OS_KERNEL OS_KERNEL_RELEASE
                            OS_CONTAINER OS_SOURCE OS_FALLBACK_USED
                            OS_TRUST_LEVEL)
fi
# The identity fields detect_os clears at the top of every run so a previous
# result can never bleed into the next; the kernel-metadata fields are included
# so a host-mode run can never leak its runner's kernel/arch into a later
# fixture run that serves a different identity. The three special fields
# (OS_DETECTED, OS_FALLBACK_USED, OS_CONTAINER) are assigned explicit values
# after the reset.
if ! declare -p _OS_RESET_FIELDS >/dev/null 2>&1; then
    readonly -a _OS_RESET_FIELDS=(OS_ID OS_ID_LIKE OS_NAME OS_VERSION
                                  OS_VERSION_ID OS_VERSION_CODENAME
                                  OS_PRETTY_NAME OS_DISTRO OS_SOURCE
                                  OS_TRUST_LEVEL OS_KERNEL OS_KERNEL_RELEASE
                                  OS_ARCH)
fi
# Internal scratch names the library writes. _os_last_detail, _os_log_file and
# _os_log_ready are ordinary writable global vars (not functions); _os_steps is
# written by detect_os as a LOCAL and read by _os_failure_record through bash
# dynamic scope. A caller-owned readonly binding of any of them would abort the
# caller's shell on assignment just like a readonly OS_* field, and a caller
# global _os_steps would be clobbered by the local on a *direct* call to
# _os_failure_record, so the collision guard treats all four as reserved:
# `_os_` is library-owned namespace in both the variable and function namespaces.
# _os_fn_collision/_os_fn_collided are set by the source-time function preflight
# and _os_fn_candidate is its loop variable — a caller-owned readonly binding of
# any of them would abort the caller's shell on assignment just as well.
if ! declare -p _OS_INTERNAL_SCRATCH >/dev/null 2>&1; then
    readonly -a _OS_INTERNAL_SCRATCH=(_os_last_detail _os_log_file _os_log_ready
                                     _os_steps _os_fn_collision _os_fn_collided
                                     _os_fn_candidate _os_env_failed)
fi

# ---------------------------------------------------------------------------
# Captured tool paths
# ---------------------------------------------------------------------------
# The external commands this library may use are resolved ONCE at source time
# into read-only slots. A caller that mutates PATH afterwards cannot silently
# swap what the library runs (e.g. a poisoned `uname` dropped earlier in PATH),
# and `command -v` lookups at call time are eliminated. Each slot is guarded
# so a caller already owning the name keeps its binding without an abort.
for _os_tool in _OS_UNAME:uname _OS_MKTEMP:mktemp _OS_LSBRELEASE:lsb_release \
                _OS_TIMEOUT:timeout _OS_ENV:env _OS_DATE:date _OS_MKDIR:mkdir \
                _OS_CHMOD:chmod _OS_WC:wc _OS_STAT:stat; do
    _os_var="${_os_tool%%:*}"; _os_cmd="${_os_tool#*:}"
    if ! declare -p "$_os_var" >/dev/null 2>&1; then
        readonly "$_os_var"="$(command -v "$_os_cmd" 2>/dev/null || true)"
    fi
done
# _os_tool, _os_var and _os_cmd are transient source-time scratch names that
# are unset immediately after the loop. `_os_` is library-owned namespace, so a
# caller that owns these names loses them at source time — the same contract as
# every other _os_ helper/scratch var (call-time command assume nothing here).
unset _os_tool _os_var _os_cmd

# uname is the only slot the library cannot degrade without a message: it is
# both the identity last resort and the kernel-metadata source. A missing
# uname at source time therefore warns once (tests at lines ~600 pin PATH to
# /nonexistent to exercise this), then detection degrades cleanly to rc 1.
# (Bare printf: the diagnostic helper is defined further down the file.)
if [ -z "$_OS_UNAME" ]; then
    printf '%s\n' "osdetect: uname was not found on PATH at source time — identity cannot resolve and kernel metadata will read unknown" >&2
fi
# env backs the redaction value-pass (pass 2 embedded-value scrub). Its
# absence does not break detection, but silences the strongest redaction tier,
# so it warns once at source time like uname does.
if [ -z "$_OS_ENV" ]; then
    printf '%s\n' "osdetect: env was not found on PATH at source time — redaction value-pass disabled" >&2
fi

# ---------------------------------------------------------------------------
# Observability helpers (all no-ops unless debug is active)
# ---------------------------------------------------------------------------

# NAME  _os_debug_active
# ARGS  none
# WHAT  true when _OS_DEBUG=1 or SCRIPT_DEBUG=1. Re-evaluated on every call,
#       so debug can be enabled mid-session without re-sourcing.
_os_debug_active() {
    [ "${_OS_DEBUG:-${SCRIPT_DEBUG:-0}}" = "1" ]
}

# NAME  _os_ensure_log_file
# ARGS  none
# WHAT  idempotently creates the debug log (mode 0600), echoes its path, and
#       writes the ==== START marker. Guarded against re-entry so chmod/start
#       happen exactly once; _os_runx may log back into it.
_os_ensure_log_file() {
    [ -n "${_os_log_ready:-}" ] && return 0
    _os_log_ready=1
    if [ -z "${_OS_LOG_FILE:-}" ]; then
        # Random name via mktemp so an untrusted /tmp peer cannot pre-plant a
        # symlink at a guessable "osdetect.$$" path and redirect the log (or
        # the chmod 600) onto a victim file. When mktemp is unavailable the
        # debug log warns once and degrades to OFF (writes fall to /dev/null)
        # rather than reverting to the guessable PID path the random-name
        # mechanism exists to avoid.
        _os_log_file=""
        if [ -n "$_OS_MKTEMP" ]; then
            _os_log_file="$(_os_runx "$_OS_MKTEMP" "${TMPDIR:-/tmp}/osdetect.XXXXXX" 2>/dev/null)" \
                || _os_log_file=""
        fi
        [ -n "$_os_log_file" ] && [ -n "$_OS_CHMOD" ] \
            && _os_runx "$_OS_CHMOD" 600 "$_os_log_file" || :
    else
        # Caller-chosen path: use it verbatim. The mode is the caller's own
        # business — forcing 0600 could clobber a deliberately-set mode or
        # follow a symlink the caller controls, so the library never chmods a
        # caller-supplied log file. It only warns when the mode exposes the
        # debug log (which carries redacted-but-still-data lines) to group or
        # other users.
        _os_log_file="$_OS_LOG_FILE"
        if ! : >> "$_os_log_file" 2>/dev/null; then
            _os_warn "debug requested but caller-supplied _OS_LOG_FILE is not writable — debug log is OFF"
            _os_log_file=""
            return 0
        fi
        if [ -n "$_OS_STAT" ]; then
            local logmode loggrouphot logotherbit l2
            logmode="$("$_OS_STAT" -c %a "$_os_log_file" 2>/dev/null)" || logmode=""
            # Last two octal digits, without the `${var: -2:1}` substring form
            # (negative offsets are bash 4.2+; this library keeps a 4.0 floor).
            l2="${logmode#"${logmode%??}"}"
            loggrouphot="${l2%?}"
            logotherbit="${l2#?}"
            case "${loggrouphot}${logotherbit}" in
                00) : ;;
                *)
                    _os_warn "caller-supplied _OS_LOG_FILE has group/world-visible mode $logmode (left unchanged per policy)" ;;
            esac
        fi
    fi
    if [ -z "$_os_log_file" ]; then
        _os_warn "debug requested but no writable log target (mktemp unavailable and no _OS_LOG_FILE) — debug log is OFF"
        return 0
    fi
    printf '%s\n' "osdetect debug log: $(_os_redact "$_os_log_file")" >&2
    _os_log "==== START pid=$$ file=${BASH_SOURCE[0]:-?} caller=$0"
}

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
            "\\")  out+="\\\\" ;;
            '"')  out+='\"' ;;
            $'\n') out+='\n' ;;
            $'\r') out+='\r' ;;
            $'\t') out+='\t' ;;
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

# NAME  _os_error_log_path
# ARGS  none
# WHAT  echoes the error log path: _OS_ERROR_LOG when set, otherwise
#       ${XDG_STATE_HOME}/osdetect/osdetect-failures.jsonl, falling back to
#       ${HOME}/.local/state/osdetect/osdetect-failures.jsonl and finally to
#       ${TMPDIR:-/tmp}/osdetect/osdetect-failures.jsonl when HOME is unset.
#       The state directory (never the source tree) is the default so a
#       read-only deployment cannot silently drop failure telemetry and no
#       run ever pollutes the directory the library is installed in.
_os_error_log_path() {
    if [ -n "${_OS_ERROR_LOG:-}" ]; then
        printf '%s\n' "$_OS_ERROR_LOG"
    elif [ -n "${XDG_STATE_HOME:-}" ]; then
        printf '%s\n' "$XDG_STATE_HOME/osdetect/osdetect-failures.jsonl"
    elif [ -n "${HOME:-}" ]; then
        printf '%s\n' "$HOME/.local/state/osdetect/osdetect-failures.jsonl"
    else
        printf '%s\n' "${TMPDIR:-/tmp}/osdetect/osdetect-failures.jsonl"
    fi
}

# NAME  _os_ensure_error_log
# ARGS  none
# WHAT  idempotently creates the failure log dir+file (mode 0600) and echoes
#       its path. Never chmods a caller-supplied _OS_ERROR_LOG path (same
#       policy as _OS_LOG_FILE). Fail-open: returns 1 on unwritable targets,
#       on symlinked targets/directories (a pre-planted symlink would make
#       the append and chmod hit an unrelated file), and when the caller set
#       _OS_NO_ERROR_LOG=1 (opt-out of the failure log entirely).
_os_ensure_error_log() {
    local target dir
    [ "${_OS_NO_ERROR_LOG:-0}" = "1" ] && return 1
    target="$(_os_error_log_path)"
    case "$target" in
        */*) dir="${target%/*}" ;;
        *)   dir="." ;;
    esac
    [ -L "$target" ] && return 1
    if [ -n "$_OS_MKDIR" ]; then
        "$_OS_MKDIR" -p "$dir" 2>/dev/null || return 1
    else
        return 1
    fi
    # Re-check after mkdir: an attacker can swap the target (or the directory)
    # for a symlink at any point up to the write.
    [ -L "$target" ] && return 1
    [ -L "$dir" ] && return 1
    : >> "$target" 2>/dev/null || return 1
    if [ -z "${_OS_ERROR_LOG:-}" ]; then
        [ -n "$_OS_CHMOD" ] && "$_OS_CHMOD" 600 "$target" 2>/dev/null || :
    elif [ -n "$_OS_STAT" ]; then
        local emode egroup eother l2
        emode="$("$_OS_STAT" -c %a "$target" 2>/dev/null)" || emode=""
        # Last two octal digits, without the `${var: -2:1}` substring form
        # (negative offsets are bash 4.2+; this library keeps a 4.0 floor).
        l2="${emode#"${emode%??}"}"
        egroup="${l2%?}"
        eother="${l2#?}"
        case "${egroup}${eother}" in
            00) : ;;
            *) _os_warn "caller-supplied _OS_ERROR_LOG has group/world-visible mode $emode (left unchanged per policy)" ;;
        esac
    fi
    printf '%s\n' "$target"
}

# NAME  _os_secret_name
# ARGS  variable name
# WHAT  rc 0 iff NAME matches the secret wordlist (case-insensitive). Six
#       tiers:
#         - substring words (pass/token/secret/cred/psk/jdbc/...) match names
#           that contain them anywhere, so MY_TOKEN or XTOKEN cannot slip
#           through by hiding the word inside a longer name;
#         - the collision-prone words key and auth must additionally sit at a
#           name-separator boundary (underscore, hyphen, or a name edge), so
#           API_KEY / ACCESS_KEY / KEY_ID / AUTH_TOKEN / bare KEY / bare AUTH
#           stay redacted while MONKEY, KEYBOARD, KEYRING, TURKEY, KEYMAP and
#           GIT_AUTHOR_NAME, AUTHOR (a person, not a credential) are not
#           mistaken for secrets and eaten out of legitimate log lines;
#         - whole-tail pwd spellings *pw/*pwd/*passwd (MAILPW, MYSQL_PWD,
#           PASSWD) — the working-directory variables bare PWD/OLDPWD are
#           paths, not credentials, and are excluded;
#         - whole-tail compound-key spellings *accesskey/*appkey/*apikey/
#           *secretkey/*authkey/*consumerkey (AWS_ACCESS_KEY_ID already
#           boundary-matches; S3ACCESSKEY/ANDROID_APPKEY hold the secret
#           without a separator and need their own tier);
#         - whole-tail token spellings *_pat/*_pem/*_jwt (a GitHub PAT, a
#           PEM key path, a JWT blob) plus the bare name `pat` — `pat` is too
#           collision-prone as a substring (patch/pattern/compat) to match
#           anywhere, so it is whole-name/whole-tail only;
#         - whole-tail *_db_url/*_db_uri/*_database_url/*_database_uri so a
#           MY_DB_URL-ish connection string is caught by name even though the
#           bare exact tier below only lists fixed spellings;
#         - exact whole names (database_url, postgres_url, ...) catch the
#           connection-string family whose name carries the secret even
#           though it contains no "secret" word.
#         - obfuscation/typo spellings (*pasw*/*secr*/*authid*/*authn*/
#           *keyid*/*keyl*/*crdt*) catch truncated or near-miss names that
#           would otherwise dodge the boundary rules above (AUTHID fails the
#           `auth` boundary because a digit follows; PASWRD contains no "pass").
#       Broad *url*/*uri* patterns are deliberately excluded: public
#       os-release fields HOME_URL/BUG_REPORT_URL/SUPPORT_URL would match
#       and their values would be eaten out of legitimate log lines.
_os_secret_name() {
    local name="${1,,}"
    case "$name" in
        *pass*|*token*|*secret*|*cred*|*cookie*|*psk*|*bearer*|*otp*|*mfa*|*dsn*|*jdbc*|*webhook*|*conn*string*|*connstr*)
            return 0 ;;
    esac
    # Space-padded so a name that *ends* in key/auth (OPENAI_API_KEY, AUTH)
    # is still boundary-matched by the trailing pad.
    case " $name " in
        *[^a-z0-9]key[^a-z0-9]*|*[^a-z0-9]auth[^a-z0-9]*)
            return 0 ;;
    esac
    case "$name" in
        pwd|oldpwd) ;;
        *pw|*pwd|*passwd)
            return 0 ;;
    esac
    case "$name" in
        *accesskey|*appkey|*apikey|*secretkey|*authkey|*consumerkey)
            return 0 ;;
    esac
    case "$name" in
        *_pat|*_pem|*_jwt|*_db_url|*_db_uri|*_database_url|*_database_uri|pat)
            return 0 ;;
    esac
    case "$name" in
        database_url|database_uri|redis_url|redis_uri|mongo_url|mongo_uri|mongodb_url|mongodb_uri|postgres_url|postgres_uri|pg_url|pguri|mysql_url|mysql_uri|elasticsearch_url|elasticsearch_uri|amqp_url|rabbitmq_url|kafka_url)
            return 0 ;;
    esac
    # Obfuscation/typo tier: truncated or near-miss spellings that survive real
    # codebases (PASWRD missing an s, SECR truncated, AUTHID/AUTHN/KEYID/KEYL
    # short common forms, CRDT swapped letters). These sit OUTSIDE the boundary
    # rules above (a trailing digit/letter would stop `auth`/`key` matching),
    # so without this tier `_os_secret_name` returns false and the value leaks
    # both as NAME=value and in the pass-2 scrub. Suffix-style matches, like
    # the *pw tier, tolerate arbitrary case.
    case "$name" in
        *pasw*|*secr*|*authid*|*authn*|*keyid*|*keyl*|*crdt*)
            return 0 ;;
    esac
    return 1
}

# NAME  _os_redact_shapes
# ARGS  one line of text
# WHAT  redacts credential VALUES by their shape, independent of variable
#       name: HTTP Authorization/Bearer headers, bare Bearer tokens, AWS
#       AKIA/ASIA access-key ids, JWT triple-dot blobs, PEM private-key
#       banners, and JSON `"key":"value"` credential pairs. This complements
#       _os_redact's name-driven passes, which cannot see `curl -H
#       "Authorization: Bearer eyJ..."` or `{"api_key":"sk-..."}` (no
#       NAME=value token for _os_secret_name to key on). Called only when
#       _os_redact's cheap shape gate already matched, so the common line pays
#       nothing. Uses no `\b` (bash ERE lacks it) and no external tools.
_os_redact_shapes() {
    local line="$1" tok
    # PEM private-key banner (normally its own log line): the whole line is
    # the secret, so it collapses to a single marker.
    case "$line" in
        *-----BEGIN*PRIVATE*KEY-----*)
            printf '%s\n' "[REDACTED]"
            return 0 ;;
    esac
    # Authorization: Bearer <token> (header or `=` form; %20 encodes a space).
    while [[ $line =~ (Authorization[[:space:]]*[:=][[:space:]]*Bearer)((%20|[[:space:]])+)([A-Za-z0-9._~+/=-]+) ]]; do
        tok="${BASH_REMATCH[0]}"
        line="${line/"$tok"/"${BASH_REMATCH[1]}${BASH_REMATCH[2]}[REDACTED]"}"
    done
    # Bare Bearer token (>=20 chars so prose words like "Bearer token" stay).
    while [[ $line =~ (Bearer)((%20|[[:space:]])+)([A-Za-z0-9._~+/=-]{20,}) ]]; do
        tok="${BASH_REMATCH[0]}"
        line="${line/"$tok"/"${BASH_REMATCH[1]}${BASH_REMATCH[2]}[REDACTED]"}"
    done
    # AWS access-key ids: AKIA/ASIA + 16 uppercase-alnum.
    while [[ $line =~ (AKIA|ASIA)[A-Z0-9]{16} ]]; do
        tok="${BASH_REMATCH[0]}"
        line="${line/"$tok"/[REDACTED]}"
    done
    # JWT: base64url header (eyJ...) . payload . signature.
    while [[ $line =~ eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+ ]]; do
        tok="${BASH_REMATCH[0]}"
        line="${line/"$tok"/[REDACTED]}"
    done
    # JSON credential pair: "key":"value" for any credential-ish key.
    # The loop must STOP when the value is already the [REDACTED] marker
    # (which the value class `\"[^\"]*\"` would otherwise re-match forever);
    # replacing the marker with itself would never converge.
    while [[ $line =~ (\"(private_key|client_secret|api_key|access_token|refresh_token|auth_token|secret_key|secret|password|passphrase|privateKey|clientSecret|apiKey|accessToken|refreshToken|authToken|secretKey|token)\"[[:space:]]*:[[:space:]]*)\"[^\"]*\" ]]; do
        tok="${BASH_REMATCH[0]}"
        qv="${BASH_REMATCH[1]}\"[REDACTED]\""
        [ "$tok" = "$qv" ] && break
        line="${line/"$tok"/"$qv"}"
    done
    printf '%s\n' "$line"
}

# NAME  _os_redact
# ARGS  one line of text
# WHAT  redacts secret material from the line and prints the (possibly
#       unchanged) line. Three passes — two name-driven via _os_secret_name
#       plus one shape-driven:
#         1. NAME=value tokens at a whitespace boundary whose name matches
#            the wordlist are replaced in full by [REDACTED] — any value
#            length, so a secret stored as a short (<4-char) value is caught
#            when written as NAME=value. When the checked env value (exported,
#            keyed by lowercased NAME) is in the line in full — including a
#            value containing spaces — the whole NAME=value region is
#            replaced; otherwise the truncated token is, as before. A value
#            with embedded whitespace is also rebuilt with a double-quoted
#            or a single-quoted wrapper, so a quoted NAME="sec ret" form
#            is consumed whole instead of leaking its post-space tail.
#         2. The values of wordlist-matched env vars (>=4 chars) are replaced
#            wherever they appear, longest value first, so a short prefix
#            value cannot leave a [REDACTED]def residuum behind.
#         3. Credential VALUES recognized by shape alone even when the NAME is
#            innocuous (Authorization/Bearer headers, AKIA/ASIA ids, JWTs,
#            PEM banners, JSON "key":"value" pairs) — see _os_redact_shapes.
#       A `=`-less env line is the continuation of the preceding = line's value
#       (env never starts a variable name without `=`), so a secret stored as
#       KEY=$'a\nb' is reassembled and its >=4-char segments — which land on
#       separate log lines — are each redacted. A continuation line that itself
#       contains `=` (KEY=$'a\nb=c' prints "b=c") is indistinguishable from a
#       new assignment and is a documented, irreducible ambiguity.
#       env() is exported-only; that is the documented enforcement boundary
#       (unexported shell vars are invisible here). Values shorter than 4
#       chars embedded in prose stay untouched so a common token like "/" or
#       "1" cannot corrupt every log line.
_os_redact() {
    local line="$1" name val envline envout rest out m pre begin previous envval cand q matched
    local prev_name="" seg
    local -a vals=()
    local -A conf=()
    # env() is captured into a here-string instead of `done < <(env)`: the
    # header promises no process substitution, and the substitution would make
    # the loop a pipeline subshell, silently dropping the edits to `line`.
    envout=""
    if [ -n "$_OS_ENV" ]; then
        envout="$("$_OS_ENV")" 2>/dev/null || {
            # A non-empty _OS_ENV that fails to run degrades value-pass to OFF
            # silently; warn once so a wrong path/env name cannot go unnoticed
            # forever, mirroring the source-time uname warning above. The
            # one-shot guard keeps repeated log lines from spamming stderr.
            if [ -z "$_os_env_failed" ]; then
                _os_env_failed=1
                _os_warn "caller-supplied _OS_ENV ($_OS_ENV) failed to run — environment value-scrub is OFF"
            fi
            envout=""
        }
    fi
    while IFS= read -r envline; do
        if [[ $envline != *"="* ]]; then
            # `=`-less env line = continuation of the previous = line's value.
            # Reassemble secret values split across lines (KEY=$'a\nb'); the
            # tail would otherwise leak onto its own log line.
            if [ -n "$prev_name" ] && _os_secret_name "$prev_name"; then
                conf[$prev_name]+=$'\n'"$envline"
            fi
            continue
        fi
        name="${envline%%=*}"
        val="${envline#*=}"
        prev_name="${name,,}"
        if _os_secret_name "$name"; then
            conf[${name,,}]="$val"
            # A case-variant pair (MYSECRET and mysecret) shares one lowercased
            # conf key, so the later line would overwrite the earlier and drop
            # its value from the pass-2 list below. Accumulate the raw values
            # inline as well so BOTH survive into the value scrub.
            [ "${#val}" -ge 4 ] && vals+=( "$val" )
        fi
    done <<< "$envout"
    # Pass-2 value list, built from the reassembled conf. A multi-line secret's
    # parts sit on separate log lines, so each >=4-char newline-segment is a
    # value-pass entry of its own.
    for name in "${!conf[@]}"; do
        _os_secret_name "$name" || continue
        if [[ ${conf[$name]} == *$'\n'* ]]; then
            while IFS= read -r seg; do
                [ "${#seg}" -ge 4 ] && vals+=( "$seg" )
            done <<< "${conf[$name]}"
        elif [ "${#conf[$name]}" -ge 4 ]; then
            vals+=( "${conf[$name]}" )
        fi
    done
    # Pass-2a: exported array/associative-array component values via
    # `declare -p`. bash CANNOT export structured variables into env(): an
    # `export -A CREDS=([token]=...)` puts the *name* on the export list but
    # its components never appear in `env` output — the env pass above would
    # miss the token value entirely and it would leak verbatim. `declare -p`
    # (a builtin — no fork) is the window that carries the component literals,
    # so each `[key]=value` slot of an exported array/assoc whose NAME matches
    # the wordlist is added to pass-2. Scalar values are deliberately left to
    # env(): an absent _OS_ENV still degrades scalar value-pass to OFF per the
    # documented contract, but structured values, which env() could NEVER see,
    # are always worth catching.
    local dline dname dseg seg dump
    local -a dsegs=()
    # One-fork dump, then a single anchored regex over the whole blob BEFORE
    # the per-line scan: iterating every declaration costs ~0.3ms/line, which
    # is pure waste on the common case where no exported structured secret
    # exists (an exported array/assoc cannot appear in env() output).
    dump="$(declare -p 2>/dev/null || true)"
    if [[ $dump =~ declare\ -[A-Za-z]*x[A-Za-z]*\ [A-Za-z0-9_]+=\( ]]; then
        while IFS= read -r dline; do
            # exported declaration (flag set contains x) whose value is an
            # array/assoc literal: `declare -Ax CREDS=(...)` — the value's very
            # first chars after the NAME-binding `=` are `(`.
            case "$dline" in
                "declare -"*"x"*"=("* ) ;;
                *) continue ;;
            esac
            dname="${dline%%=*}"
            dname="${dname##* }"                 # strip "declare -Ax " prefix
            # The name must be a bare shell identifier before it is ever used
            # as a variable reference in the `eval` below.
            case "$dname" in
                *[!A-Za-z0-9_]*) continue ;;
            esac
            _os_secret_name "$dname" || continue
            # Direct component read. The old slot-regex literal parser could
            # not see a value containing `]`, a newline, or an escaped quote;
            # reading the array itself yields every component exactly.
            # `declare -n` is unavailable (bash 4.3+; this library keeps the
            # bash 4.0 floor), so the read goes through `eval` — but the only
            # text reaching the evaluator is the regex-validated identifier
            # above, never caller data. This is the ONE documented eval
            # exception to the header's "no eval" promise.
            # shellcheck disable=SC1087  # ${NAME[@]} is built at eval time
            eval "dsegs=( \"\${$dname[@]}\" )"
            for dseg in "${dsegs[@]}"; do
                [ "${#dseg}" -ge 4 ] && vals+=( "$dseg" )
            done
        done <<< "$dump"
    fi
    # Insertion sort, longest value first.
    local i j current
    for (( i = 1; i < ${#vals[@]}; i++ )); do
        current="${vals[i]}"
        (( j = i - 1 )) || :
        while (( j >= 0 && ${#current} > ${#vals[j]} )); do
            vals[j+1]="${vals[j]}"
            (( j-- )) || :
        done
        vals[j+1]="$current"
    done
    # Pass 1: name-context token scan (leftmost maximal identifier run before
    # `=`; the run must start at a line/space boundary; leading digits are
    # admitted so names like 3DES_KEY redact too — non-secret matches are
    # re-emitted byte-for-byte, including any spaces the line put around `=`,
    # so `FOO = bar` is never reshaped into `FOO=bar`).
    rest="$line"
    out=""
    while [[ $rest =~ ([A-Za-z0-9_][A-Za-z0-9_]*)([[:space:]]*)=([[:space:]]*)([^[:space:]]*) ]]; do
        m="${BASH_REMATCH[0]}"
        pre="${rest%%"$m"*}"
        begin=${#pre}
        previous=""
        [ "$begin" -gt 0 ] && previous="${rest:begin-1:1}"
        out+="$pre"
        if { [ "$begin" -eq 0 ] || [[ "$previous" != [A-Za-z0-9_] ]]; } \
            && _os_secret_name "${BASH_REMATCH[1]}"; then
            out+="[REDACTED]"
            # Reconstruct the line's own NAME <ws> = <ws> VALUE region from
            # the env value when the name is a known secret and the env value
            # is present and non-empty; try the bare, double-quoted and
            # single-quoted forms and consume whichever is longer than the
            # match and actually present. A known-secret name with NO env
            # value simply advances past the matched token (the value is
            # redacted by name, as before).
            matched=0
            if [ "${conf[${BASH_REMATCH[1],,}]+set}" = "set" ] \
                && [ -n "${conf[${BASH_REMATCH[1],,}]}" ]; then
                envval="${conf[${BASH_REMATCH[1],,}]}"
                for q in '' '"' "'"; do
                    cand="${BASH_REMATCH[1]}${BASH_REMATCH[2]}=${BASH_REMATCH[3]}${q}${envval}${q}"
                    if [ "${#cand}" -gt "${#m}" ] \
                        && [[ "${rest:begin:${#cand}}" == "$cand" ]]; then
                        rest="${rest:begin+${#cand}}"
                        matched=1
                        break
                    fi
                done
            fi
            [ "$matched" -eq 1 ] || rest="${rest:begin+${#m}}"
        else
            out+="$m"
            rest="${rest:begin+${#m}}"
        fi
    done
    line="$out$rest"
    # Pass 2: embedded value replacement (>=4 chars), longest first.
    local v
    for v in "${vals[@]}"; do
        line="${line//"$v"/[REDACTED]}"
    done
    # Pass 3: value-shape credentials the name-driven passes cannot see
    # (innocuous NAME, `Authorization: Bearer`, bare cloud tokens) or that are
    # shattered by quoting/encoding (JSON `"key":"value"`). A cheap case gate
    # keeps the common line out of the regex path entirely.
    case "$line" in
        *Bearer*|*bearer*|*AKIA*|*ASIA*|*eyJ*|*-----BEGIN*|*PRIVATE*KEY-----*|*private_key*|*privateKey*|*client_secret*|*clientSecret*|*access_token*|*accessToken*|*refresh_token*|*refreshToken*|*api_key*|*apiKey*|*password*|*passphrase*|*secret*|*token*)
            line="$(_os_redact_shapes "$line")" ;;
    esac
    printf '%s\n' "$line"
}

# NAME  _os_failure_record
# ARGS  none (reads run-scoped _os_steps array + OS_* globals)
# WHAT  appends one NDJSON identity-unresolved event to the failure log.
#       All values are redacted before JSON-encoding. Fail-open: an
#       unwritable log never changes detect_os rc. The human-visible stderr
#       diagnostic is emitted by detect_os at the unresolved path, not here.
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
    for fname in OS_ID OS_ID_LIKE OS_NAME OS_VERSION OS_PRETTY_NAME OS_SOURCE OS_TRUST_LEVEL; do
        fval="$(_os_redact "${!fname:-}")"; fval="${fval%$'\n'}"
        fs="$(_os_json_escape "$fval")"
        [ -n "$finals_json" ] && finals_json+=","
        finals_json+="\"${fname#OS_}\":\"$fs\""
    done
    finals_json+=",\"FALLBACK\":$([ "${OS_FALLBACK_USED:-0}" = "1" ] && printf '%s' true || printf '%s' false)"
    local line=""
    line+="{\"ts\":\"$(_os_json_escape "$(${_OS_DATE:-:} -u '+%FT%TZ')")\""
    line+=",\"pid\":$$"
    line+=",\"caller\":\"$(_os_json_escape "$(_os_redact "$0")")\""
    line+=",\"lib\":\"$(_os_json_escape "$(_os_redact "${BASH_SOURCE[0]##*/}")")\""
    line+=",\"version\":\"$(_os_json_escape "$_OS_VERSION")\""
    line+=",\"_os_root\":$([ -n "${_OS_ROOT:-}" ] && printf '%s' true || printf '%s' false)"
    line+=",\"uname\":$([ -n "$_OS_UNAME" ] && printf '%s' true || printf '%s' false)"
    line+=",\"outcome\":\"identity-unresolved\""
    line+=",\"steps\":[$steps_json]"
    line+=",\"finals\":{$finals_json}"
    line+="}"
    printf '%s\n' "$line" >> "$target" 2>/dev/null || :
    return 0
}

# NAME  _os_log_raw
# ARGS  message
# WHAT  appends the message to the debug log verbatim.
_os_log_raw() {
    _os_debug_active || return 0
    _os_ensure_log_file
    printf '%s %s\n' "$(${_OS_DATE:-:} '+%F %T')" "$*" >> "${_os_log_file:-/dev/null}" 2>/dev/null || :
}

# NAME  _os_log
# ARGS  message
# WHAT  _os_log_raw with secret-value redaction applied.
_os_log() {
    _os_debug_active || return 0
    _os_ensure_log_file
    printf '%s %s\n' "$(${_OS_DATE:-:} '+%F %T')" "$(_os_redact "$*")" >> "${_os_log_file:-/dev/null}" 2>/dev/null || :
}

# NAME  _os_stage
# ARGS  stage label
# WHAT  logs a "=== STAGE:" marker at every phase boundary.
_os_stage() {
    _os_log "=== STAGE: $*"
}

# NAME  _os_enter / _os_exit
# ARGS  none
# WHAT  log ENTER/EXIT markers naming the calling function (no-op unless debug).
_os_enter() {
    _os_log "ENTER ${FUNCNAME[1]:-?}"
}
_os_exit() {
    _os_log "EXIT ${FUNCNAME[1]:-?}"
}

# NAME  _os_runx
# ARGS  command + args
# WHAT  runs an external command, logging "EXEC: ..." and "RC=n", and returns
#       the command's status. Safe under caller strict mode: a failing command
#       never triggers errexit because of the || fallback.
_os_runx() {
    _os_log "EXEC: $*"
    local rc=0
    "$@" || rc=$?
    _os_log "RC=$rc"
    return "$rc"
}

# NAME  _os_warn
# ARGS  message
# WHAT  prints a message to the caller's stderr (human diagnostics).
_os_warn() {
    printf '%s\n' "osdetect: $*" >&2
}

# NAME  _os_field_listed
# ARGS  name
# WHAT  true when the name is one of the OS_* destination fields (see
#       _OS_FIELDS, the SSOT vocabulary) or one of the _os_* internal scratch
#       names the library writes globally (see _OS_INTERNAL_SCRATCH). Returns
#       1 for any other name so a caller-owned variable near-but-not-in the
#       vocabulary (e.g. OS_FUTURE) is never reported.
_os_field_listed() {
    local n
    # The SSOT arrays are normally readonly arrays (top of the file), but a
    # caller that already owned the names keeps its binding — which could be a
    # scalar. Iterating a scalar with "${a[@]}" yields the scalar as one bogus
    # element, so fall back to the literal SSOT union in that case.
    if [[ "$(declare -p _OS_FIELDS 2>/dev/null || true)" == *"declare -a"* ]] \
        && [[ "$(declare -p _OS_INTERNAL_SCRATCH 2>/dev/null || true)" == *"declare -a"* ]]; then
        for n in "${_OS_FIELDS[@]}" "${_OS_INTERNAL_SCRATCH[@]}"; do
            [ "$n" = "$1" ] && return 0
        done
        return 1
    fi
    for n in OS_DETECTED OS_ID OS_ID_LIKE OS_NAME OS_VERSION OS_VERSION_ID \
             OS_VERSION_CODENAME OS_PRETTY_NAME OS_DISTRO OS_ARCH OS_KERNEL \
             OS_KERNEL_RELEASE OS_CONTAINER OS_SOURCE OS_FALLBACK_USED \
             OS_TRUST_LEVEL _os_last_detail _os_log_file _os_log_ready \
             _os_steps _os_fn_collision _os_fn_collided _os_fn_candidate; do
        [ "$n" = "$1" ] && return 0
    done
    return 1
}

# NAME  _os_is_readonly
# ARGS  variable name
# WHAT  rc 0 iff NAME is readonly in the caller's shell (handles both `declare
#       -r NAME` and `readonly NAME` formats, mirroring _os_readonly_collision).
_os_is_readonly() {
    local name="$1" line flags varname
    while IFS= read -r line; do
        case "$line" in
            "declare -"*|readonly*) ;;
            *) continue ;;
        esac
        case "$line" in
            readonly*) flags="readonly" ;;
            *)         line="${line#declare }"; flags="${line%% *}" ;;
        esac
        case "$flags" in *r*) ;; *) continue ;; esac
        varname="${line#* }"; varname="${varname%%=*}"
        if [ "$varname" = "$name" ]; then
            return 0
        fi
    done <<< "$(readonly -p 2>/dev/null || true)"
    return 1
}

# NAME  _os_readonly_collision
# ARGS  none
# WHAT  detects whether any destination OS_* global is already readonly in the
#       caller's shell (readonly scalar/array/assoc, set or unset). Writing a
#       readonly name aborts the caller's shell even without set -e, so
#       detect_os refuses up front instead. Always returns 0; the colliding
#       name (if any) is the only stdout, so callers can use command
#       substitution without tripping a strict-mode abort.
# NOTE  `readonly -p` prints BOTH formats by bash lineage: `declare -r NAME`
#       (modern, non-posix) and bare `readonly NAME` (bash 4.0-4.4 and/or
#       `set -o posix`). A scan that only understood `declare -r` would miss
#       the second, and the later write would abort the caller's shell with
#       exit 127 — which is exactly the abort this guard exists to prevent.
# RET   0 always; stdout empty when everything is writable, else the name.
_os_readonly_collision() {
    local ro line flags varname
    ro="$(readonly -p 2>/dev/null)" || ro=""
    while IFS= read -r line; do
        case "$line" in
            "declare -"*|readonly*) ;;
            *) continue ;;
        esac
        case "$line" in
            readonly*) flags="readonly" ;;
            *)         line="${line#declare }"; flags="${line%% *}" ;;
        esac
        case "$flags" in *r*) ;; *) continue ;; esac
        varname="${line#* }"; varname="${varname%%=*}"
        if _os_field_listed "$varname"; then
            printf '%s\n' "$varname"
            return 0
        fi
    done <<< "$ro"
    return 0
}

# NAME  _os_dump_state
# ARGS  none
# WHAT  appends a "---- STATE DUMP" block of all OS_* globals (redacted).
_os_dump_state() {
    _os_debug_active || return 0
    local name
    {
        printf '%s\n' "---- STATE DUMP"
        for name in "${_OS_FIELDS[@]}"; do
            _os_redact "${name}=${!name-}"
        done
        printf '%s\n' "---- END STATE DUMP"
    } >> "${_os_log_file:-/dev/null}" 2>/dev/null || :
}

# ---------------------------------------------------------------------------
# Path & string helpers
# ---------------------------------------------------------------------------

# NAME  _os_file_ok
# ARGS  absolute path [, max_bytes]
# WHAT  rc 0 iff the path is a regular readable file whose byte count is <=
#       max_bytes (default 262144). -f rejects FIFOs/devices/dirs that would
#       block or error on read; the size cap keeps a hostile/garbled multi-GB
#       "release" file from being slurped into the caller's memory by
#       `read -r`. The byte count is read from stat (metadata only — the file
#       content is NEVER read before the cap is applied, so a hostile multi-GB
#       file is rejected without wc having to consume it), falling back to wc
#       when stat is unavailable. Empty files deliberately PASS (legacy
#       markers like arch-release are legitimately empty — presence is the
#       signal; empty content files simply yield no ID and defer). Symlinks
#       are rejected outright (see body). When both stat and wc are
#       unavailable the cap is still enforced by a bounded read of max+1
#       chars (not bytes — see body) and the file is never slurped whole.
_os_file_ok() {
    local f="$1" max="${2:-262144}" bytes _os_cap_probe
    [ -f "$f" ] && [ -r "$f" ] || return 1
    # A symlink is rejected outright: a release marker an attacker with /etc
    # write could point anywhere, and following it opens a TOCTOU window
    # between this check and the later read. These paths are never legitimately
    # symlinks (Debian's /etc/os-release is a real file, not a link).
    [ -L "$f" ] && return 1
    if [ -n "$_OS_STAT" ]; then
        bytes="$("$_OS_STAT" -c %s "$f" 2>/dev/null)" || return 1
        bytes="${bytes//[!0-9]/}"
        [ -n "$bytes" ] && [ "$bytes" -le "$max" ] || return 1
    elif [ -n "$_OS_WC" ]; then
        bytes="$("$_OS_WC" -c < "$f" 2>/dev/null)" || return 1
        bytes="${bytes//[!0-9]/}"
        [ -n "$bytes" ] && [ "$bytes" -le "$max" ] || return 1
    else
        # Neither stat nor wc: cap WITHOUT slurping the file by reading at
        # most max+1 characters. A fill of max+1 characters means oversize; a
        # short read (EOF, rc 1) means it fits. The -d '' NUL delimiter stops
        # the probe at EOF instead of at the first newline: `read -r -n N`
        # alone returns rc 0 on the first delimiter, which would wrongly
        # reject every well-formed multi-line release file. The redirect
        # keeps a hostile/again-changing file from aborting the caller.
        # Note: read counts CHARACTERS, so in this tool-less path a hostile
        # multibyte file may draw up to ~4x the cap before rejection — the cap
        # stays a byte-tight DoS bound whenever stat (or wc) is present, and
        # the file is never slurped whole either way.
        if IFS= read -r -d '' -n "$(( max + 1 ))" _os_cap_probe < "$f" 2>/dev/null; then
            return 1
        fi
    fi
    return 0
}

# NAME  _os_file_probe
# ARGS  absolute path (e.g. /etc/os-release)
# WHAT  returns the effective path under $_OS_ROOT when set (test/chroot hook).
_os_file_probe() {
    local root="${_OS_ROOT:-}" p="$1"
    if [ -z "$root" ]; then
        printf '%s\n' "$p"
        return 0
    fi
    case "$root" in */) root="${root%/}" ;; esac
    case "$p" in /*) p="${p#/}" ;; esac
    printf '%s\n' "$root/$p"
}

# NAME  _os_sanitize_id
# ARGS  raw string
# WHAT  maps a loosely-written distro name onto the ID character set per the
#       os-release spec: lowercase [0-9a-z._-]; anything else becomes _.
#       When the input contains no charset character at all (e.g. ID="@@@@"
#       from a hostile file), the output is empty instead of a string of
#       underscores — a fabricated ID (e.g. "____") could let a hostile
#       file force a fake identity. Caller must not treat an empty result
#       as a valid ID.
# WHY   the Bashism ${var,,} keeps this bash-only, which is fine — callers
#       are bash.
_os_sanitize_id() {
    local s="${1//[^a-zA-Z0-9._-]/_}"
    # If the original input contains no id-charset character at all
    # (e.g. ID="@@@@" from a hostile file), fabricating an ID like
    # "____" could let a hostile file force a fake identity.
    case "$1" in
        *[a-zA-Z0-9._-]*) : ;;
        *) printf '%s\n' ""; return 0 ;;
    esac
    s="${s,,}"
    printf '%s\n' "$s"
}

# NAME  _os_sanitize_version
# ARGS  raw string
# WHAT  maps a version string onto the script-safe charset [0-9a-zA-Z._+-];
#       anything else (shell metachars, quotes, whitespace, control chars)
#       becomes _. os_version() documents its output as script-safe, so a
#       hostile release file can never smuggle `;`, `$()`, etc. into callers
#       that interpolate the field unquoted.
_os_sanitize_version() {
    local s="$1"
    s="${s//[^0-9a-zA-Z._+-]/_}"
    printf '%s\n' "$s"
}

# NAME  _os_sanitize_display
# ARGS  raw string
# WHAT  allowlist-scrubs a human display field (PRETTY_NAME/NAME/VERSION/
#       CODENAME/ID_LIKE). ASCII bytes outside the printable-safe set are
#       removed outright; high bytes pass only as part of a well-formed
#       UTF-8 multibyte sequence so terminal display keeps its fidelity.
#       C1 control characters (U+0080-009F), overlong encodings, invalid or
#       truncated sequences, surrogates, noncharacters, and the invisible
#       format controls (zero-width U+200B-200F, bidi U+202A-202E, interlinear
#       annotation U+2066-206F) are dropped, as are any codepoints past
#       U+10FFFF. Leading/trailing whitespace is trimmed. The kept set is
#       [A-Za-z0-9] plus space and . _ : / , + = ( ) @ % ^ — every quote,
#       backslash, backtick, glob and brace metachar, `;`, `$` and all C0
#       controls / DEL sit outside it, so a hostile release file can never
#       smuggle `echo "$OS_DISTRO"` terminal-escape injection, an invisible
#       bidi-reordering payload, a shell metachar, a glob pattern, or an
#       unquoted-for-loop word into a caller that interpolates the field.
_os_sanitize_display() {
    local s="$1" out="" c i code cp need=0 k ok
    local LC_ALL=C
    for (( i = 0; i < ${#s}; i++ )); do
        c="${s:i:1}"
        case "$c" in
            [[:alnum:]]|" "|"."|"_"|"-"|":"|"/"|","|"+"|"="|"("|")"|"@"|"%"|"^")
                out+="$c"; continue ;;
        esac
        # Non-allowlisted byte: numeric value. < 128 is disallowed ASCII
        # (quotes, backslash, glob/brace/shell metachars, C0 controls, DEL).
        code="$(printf '%d' "'$c" 2>/dev/null)" || continue
        [ "$code" -lt 128 ] && continue
        # Multibyte length from the lead byte: C2-DF = 1 continuation,
        # E0-EF = 2, F0-F4 = 3. Overlong leads C0-C1, lone continuation
        # bytes 0x80-BF, and 0xF5-FF are dropped.
        case "$code" in
            194|195|196|197|198|199|200|201|202|203|204|205|206|207) need=1; cp=$(( code & 31 )) ;;
            224|225|226|227|228|229|230|231|232|233|234|235|236|237|238|239) need=2; cp=$(( code & 15 )) ;;
            240|241|242|243|244) need=3; cp=$(( code & 7 )) ;;
            *) continue ;;
        esac
        ok=1
        for (( k = 1; k <= need; k++ )); do
            [ $(( i + k )) -lt "${#s}" ] || { ok=0; break; }
            c="${s:i+k:1}"
            code="$(printf '%d' "'$c" 2>/dev/null)" || { ok=0; break; }
            if [ "$code" -lt 128 ] || [ "$code" -gt 191 ]; then ok=0; break; fi
            cp=$(( (cp << 6) | (code & 63) ))
        done
        # Reject overlong encodings, C1 controls (U+0080-009F), zero-width /
        # bidi / annotation format controls, surrogates, noncharacters, and
        # anything past U+10FFFF. The modulo check catches every plane's
        # U+xFFFE/U+xFFFF pair. A dropped lead leaves the offending byte to be
        # reclassified on the next iteration.
        if [ "$ok" -ne 1 ] \
            || { [ "$need" -eq 1 ] && [ "$cp" -lt 128 ]; } \
            || { [ "$need" -eq 2 ] && [ "$cp" -lt 2048 ]; } \
            || { [ "$need" -eq 3 ] && [ "$cp" -lt 65536 ]; } \
            || { [ "$cp" -ge 128 ] && [ "$cp" -le 159 ]; } \
            || { [ "$cp" -ge 8203 ] && [ "$cp" -le 8207 ]; } \
            || { [ "$cp" -ge 8234 ] && [ "$cp" -le 8238 ]; } \
            || { [ "$cp" -ge 8288 ] && [ "$cp" -le 8303 ]; } \
            || { [ "$cp" -ge 55296 ] && [ "$cp" -le 57343 ]; } \
            || [ $(( cp % 65536 )) -ge 65534 ] \
            || [ "$cp" -gt 1114111 ]; then
            continue
        fi
        out+="${s:i:$(( need + 1 ))}"
    done
    # Trim leading/trailing whitespace so a padded release value cannot smuggle
    # a boundary space into callers that compare or interpolate the field.
    out="${out#"${out%%[![:space:]]*}"}"
    out="${out%"${out##*[![:space:]]}"}"
    printf '%s\n' "$out"
}

# NAME  _os_unquote
# ARGS  a raw os-release value line
# WHAT  strips a matching leading/trailing quote pair so that
#       ID_LIKE="rhel fedora" yields  rhel fedora. Values containing C-style
#       escapes ($'...') are unsupported by design — they never appear in
#       distro release files of record.
_os_unquote() {
    local v="$1"
    if [ "${v#\"}" != "$v" ] && [ "${v%\"}" != "$v" ]; then
        v="${v#\"}"; v="${v%\"}"
    elif [ "${v#\'}" != "$v" ] && [ "${v%\'}" != "$v" ]; then
        v="${v#\'}"; v="${v%\'}"
    fi
    printf '%s\n' "$v"
}

# NAME  _os_first_line
# ARGS  file path
# WHAT  prints the first non-blank, non-comment line of a release file;
#       returns 1 on empty/unreadable file.
_os_first_line() {
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        line="${line#$'\xef\xbb\xbf'}"
        case "$line" in
            ''|\#*) continue ;;
        esac
        printf '%s\n' "$line"
        return 0
    done < "$1"
    return 1
}

# NAME  _os_first_version_token
# ARGS  a content line
# WHAT  prints the first dotted numeric token (e.g. 9.3 in "release 9.3 (Plano)"),
#       returns 1 when the line has no version digits (rolling/empty releases).
_os_first_version_token() {
    if [[ "$1" =~ [0-9][0-9]*(\.[0-9]+)* ]]; then
        printf '%s\n' "${BASH_REMATCH[0]}"
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Family content parsers
# ---------------------------------------------------------------------------

# NAME  _os_parse_fedora_family_content
# ARGS  content line of a redhat/centos/system-release file
# WHAT  maps the line onto an ID. Returns 1 if the vendor text is unrecognized.
_os_parse_fedora_family_content() {
    local line="$1" ver
    case "$line" in
        *"Fedora"*)    OS_ID=fedora ;;
        *"CentOS"*)    OS_ID=centos;  OS_ID_LIKE="rhel fedora" ;;
        *"Rocky"*)     OS_ID=rocky;   OS_ID_LIKE="rhel centos fedora" ;;
        *"AlmaLinux"*) OS_ID=almalinux; OS_ID_LIKE="rhel centos fedora" ;;
        *"Red Hat"*)   OS_ID=rhel ;;
        *) return 1 ;;
    esac
    OS_PRETTY_NAME="$(_os_sanitize_display "$line")"
    ver="$(_os_first_version_token "$line")" && OS_VERSION_ID="$ver"
    return 0
}

# ---------------------------------------------------------------------------
# Ladder steps
# ---------------------------------------------------------------------------

# NAME  _os_parse_os_release_file
# ARGS  os-release file path [, reset]
# WHAT  parses KEY="VALUE" pairs into the OS_* globals (both casings).
#       WHY plain .-source is avoided: ID, NAME, VERSION and PRETTY_NAME are
#       extremely common variable names that would clobber the caller's shell;
#       a field-scoped parse keeps the library namespace-safe.
#       With the second arg "reset" the identity fields are cleared first, so
#       a partial /etc/os-release (e.g. NAME but no ID) is never mixed with a
#       /usr/lib/os-release that provides the missing pieces — fields always
#       come from ONE file, never several.
# RET   0 if an ID was parsed, 1 otherwise.
_os_parse_os_release_file() {
    local f="$1" k v line parsed_id
    if [ "${2:-}" = "reset" ]; then
        OS_ID="" OS_ID_LIKE="" OS_NAME="" OS_VERSION="" OS_VERSION_ID=""
        OS_VERSION_CODENAME="" OS_PRETTY_NAME=""
        OS_SOURCE="" OS_TRUST_LEVEL=""
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        line="${line#$'\xef\xbb\xbf'}"
        case "$line" in
            ''|\#*) continue ;;
            *=*)
                k="${line%%=*}"; v="$(_os_unquote "${line#*=}")"
                case "$k" in
                    ID|id)             [ -n "$v" ] && { parsed_id="$(_os_sanitize_id "$v")"; if [ -n "$parsed_id" ]; then OS_ID="$parsed_id"; OS_SOURCE="$f"; fi; } ;;
                    ID_LIKE|id_like)   [ -n "$v" ] && OS_ID_LIKE="$(_os_sanitize_display "$v")" ;;
                    NAME|name)         [ -n "$v" ] && OS_NAME="$(_os_sanitize_display "$v")" ;;
                    VERSION|version)   [ -n "$v" ] && OS_VERSION="$(_os_sanitize_display "$v")" ;;
                    VERSION_ID|version_id) [ -n "$v" ] && OS_VERSION_ID="$(_os_sanitize_version "$v")" ;;
                    VERSION_CODENAME|version_codename) [ -n "$v" ] && OS_VERSION_CODENAME="$(_os_sanitize_display "$v")" ;;
                    PRETTY_NAME|pretty_name) [ -n "$v" ] && OS_PRETTY_NAME="$(_os_sanitize_display "$v")" ;;
                esac
                ;;
        esac
    done < "$f"
    [ -n "${OS_ID:-}" ]
}

# NAME  _os_read_os_release
# ARGS  none
# WHAT  step 1 of the ladder: /etc/os-release, falling back to
#       /usr/lib/os-release. A PRESENT file with a real ID wins: /usr/lib
#       takes over the whole identity (reset) when the /etc file could not
#       supply one. A present-but-ID-less (or 0-byte, or non-regular) file
#       claims nothing and defers to the rest of the ladder — ID=linux is only
#       ever emitted by the uname last resort, so a fallback paternity claim
#       can never disguise itself as an os-release hit.
# RET   0 detected (a real ID was parsed), 1 neither file yielded an ID.
_os_read_os_release() {
    _os_enter
    local f_e f_u
    f_e="$(_os_file_probe /etc/os-release)"
    f_u="$(_os_file_probe /usr/lib/os-release)"
    # _os_file_ok rejects FIFOs/devices/dirs that would block or error on
    # read, treats a 0-byte file as absent, and caps the byte count (wc) so a
    # maliciously oversized release file cannot be slurped into memory.
    if _os_file_ok "$f_e"; then
        _os_parse_os_release_file "$f_e" || true   # parse may find no ID
    fi
    if [ -z "${OS_ID:-}" ] && _os_file_ok "$f_u"; then
        # takeover: /usr/lib owns the whole identity, drop any partial /etc
        # fields so OS_NAME==Leftover can never pair with OS_ID=fedora
        _os_parse_os_release_file "$f_u" reset || true
    fi
    if [ -n "${OS_ID:-}" ]; then
        OS_TRUST_LEVEL=high
        _os_exit
        return 0
    fi
    # ID-less os-release: clear the partial identity fields so a later ladder
    # step owns the whole identity and nothing mixes with it.
    OS_ID="" OS_ID_LIKE="" OS_NAME="" OS_VERSION=""
    OS_VERSION_ID="" OS_VERSION_CODENAME="" OS_PRETTY_NAME=""
    OS_TRUST_LEVEL=none
    local de du
    de="absent"; du="absent"
    [ -f "$f_e" ] && de="present"
    [ -f "$f_u" ] && du="present"
    _os_last_detail="/etc/os-release $de (no ID), /usr/lib/os-release $du (no ID)"
    _os_exit
    return 1
}

# NAME  _os_parse_lsb_release
# ARGS  none
# WHAT  step 2: parse /etc/lsb-release directly (no command dependency).
# RET   0 if DISTRIB_ID gave an ID, 1 otherwise.
_os_parse_lsb_release() {
    _os_enter
    local f k v line
    f="$(_os_file_probe /etc/lsb-release)"
    if ! _os_file_ok "$f"; then
        _os_last_detail="/etc/lsb-release absent"
        _os_exit; return 1
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        line="${line#$'\xef\xbb\xbf'}"
        case "$line" in
            ''|\#*) continue ;;
            *=*)
                k="${line%%=*}"; v="$(_os_unquote "${line#*=}")"
                case "$k" in
                    DISTRIB_ID)          [ -n "$v" ] && OS_ID="$(_os_sanitize_id "$v")" ;;
                    DISTRIB_RELEASE)     [ -n "$v" ] && OS_VERSION_ID="$(_os_sanitize_version "$v")" ;;
                    DISTRIB_CODENAME)    [ -n "$v" ] && OS_VERSION_CODENAME="$(_os_sanitize_display "$v")" ;;
                    DISTRIB_DESCRIPTION) [ -n "$v" ] && OS_PRETTY_NAME="$(_os_sanitize_display "$v")" ;;
                esac
                ;;
        esac
    done < "$f"
    if [ -n "${OS_ID:-}" ]; then
        OS_SOURCE="$f"; OS_TRUST_LEVEL=medium; _os_exit; return 0
    fi
    local ld
    ld="absent"
    [ -f "$f" ] && ld="present (no DISTRIB_ID)"
    OS_VERSION_ID="" OS_VERSION_CODENAME="" OS_PRETTY_NAME=""
    OS_TRUST_LEVEL=none
    _os_last_detail="/etc/lsb-release $ld"
    _os_exit
    return 1
}

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

# NAME  _os_run_lsb_cmd
# ARGS  none
# WHAT  step 3: read ID/version/codename/description via the lsb_release
#       command when present (older Ubuntu/Debian line).
# RET   0 if an ID came back, 1 otherwise.
_os_run_lsb_cmd() {
    _os_enter
    local v
    if [ -z "$_OS_LSBRELEASE" ]; then
        _os_last_detail="lsb_release command not found on PATH"
        _os_exit; return 1
    fi
    # Host isolation: when probing a fake/chroot root (_OS_ROOT), the pinned
    # `lsb_release` binary answers for the HOST, not the target — its output
    # would leak host identity into a cross-env detection. Only the file-based
    # step (/etc/lsb-release under $_OS_ROOT) is authoritative there, so the
    # command is never consulted when a root prefix is set.
    if [ -n "${_OS_ROOT:-}" ]; then
        _os_last_detail="lsb_release command disabled under _OS_ROOT (host isolation)"
        _os_exit; return 1
    fi
    # Bound lsb_release with coreutils `timeout` when present at source time —
    # it can hang on broken systems. Absent timeout -> unbounded legacy
    # behavior. A run killed by timeout (rc 124) is treated exactly like a
    # missing command, so a hung probe can never stall or fail detection.
    # All four probes share ONE 5-second budget (SECONDS = shell runtime):
    # the first call inherits the full budget and each later call only gets
    # whatever remains, so a pathological lsb_release can cost at most ~5s
    # total instead of 5s per invocation.
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
}

# NAME  _os_parse_legacy
# ARGS  none
# WHAT  step 4: legacy /etc release files. Presence is the identity signal for
#       the "empty-file" markers (arch, gentoo, alpine); content is parsed for
#       versioned ones. A catch-all then claims any remaining /etc/*-release
#       whose <id>-release basename yields a valid ID (nobara, mageia, ...).
# RET   0 if an ID was assigned, 1 otherwise.
_os_parse_legacy() {
    _os_enter
    local d line v lc
    d="$(_os_file_probe /etc)"

    # --- Debian: /etc/debian_version (content is the version) ---
    if _os_file_ok "$d/debian_version"; then
        OS_ID=debian; OS_SOURCE="$d/debian_version"; OS_NAME="Debian"
        OS_TRUST_LEVEL=medium
        line="$(_os_first_line "$d/debian_version")" || line=""
        # codename/sid lines are words, not versions — keep VERSION_ID empty
        [ -n "$line" ] && OS_PRETTY_NAME="$(_os_sanitize_display "$line")"
        v="$(_os_first_version_token "$line")" && OS_VERSION_ID="$v"
        _os_exit; return 0
    fi

    # --- Arch: empty marker file ---
    if _os_file_ok "$d/arch-release"; then
        OS_ID=arch; OS_SOURCE="$d/arch-release"; OS_NAME="Arch Linux"
        OS_TRUST_LEVEL=medium
        _os_exit; return 0
    fi

    # --- Gentoo: marker with version text ---
    if _os_file_ok "$d/gentoo-release"; then
        OS_ID=gentoo; OS_SOURCE="$d/gentoo-release"; OS_NAME="Gentoo"
        OS_TRUST_LEVEL=medium
        line="$(_os_first_line "$d/gentoo-release")" || line=""
        [ -n "$line" ] && OS_PRETTY_NAME="$(_os_sanitize_display "$line")"
        v="$(_os_first_version_token "$line")" && OS_VERSION_ID="$v"
        _os_exit; return 0
    fi

    # --- Alpine: version-only file ---
    if _os_file_ok "$d/alpine-release"; then
        OS_ID=alpine; OS_SOURCE="$d/alpine-release"; OS_NAME="Alpine Linux"
        OS_TRUST_LEVEL=medium
        line="$(_os_first_line "$d/alpine-release")" || line=""
        [ -n "$line" ] && OS_VERSION_ID="$(_os_sanitize_version "$line")"
        _os_exit; return 0
    fi

    # --- Oracle: /etc/oracle-release must be checked BEFORE the Fedora-family
    #     loop — Oracle ships a RHEL-compatible /etc/redhat-release whose text
    #     ("Red Hat Enterprise Linux ...") would otherwise win and mislabel the
    #     host as rhel instead of ol.
    if _os_file_ok "$d/oracle-release"; then
        line="$(_os_first_line "$d/oracle-release")" || line=""
        case "$line" in
            *"Oracle"*)
                OS_ID=ol; OS_NAME="Oracle Linux"; OS_ID_LIKE="rhel centos fedora"; OS_SOURCE="$d/oracle-release"
                OS_TRUST_LEVEL=medium
                [ -n "$line" ] && OS_PRETTY_NAME="$(_os_sanitize_display "$line")"
                v="$(_os_first_version_token "$line")" && OS_VERSION_ID="$v"
                _os_exit; return 0 ;;
        esac
    fi

    # --- Fedora-family: redhat-release / centos-release / fedora-release /
    #     rocky-release / almalinux-release ---
    # Trust is a function of the marker's authority (a vendored release file in
    # /etc), NOT of which vendor happens to name it: fedora/rocky/almalinux get
    # the same medium trust as centos/redhat here instead of falling to the
    # low-trust catch-all below.
    for rel in redhat-release centos-release fedora-release rocky-release almalinux-release; do
        if _os_file_ok "$d/$rel"; then
            line="$(_os_first_line "$d/$rel")" || continue
            if _os_parse_fedora_family_content "$line"; then
                OS_SOURCE="$d/$rel"; OS_TRUST_LEVEL=medium; _os_exit; return 0
            fi
        fi
    done

    # --- system-release (Amazon Linux, Oracle Linux, or other family text) ---
    if _os_file_ok "$d/system-release"; then
        line="$(_os_first_line "$d/system-release")" || line=""
        case "$line" in
            *"Amazon"*) OS_ID=amzn; OS_NAME="Amazon Linux"; OS_ID_LIKE="rhel fedora" ;;
            *"Oracle"*) OS_ID=ol;   OS_NAME="Oracle Linux"; OS_ID_LIKE="rhel centos fedora" ;;
        esac
        # unrecognized vendor text falls through to the catch-all below
        if [ -z "${OS_ID:-}" ]; then
            _os_parse_fedora_family_content "$line" || true
        fi
        if [ -n "${OS_ID:-}" ]; then
            OS_SOURCE="$d/system-release"
            OS_TRUST_LEVEL=medium
            [ -n "$line" ] && OS_PRETTY_NAME="$(_os_sanitize_display "$line")"
            v="$(_os_first_version_token "$line")" && OS_VERSION_ID="$v"
            _os_exit; return 0
        fi
    fi

    # --- SUSE / openSUSE ---
    # Both casings are probed: older SUSE wrote /etc/SuSE-release, while
    # openSUSE Leap/Tumbleweed and newer SLES write /etc/suse-release (the
    # catch-all below deliberately skips both). Matching the lowercased CONTENT
    # keeps vendor detection case-insensitive, so a file that says "opensuse"
    # still lands on the right ID and a Tumbleweed line still wins over its
    # substring "opensuse".
    for asuse in SuSE-release suse-release; do
        if _os_file_ok "$d/$asuse"; then
            line="$(_os_first_line "$d/$asuse")" || line=""
            lc="${line,,}"
            case "$lc" in
                *tumbleweed*) OS_ID=opensuse-tumbleweed; OS_NAME="openSUSE Tumbleweed" ;;
                *leap*)       OS_ID=opensuse-leap;       OS_NAME="openSUSE Leap" ;;
                *opensuse*)   OS_ID=opensuse;            OS_NAME="openSUSE" ;;
                *)            OS_ID=sles;                OS_NAME="SUSE Linux Enterprise" ;;
            esac
            OS_SOURCE="$d/$asuse"
            OS_TRUST_LEVEL=medium
            [ -n "$line" ] && OS_PRETTY_NAME="$(_os_sanitize_display "$line")"
            case "$OS_ID" in
                opensuse-tumbleweed) ;;          # rolling: "version" is a build date
                *) v="$(_os_first_version_token "$line")" && OS_VERSION_ID="$v" ;;
            esac
            _os_exit; return 0
        fi
    done

    # --- Catch-all: any remaining <id>-release / <id>_release file ---
    # WHY presence is the signal even for unknown vendored files, which keeps
    # the undetected-OS rate low; the id is the basename minus its suffix.
    # The globs are expanded into an array (quoted on iteration) so paths that
    # contain spaces survive word-splitting, and `-f` rejects directories,
    # FIFOs and symlink-to-dir entries that would otherwise error on read.
    local files f base id
    files=("$d"/*-release "$d"/*_release)
    for f in "${files[@]}"; do
        _os_file_ok "$f" || continue
        base="${f##*/}"
        case "$base" in
            os-release|usr-os-release|lsb-release|system-release         \
            |SuSE-release|suse-release|redhat-release|centos-release     \
            |fedora-release|rocky-release|almalinux-release              \
            |oracle-release|arch-release|gentoo-release|alpine-release)
                continue ;;
            # CPE metadata files (<id>-release-cpe) are NOT matched by the
            # *-release/*_release globs above, so they can never reach this
            # case; the arm is intentionally absent — do NOT broaden the glob
            # to `*-release*` to re-add it, or CPE files silently become
            # catch-all identity claims.
        esac
        id="${base%-release}"; id="${id%_release}"
        id="$(_os_sanitize_id "$id")"
        [ -n "$id" ] || continue
        OS_ID="$id"; OS_SOURCE="$f"; OS_TRUST_LEVEL=low
        line="$(_os_first_line "$f")" || line=""
        [ -n "$line" ] && OS_PRETTY_NAME="$(_os_sanitize_display "$line")"
        v="$(_os_first_version_token "$line")" && OS_VERSION_ID="$v"
        _os_exit; return 0
    done
    _os_last_detail="no legacy release file matched in /etc"
    OS_TRUST_LEVEL=none
    _os_exit
    return 1
}

# NAME  _os_uname_fallback
# ARGS  none
# WHAT  step 5 / last resort: derive an ID from `uname -s`. The ID is the
#       kernel name lowercased (so a Linux host resolves to ID=linux, the
#       os-release spec default) and OS_SOURCE records it.
# RET   0 if uname produced a usable ID, 1 if even uname is unavailable.
_os_uname_fallback() {
    _os_enter
    local s
    s="$(_os_runx "$_OS_UNAME" -s 2>/dev/null)" || s=""
    s="$(_os_sanitize_id "$s")"
    if [ -n "$s" ]; then
        OS_ID="$s"; OS_SOURCE="uname"; OS_TRUST_LEVEL=low
        [ "$s" = "linux" ] && OS_NAME="Linux"
        _os_exit; return 0
    fi
    _os_last_detail="uname produced no usable ID"
    OS_TRUST_LEVEL=none
    _os_exit
    return 1
}

# NAME  _os_detect_container
# ARGS  none
# WHAT  records OS_CONTAINER: docker | podman | oci | containers | none.
#       Never consulted for the distribution ID — container buildsteps still
#       inherit the host/chroot distribution from the ladder above.
# NAME  _os_container_from_file
# ARGS  path to a /run/.containerenv-style file
# WHAT  prints docker|podman|oci|containers (never none) from an engine= line;
#       rc 1 when no engine= line is present. Kept separate so the file parse
#       is testable on its own and _os_detect_container stays branch-simple.
_os_container_from_file() {
    local file="$1" line v
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        case "$line" in
            engine=*)
                v="${line#*=}"; v="$(_os_unquote "$v")"
                case "$v" in
                    *podman*) printf '%s\n' podman; return 0 ;;
                    *crun*)   printf '%s\n' podman; return 0 ;;
                    *)        printf '%s\n' oci;    return 0 ;;
                esac ;;
        esac
    done < "$file"
    return 1
}

# NAME  _os_detect_container
# ARGS  none
# WHAT  records OS_CONTAINER: docker | podman | oci | containers | none.
#       docker via /.dockerenv, podman/oci via /run/.containerenv, and the
#       ROOTLESS podman case via a /run/user/<uid>/.containerenv marker (no
#       /run/.containerenv, no engine line — presence is all that is known, so
#       the honest verdict is `containers`). Never consulted for the
#       distribution ID — container buildsteps still inherit the host/chroot
#       distribution from the ladder above.
_os_detect_container() {
    _os_enter
    local df ce line dir cf
    OS_CONTAINER=none
    df="$(_os_file_probe /.dockerenv)"
    ce="$(_os_file_probe /run/.containerenv)"
    if [ -f "$df" ]; then
        OS_CONTAINER=docker
    elif _os_file_ok "$ce" 4096; then
        # podman's /run/.containerenv carries an engine="podman|crun"
        # variable; `runc` stays generic OCI, never podman-branded. The small
        # size cap keeps a hostile multi-GB file from being slurped.
        if line="$(_os_container_from_file "$ce")"; then
            OS_CONTAINER="$line"
        else
            OS_CONTAINER=containers
        fi
    else
        # Rootless podman mounts the marker under /run/user/<uid>/ and creates
        # no /run/.containerenv. Any such marker means "inside a container"
        # but reveals no runtime.
        dir="$(_os_file_probe /run/user)"
        for cf in "$dir"/*/.containerenv; do
            if [ -f "$cf" ]; then
                OS_CONTAINER=containers
                break
            fi
        done
    fi
    _os_exit
}

# NAME  _os_compose_distro
# ARGS  none
# WHAT  builds OS_DISTRO, the best-effort human display string, preferring
#       PRETTY_NAME then NAME+VERSION then the bare ID. When even the ID is
#       unresolved OS_DISTRO stays EMPTY — a literal "Linux" would present a
#       failed detection as a real answer (see detect_os rc 1 path).
_os_compose_distro() {
    local n v
    if [ -n "${OS_PRETTY_NAME:-}" ]; then
        OS_DISTRO="$OS_PRETTY_NAME"
    elif [ -n "${OS_ID:-}" ]; then
        n="${OS_NAME:-}"
        v="${OS_VERSION:-${OS_VERSION_ID:-}}"
        if [ -n "$n" ]; then
            if [ -n "$v" ]; then OS_DISTRO="$n $v"; else OS_DISTRO="$n"; fi
        else
            OS_DISTRO="$OS_ID"
        fi
    else
        OS_DISTRO=""
    fi
}

# NAME  _os_reset_identity
# ARGS  none
# WHAT  clears every WRITABLE field in _OS_RESET_FIELDS so a previous run's
#       identity or kernel metadata can never bleed into the next run. Called
#       at the top of every detect_os run AND before each refusal return: a
#       refused run returns rc 1, so it must not leave a prior
#       OS_ID/OS_TRUST_LEVEL readable as if that truth were this run's answer.
#       Caller-owned readonly fields are skipped — clearing them would abort
#       the caller's shell, and they are the caller's binding to leave alone.
_os_reset_identity() {
    local name
    for name in "${_OS_RESET_FIELDS[@]}"; do
        _os_is_readonly "$name" || printf -v "$name" '%s' ''   # %s (not '') — empty *format* does not assign under bash 4.0
    done
}

# NAME  _os_reset_runmarkers
# ARGS  none
# WHAT  clears the three run-scoped marker fields (OS_DETECTED,
#       OS_FALLBACK_USED, OS_CONTAINER) on every refusal and at the top of
#       every normal run. OS_CONTAINER is cleared to "" (not "none") so a
#       refused run cannot present a container verdict as truth; a successful
#       run assigns "none" later in _os_detect_container. Each write is skipped
#       when the caller owns the name readonly: a bare `OS_DETECTED=0` on a
#       readonly name aborts the caller's shell even without set -e, which is
#       exactly the abort the refusal guards exist to prevent.
_os_reset_runmarkers() {
    _os_is_readonly OS_DETECTED      || OS_DETECTED=0
    _os_is_readonly OS_FALLBACK_USED || OS_FALLBACK_USED=0
    _os_is_readonly OS_CONTAINER     || OS_CONTAINER=""
}

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

# NAME  detect_os
# ARGS  none
# WHAT  runs the full detection ladder + metadata capture and populates every
#       OS_* global (see the header table). Re-runs fresh on every call.
# GLOBALS WRITTEN   OS_DETECTED OS_ID OS_ID_LIKE OS_NAME OS_VERSION
#                   OS_VERSION_ID OS_VERSION_CODENAME OS_PRETTY_NAME OS_DISTRO
#                   OS_ARCH OS_KERNEL OS_KERNEL_RELEASE OS_CONTAINER
#                   OS_SOURCE OS_FALLBACK_USED OS_TRUST_LEVEL
# RET   0 detected, 1 identity could not be resolved (kernel metadata still set
#       in host mode; stays empty under a _OS_ROOT fixture, which never consults
#       the runner's uname)
detect_os() {
    _os_enter
    if [ "${_os_fn_collision:-0}" = "1" ]; then
        _os_warn "refusing to run: generic function name(s)$_os_fn_collided clobbered at source time — identity fields cleared, nothing else written"
        _os_reset_runmarkers
        _os_reset_identity
        _os_exit
        return 1
    fi
    local collision
    collision="$(_os_readonly_collision)"
    if [ -n "$collision" ]; then
        _os_warn "cannot overwrite caller-owned readonly $collision — identity fields cleared, nothing else written"
        # The identity fields from a prior successful run are wiped so the
        # consumer sees only stale emptiness paired with rc 1; the readonly
        # collision name itself is left untouched (clearing it would abort
        # the caller's shell). The run markers go through the readonly-safe
        # helper so an OS_DETECTED/OS_FALLBACK_USED/OS_CONTAINER collision
        # never aborts either.
        _os_reset_identity
        _os_reset_runmarkers
        _os_exit
        return 1
    fi
    _os_reset_identity
    _os_reset_runmarkers

    _os_stage "identity-detection"
    local -a _os_steps=()
    _os_last_detail=""   # global scratch: the ladder helpers write it, detect_os reads it
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

    _os_stage "kernel-metadata"
    # Kernel metadata is capped at the ladder result, never the runner: under
    # _OS_ROOT the fixture defines the identity, and uname -s/-r/-m would
    # silently record the RUNNER's host kernel/arch into OS_KERNEL/OS_ARCH —
    # contaminating every fixture assertion with non-deterministic leakage. In
    # fixture mode the fields stay as reset; the identity may still fall back
    # to uname (the documented last resort) separately.
    if [ -z "${_OS_ROOT:-}" ]; then
        local _os_kv
        _os_kv="$(_os_runx "$_OS_UNAME" -s 2>/dev/null)" || _os_kv=unknown
        OS_KERNEL="$(_os_sanitize_version "$_os_kv")"
        _os_kv="$(_os_runx "$_OS_UNAME" -r 2>/dev/null)" || _os_kv=unknown
        OS_KERNEL_RELEASE="$(_os_sanitize_version "$_os_kv")"
        _os_kv="$(_os_runx "$_OS_UNAME" -m 2>/dev/null)" || _os_kv=unknown
        OS_ARCH="$(_os_sanitize_version "$_os_kv")"
    fi

    _os_stage "distro-name"
    _os_compose_distro

    _os_stage "container-detection"
    _os_detect_container

    if [ -n "${OS_ID:-}" ]; then
        OS_DETECTED=1
        _os_log "RESOLVED ID=${OS_ID} SOURCE=${OS_SOURCE:-unknown} FALLBACK=$OS_FALLBACK_USED"
        _os_dump_state
        _os_exit
        return 0
    fi
    OS_DETECTED=0
    OS_TRUST_LEVEL=none
    _os_log "!! ERROR identity could not be resolved"
    # A resolved identity is silent, so an unresolved one must be LOUD on the
    # caller's stderr: the NDJSON failure log is telemetry, not a diagnostic a
    # human will see, and a silent rc 1 looks indistinguishable from an rc 0
    # that never ran. The log path is mentioned only when a record will
    # actually be written (opt-out/unwritable stays exit-status-only but the
    # warning above still fires).
    _os_warn "identity could not be resolved across the detection ladder — OS_DETECTED=0"
    if [ "${_OS_NO_ERROR_LOG:-0}" != "1" ]; then
        _os_warn "failure record: $(_os_redact "$(_os_error_log_path)")"
    fi
    _os_dump_state
    _os_failure_record
    _os_exit
    return 1
}

# ---------------------------------------------------------------------------
# Field accessor functions (echo empty string when unset; rc 0)
# ---------------------------------------------------------------------------
os_id()              { printf '%s\n' "${OS_ID:-}"; }
os_like()            { printf '%s\n' "${OS_ID_LIKE:-}"; }
os_name()            { printf '%s\n' "${OS_NAME:-}"; }
os_version()         { printf '%s\n' "${OS_VERSION_ID:-}"; }   # script-safe version
os_version_full()    { printf '%s\n' "${OS_VERSION:-}"; }       # human version string
os_codename()        { printf '%s\n' "${OS_VERSION_CODENAME:-}"; }
os_pretty()          { printf '%s\n' "${OS_PRETTY_NAME:-}"; }
os_distro()          { printf '%s\n' "${OS_DISTRO:-}"; }
os_arch()            { printf '%s\n' "${OS_ARCH:-}"; }
os_kernel()          { printf '%s\n' "${OS_KERNEL:-}"; }
os_kernel_release()  { printf '%s\n' "${OS_KERNEL_RELEASE:-}"; }
os_container()       { printf '%s\n' "${OS_CONTAINER:-}"; }
os_source()          { printf '%s\n' "${OS_SOURCE:-}"; }
os_trust_level()     { printf '%s\n' "${OS_TRUST_LEVEL:-}"; }
os_detected()        { [ "${OS_DETECTED:-0}" = "1" ]; }        # guard: if os_detected

# ---------------------------------------------------------------------------
# Direct-execution guard (library is source-only)
# ---------------------------------------------------------------------------
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    printf '%s\n' "fx-detect-os.sh $_OS_VERSION is a source-only library — do not execute directly." >&2
    printf '%s\n' "Usage:  . ${0##*/}    then:   detect_os && echo \"\${OS_ID}\"" >&2
    exit 2
fi

# Load-completion marker (see source-guard note at the top of the file). Must
# be the last line: its presence proves every function above ran.
_os_loaded() { :; }
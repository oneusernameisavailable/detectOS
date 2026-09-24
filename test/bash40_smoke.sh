#!/usr/bin/env bash
# Real bash-4.0 runtime smoke: source the library and exercise its main
# contract under an actual bash 4.0 binary (bundled by the bash:4.0 image),
# guarding the documented 4.0 floor far harder than the static regex test.
# Run directly with the host bash:
#     bash test/bash40_smoke.sh /path/to/fx-detect-os.sh
# and inside the container via the bats wrapper (test/detect_os.bats).
# Only bash 4.0 features are used here, on purpose.
# shellcheck disable=SC1003,SC2015,SC2016
# shellcheck source=../fx-detect-os.sh
set -u
# shellcheck disable=SC1090,SC1091
. "${1:?usage: bash40_smoke.sh /path/to/fx-detect-os.sh}"
fails=0
ok() { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; fails=$((fails + 1)); }

root=$(mktemp -d "${TMPDIR:-/tmp}/os40.XXXXXX")
mkdir -p "$root/etc"
export _OS_ROOT="$root" _OS_NO_ERROR_LOG=1

# os-release present -> identified fast and confidently
printf 'ID=debian\nVERSION_ID="12"\nNAME="Debian GNU/Linux"\n' > "$root/etc/os-release"
detect_os; rc=$?
[ "$rc" -eq 0 ]           && ok "detect_os rc=0 (os-release)"  || bad "detect_os rc=$rc (os-release)"
[ "${OS_ID:-}" = debian ] && ok "OS_ID=debian"                 || bad "OS_ID=${OS_ID:-}"
[ "${OS_TRUST_LEVEL:-}" = high ] && ok "trust=high (os-release)" || bad "trust=${OS_TRUST_LEVEL:-} (os-release)"

# empty os-release -> fallback, still rc 0, never high
: > "$root/etc/os-release"
detect_os; rc=$?
[ "$rc" -eq 0 ] && ok "detect_os rc=0 (empty)" || bad "detect_os rc=$rc (empty)"
case "${OS_TRUST_LEVEL:-}" in
    none|low) ok "trust=${OS_TRUST_LEVEL:-} (empty)" ;;
    *)        bad "trust=${OS_TRUST_LEVEL:-} (empty)" ;;
esac

# oversized file -> skipped (rc 0), never high
{ printf 'ID=huge\n'; head -c 300000 /dev/zero | tr '\0' 'A'; } > "$root/etc/os-release"
detect_os; rc=$?
[ "$rc" -eq 0 ]      && ok "detect_os rc=0 (oversize)" || bad "detect_os rc=$rc (oversize)"
[ "${OS_TRUST_LEVEL:-}" != high ] && ok "trust!=high (oversize)" || bad "trust=${OS_TRUST_LEVEL:-} (oversize)"

# redaction of env-wordlist secrets
secret="kx${RANDOM}${RANDOM}pz"
export MY_TOKEN="$secret" SECRET_KEY="$secret"
out=$(_os_redact "SECRET_KEY=$secret TOKEN=abc https://u:$secret@h junk")
case "$out" in
    *"$secret"*) bad "redact leaked secret: $out" ;;
    *)           ok "redact scrubbed secret" ;;
esac

# sanitizer invariants (id/version charsets, display whole-string scrub)
id=$(_os_sanitize_id 'Dist7_!@#x')
case "$id" in
    *[!a-z0-9._-]*) bad "sanitize_id bad: $id" ;;
    *)              ok "sanitize_id charset" ;;
esac
ver=$(_os_sanitize_version 'v1;x`y')
case "$ver" in
    *[!0-9a-zA-Z._+-]*) bad "sanitize_version bad: $ver" ;;
    *)                  ok "sanitize_version charset" ;;
esac
disp=$(_os_sanitize_display 'N$o;`\"'"'"'x')   # / is allowlisted (kept); fixture avoids it so the scrub is Nox
[ "$disp" = "Nox" ] && ok "sanitize_display scrub" || bad "sanitize_display: $disp"

rm -rf "$root"
[ "$fails" -eq 0 ] || { printf 'bash-4.0 smoke FAILURES: %d\n' "$fails" >&2; exit 1; }
printf 'bash-4.0 smoke: all ok\n'
exit 0
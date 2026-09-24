#!/usr/bin/env bash
# Fuzz: detect_os always returns 0 and yields a valid trust level for random-
# sized os-release files. Run by test/detect_os.bats in an untrapped child
# shell: each detect_os run executes hundreds of commands, and bats' DEBUG
# trap on @test bodies taxes every one (~1.7s per run); here it is ~50ms.
# Isolated via a fresh _OS_ROOT; no failure records are written.
# Exit status: 0 = all iterations valid, non-zero = violation (details on stderr).
# shellcheck source=../fx-detect-os.sh
set -u
# shellcheck disable=SC1091
. "${1:?usage: fuzz_detect.sh /path/to/fx-detect-os.sh}"
root=$(mktemp -d "${TMPDIR:-/tmp}/osdetect-fuzz.XXXXXX")
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/etc"
export _OS_ROOT="$root" _OS_NO_ERROR_LOG=1
for i in $(seq 1 40); do
    : > "$root/etc/os-release"
    printf 'ID=fuzz\n' > "$root/etc/os-release"
    detect_os; rc=$?
    [ "$rc" -eq 0 ] || { printf 'rc=%s at fill iter=%s\n' "$rc" "$i" >&2; exit 1; }
    case "${OS_TRUST_LEVEL:-}" in high|medium|low|none) ;; *) printf 'bad fill trust: %s\n' "${OS_TRUST_LEVEL:-}" >&2; exit 1 ;; esac
    # random-size file either parsed (max 1 byte under normal size) or skipped:
    { printf 'ID=randx\n'; head -c "$((RANDOM % 200000))" /dev/zero | tr '\0' 'A'; } > "$root/etc/os-release"
    detect_os; rc=$?
    [ "$rc" -eq 0 ] || { printf 'rc=%s at rand iter=%s\n' "$rc" "$i" >&2; exit 1; }
    case "${OS_TRUST_LEVEL:-}" in high|none|low) ;; *) printf 'bad rand trust: %s\n' "${OS_TRUST_LEVEL:-}" >&2; exit 1 ;; esac
done
exit 0
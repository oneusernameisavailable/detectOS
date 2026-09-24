#!/usr/bin/env bash
# Fuzz: sanitizer invariants hold for random inputs. Run by test/detect_os.bats
# in an untrapped child shell for the same reason as fuzz_redact.sh.
# Exit status: 0 = invariants held, non-zero = violated (details on stderr).
# shellcheck disable=SC1003,SC2016,SC2034
# shellcheck source=../fx-detect-os.sh
set -u
# shellcheck disable=SC1091
. "${1:?usage: fuzz_sanitize.sh /path/to/fx-detect-os.sh}"
for i in $(seq 1 200); do
    raw="Dist${RANDOM}_$(printf 'x%02d' $((RANDOM % 64)))"
    id="$(_os_sanitize_id "$raw")"
    # id charset is [0-9a-z._-]; empty only when raw had no id-chars
    case "$id" in
        *[^a-z0-9._-]*) printf 'bad id chars: %s\n' "$id" >&2; exit 1 ;;
    esac
    ver="$(_os_sanitize_version "v${RANDOM};x\`y")"
    case "$ver" in
        *[^0-9a-zA-Z._+-]*) printf 'bad version chars: %s\n' "$ver" >&2; exit 1 ;;
    esac
    disp="$(_os_sanitize_display "Name ${RANDOM}\$;\`'\"")"
    for bad in '$' ';' '`' "'" '"' '\'; do
        [[ "$disp" == *"$bad"* ]] && { printf 'display kept forbidden byte: %s\n' "$disp" >&2; exit 1; }
    done
    # deterministic whole-string scrub: id-chars survive, metachars die
    [ "$(_os_sanitize_display 'ab;c`d\e'"'"'f"g$h')" = "abcdefgh" ] || { printf 'deterministic scrub failed\n' >&2; exit 1; }
done
exit 0
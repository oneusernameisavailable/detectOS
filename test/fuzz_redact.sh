#!/usr/bin/env bash
# Fuzz: _os_redact must never leak wordlist values into output.
# Run by test/detect_os.bats in an untrapped child shell: bats installs a
# DEBUG trap on @test bodies whose per-command cost turns a 200-iteration
# loop into ~30s of wall time; the same loop here runs in milliseconds.
# The coverage is identical -- the loop only calls _os_redact.
# Exit status: 0 = property held, non-zero = leaked (details on stderr).
set -u
lib=${1:?usage: fuzz_redact.sh /path/to/fx-detect-os.sh}
# shellcheck disable=SC1090
. "$lib"
secret="kx ${RANDOM}${RANDOM}pz"
export MY_TOKEN="$secret" SECRET_KEY="$secret"
for i in $(seq 1 200); do
    case $(( i % 4 )) in
        0) line="tok=${RANDOM} SECRET_KEY=$secret TOKEN=abc https://u:$secret@h tail$i" ;;
        1) line="pre cfg SECRET_KEY=\"$secret\" TOKEN=abc tail$i" ;;
        2) line="pre cfg MY_TOKEN='$secret' TOKEN=abc tail$i" ;;
        3) line="declare -- MY_TOKEN=\"$secret\" TOKEN=abc tail$i" ;;
    esac
    out="$(_os_redact "$line")"
    [[ "$out" != *"$secret"* ]] || { printf 'leak@%s: %s\n' "$i" "$out" >&2; exit 1; }
    [[ "$out" != *"TOKEN=abc"* ]] || { printf 'nameleak@%s: %s\n' "$i" "$out" >&2; exit 1; }
done
exit 0
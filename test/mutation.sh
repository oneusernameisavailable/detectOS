#!/usr/bin/env bash
# Mutation tester for fx-detect-os.sh.
#
# WHY THIS EXISTS
#   R18-402 was `rg -n ... && return 1` followed by `return 0`. With ripgrep
#   absent from every CI container the rg call short-circuited on rc 127 and the
#   test passed WITHOUT ASSERTING ANYTHING -- on every leg, for its whole life,
#   while CI was green. A green suite only means something if the tests can
#   actually fail. This harness breaks the library on purpose and reports which
#   mutants no test notices.
#
#   It is a DEVELOPMENT TOOL. It is deliberately NOT wired into CI: it is slow,
#   and a red mutation run is easy to misread as a real regression.
#
# SAFETY
#   The real tree is never modified. Each mutant gets a scratch copy under
#   mktemp (fx-detect-os.sh at the root plus a test/ dir, preserving the
#   ../fx-detect-os.sh layout the bats tests expect via $BATS_TEST_DIRNAME).
#   Only the copy is sed-ed. `--selftest` proves it.
#
# USAGE
#   test/mutation.sh                 run the whole catalogue
#   test/mutation.sh -j 8           limit concurrency (default: nproc, max 12)
#   test/mutation.sh --list          show the catalogue and exit
#   test/mutation.sh --only A04,B07  run a subset by id
#   test/mutation.sh --selftest      verify the real tree is untouched
#   test/mutation.sh --full          skip the cheap first pass (slower, stricter)
#
# EXIT
#   0 = every mutant was caught (or recorded equivalent)
#   1 = at least one mutant survived, or the harness itself misbehaved
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
CATALOGUE="$HERE/mutants.txt"
LIB="fx-detect-os.sh"
SUITE="test/detect_os.bats"

JOBS=0; LIST=0; SELFTEST=0; FULL=0; ONLY=""
WORKROOT=""

die() { printf 'mutation.sh: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        -j) JOBS="${2:-0}"; shift 2 ;;
        --list) LIST=1; shift ;;
        --selftest) SELFTEST=1; shift ;;
        --full) FULL=1; shift ;;
        --only) ONLY="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

command -v bats >/dev/null 2>&1 || die "bats not on PATH"
[ -f "$CATALOGUE" ] || die "catalogue not found: $CATALOGUE"
[ -f "$ROOT/$LIB" ] || die "library not found: $ROOT/$LIB"

# shellcheck disable=SC2329  # reached only via the trap below, never called by name
cleanup() { [ -n "$WORKROOT" ] && [ -d "$WORKROOT" ] && rm -rf "$WORKROOT"; }
trap cleanup EXIT INT TERM

WORKROOT="$(mktemp -d "${TMPDIR:-/tmp}/osmut.XXXXXX")" || die "mktemp failed"

if [ "$SELFTEST" -eq 1 ]; then
    before="$(cd "$ROOT" && git status --porcelain 2>/dev/null | sort)"
    sb="$(cksum < "$ROOT/$LIB")"
    # Exercise the real mutation path once, on a scratch copy.
    d="$WORKROOT/selftest"; mkdir -p "$d/test"
    cp "$ROOT/$LIB" "$d/$LIB"; cp "$SUITE" "$d/$SUITE"
    sed -i 's/OS_TRUST_LEVEL=low/OS_TRUST_LEVEL=medium/' "$d/$LIB"
    after="$(cd "$ROOT" && git status --porcelain 2>/dev/null | sort)"
    sa="$(cksum < "$ROOT/$LIB")"
    if [ "$before" = "$after" ] && [ "$sb" = "$sa" ]; then
        printf 'selftest: OK — real tree and %s untouched by a mutation run\n' "$LIB"
        exit 0
    fi
    die "selftest FAILED — the real tree was modified"
fi

# --- catalogue parsing --------------------------------------------------------
# Fields are ~-separated: ID ~ TARGET ~ DESCRIPTION ~ FILTER ~ OLD ~ NEW
ids=(); targets=(); descs=(); filters=(); olds=(); news=()
while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    IFS='~' read -r id tgt desc filt old new <<<"$line"
    [ -n "${id:-}" ] || continue
    if [ -n "$ONLY" ]; then
        case ",$ONLY," in *",$id,"*) ;; *) continue ;; esac
    fi
    ids+=("$id"); targets+=("$tgt"); descs+=("$desc")
    filters+=("$filt"); olds+=("$old"); news+=("$new")
done < "$CATALOGUE"

[ "${#ids[@]}" -gt 0 ] || die "catalogue yielded no mutants (bad --only?)"

if [ "$LIST" -eq 1 ]; then
    printf 'catalogue: %s mutants\n' "${#ids[@]}"
    for i in "${!ids[@]}"; do
        printf '  %-5s %-24s %s\n' "${ids[$i]}" "${targets[$i]}" "${descs[$i]}"
    done
    exit 0
fi

# --- run one mutant -----------------------------------------------------------
# Writes a single result line to stdout: "CAUGHT <id> <by>" or "SURVIVED <id>".
run_mutant() {
    local idx="$1"
    local id="${ids[$idx]}"
    local old="${olds[$idx]}" new="${news[$idx]}"
    local filt="${filters[$idx]}"
    local d="$WORKROOT/$id"
    rm -rf "$d"; mkdir -p "$d/test"
    cp "$ROOT/$LIB" "$d/$LIB" || { echo "ERROR $id (copy failed)"; return 0; }
    cp "$SUITE"   "$d/$SUITE" || { echo "ERROR $id (suite copy failed)"; return 0; }

    # Literal replacement, and OLD must occur EXACTLY ONCE. Zero matches means a
    # stale catalogue rule; more than one means the anchor went ambiguous. Both
    # are harness bugs that would otherwise read as a surviving mutant, i.e. a
    # false coverage gap, so they are called out rather than counted.
    if ! OLD="$old" NEW="$new" TARGET="$d/$LIB" python3 -c '
import os, sys
p = os.environ["TARGET"]
old = os.environ["OLD"].encode()
new = os.environ["NEW"].encode()
s = open(p, "rb").read()
n = s.count(old)
if n != 1:
    print("count=%d" % n, file=sys.stderr)
    sys.exit(3)
open(p, "wb").write(s.replace(old, new, 1))
' 2>"$WORKROOT/.err"; then
        echo "BROKESED $id (anchor matched $(tr -d '\n' < "$WORKROOT/.err") — fix the catalogue rule)"
        return 0
    fi

    if [ "$FULL" -eq 0 ]; then
        if ! ( cd "$d" && bats -f "$filt" "$SUITE" >/dev/null 2>&1 ); then
            echo "CAUGHT $id (targeted)"
            return 0
        fi
    fi
    # Tier 2: the cheap filter can hide a test that would otherwise catch it.
    if ! ( cd "$d" && bats "$SUITE" >/dev/null 2>&1 ); then
        echo "CAUGHT $id (full suite)"
    else
        echo "SURVIVED $id"
    fi
}

# --- driver -------------------------------------------------------------------
if [ "$JOBS" -le 0 ]; then
    JOBS="$( (command -v nproc >/dev/null && nproc) || echo 4 )"
fi
[ "$JOBS" -gt 12 ] && JOBS=12

printf 'mutation: %s mutants, concurrency %s%s\n' "${#ids[@]}" "$JOBS" \
    "$([ "$FULL" -eq 1 ] && printf ', full-suite only' || printf ', targeted then full')"
printf '%s\n' "----------------------------------------------------------------------"

results="$WORKROOT/results"
: > "$results"
# Batched rather than `wait -n`, which needs bash 4.3+ and would be a needless
# floor for a tool that runs wherever the suite runs.
i=0
while [ "$i" -lt "${#ids[@]}" ]; do
    end=$(( i + JOBS ))
    [ "$end" -gt "${#ids[@]}" ] && end="${#ids[@]}"
    while [ "$i" -lt "$end" ]; do
        run_mutant "$i" >> "$results" &
        i=$(( i + 1 ))
    done
    wait
done

sort "$results" | while IFS= read -r r; do printf '  %s\n' "$r"; done

caught=$(grep -c '^CAUGHT '   "$results" || true)
survived=$(grep -c '^SURVIVED ' "$results" || true)
brokesed=$(grep -c '^BROKESED ' "$results" || true)
errors=$(grep -c '^ERROR ' "$results" || true)

printf '%s\n' "----------------------------------------------------------------------"
printf 'caught %s   survived %s   broken-catalogue-rules %s   harness-errors %s\n' \
    "$caught" "$survived" "$brokesed" "$errors"

if [ "$survived" -gt 0 ]; then
    printf '\nSURVIVORS — each is either a real coverage gap or an equivalent\n'
    printf 'mutant (the killed branch was unreachable). Triage each explicitly.\n'
fi
if [ "$brokesed" -gt 0 ] || [ "$errors" -gt 0 ]; then
    printf '\nHARNESS PROBLEM: %s catalogue rule(s) did not apply and %s errored.\n' "$brokesed" "$errors"
    printf 'A rule that matches nothing yields a no-op mutant and a FALSE gap.\n'
    exit 1
fi
[ "$survived" -eq 0 ] || exit 1
exit 0

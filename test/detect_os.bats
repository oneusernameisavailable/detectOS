#!/usr/bin/env bats
# SC1091: `$BATS_TEST_DIRNAME/../fx-detect-os.sh` is a runtime-variable path;
# v0.10 cannot follow `.` sources that live inside @test blocks. The library
# file itself is linted separately, so this guard adds no coverage gap.
# shellcheck disable=SC1091
# SC2154: the internal $_os_log_file is assigned by the library during tests.
# SC2030/SC2031: @test bodies run in a subshell; the debug env exports are
# read (and honored) within that same subshell.
# shellcheck disable=SC2154
# shellcheck disable=SC2030,SC2031
# SC2317: bats runs @test functions indirectly, so every block looks
# "unreachable" to shellcheck.
# SC2034: test-subject variables and negative controls are consumed by the
# functions under test, which shellcheck cannot see.
# SC1003/SC2016: metacharacter payloads are purposefully literal; they must
# reach the fixtures and children unexpanded.
# shellcheck disable=SC2317,SC2034,SC1003,SC2016
#
# fx-detect-os.sh integration tests.
#
# Run with:  bats test/detect_os.bats        (requires https://bats-core.github.io)
# Every test isolates detection behind _OS_ROOT (a fake filesystem root), so
# the runner's own /etc is never consulted.

setup() {
    export _OS_ROOT="$BATS_TEST_TMPDIR/root"
    mkdir -p "$_OS_ROOT/etc"
    # Neutralize a host-installed lsb_release so file-based fixtures decide
    # the ladder outcome in every test. The stub is invoked by the library's
    # steps, so SC2317 (0.10) / SC2329 (0.11) — no local callers — do not apply.
    # shellcheck disable=SC2317,SC2329
    lsb_release() { return 1; }
    # Neutralize a host-installed coreutils `timeout` the same way: the library
    # wraps lsb_release with it when available, and an external timeout binary
    # cannot invoke a bash function stub. This shim keeps every fixture inside
    # a pure bash-function world.
    # shellcheck disable=SC2317,SC2329
    timeout() { shift; "$@"; }
}

lib() {
    . "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
}

@test "internal _OS_VERSION name is safe to own before sourcing" {
    mkdir -p "$_OS_ROOT/etc"
    run bash -c '
        set -euo pipefail
        readonly _OS_VERSION=already-here
        . "$1"
        detect_os' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
}

@test "single double-source guard: sourcing twice is a no-op" {
    . "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    . "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    detect_os
    [ "${OS_DETECTED:-0}" = "1" ]
    command -v detect_os >/dev/null
}

@test "os-release: ID and metadata parsed (spec path)" {
    printf '%s\n' \
        'NAME="Debian GNU/Linux"' \
        'ID=debian' \
        'ID_LIKE=""' \
        'VERSION_ID="12"' \
        'VERSION_CODENAME="bookworm"' \
        'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"' \
        > "$_OS_ROOT/etc/os-release"
    lib
    detect_os
    [ "$OS_ID" = "debian" ]
    [ "$OS_VERSION_ID" = "12" ]
    [ "$OS_VERSION_CODENAME" = "bookworm" ]
    [ "$OS_PRETTY_NAME" = "Debian GNU/Linux 12 (bookworm)" ]
    [ "$OS_FALLBACK_USED" = "0" ]
}

@test "ID-less os-release defers, ID=linux only via uname last resort (C1)" {
    printf '%s\n' 'NAME="Unknown Distro"' > "$_OS_ROOT/etc/os-release"
    lib
    detect_os
    [ "$OS_ID" = "linux" ]
    [ "$OS_SOURCE" = "uname" ]
    [ "$OS_FALLBACK_USED" = "1" ]
}

@test "usr/lib/os-release used when /etc is missing" {
    mkdir -p "$_OS_ROOT/usr/lib"
    printf '%s\n' 'ID=fedora' 'VERSION_ID="41"' > "$_OS_ROOT/usr/lib/os-release"
    lib
    detect_os
    [ "$OS_ID" = "fedora" ]
    [ "$OS_VERSION_ID" = "41" ]
}

@test "ID-less /etc/os-release hands the whole identity to /usr/lib (no mixing)" {
    mkdir -p "$_OS_ROOT/usr/lib"
    printf '%s\n' 'NAME="Leftover"' > "$_OS_ROOT/etc/os-release"
    printf '%s\n' 'ID=fedora' 'VERSION_ID="41"' > "$_OS_ROOT/usr/lib/os-release"
    lib
    detect_os
    [ "$OS_ID" = "fedora" ]
    [ "$OS_VERSION_ID" = "41" ]
    [ -z "${OS_NAME:-}" ]
    [ "$OS_SOURCE" = "$_OS_ROOT/usr/lib/os-release" ]
}

@test "ID-less /usr/lib/os-release alone defers, never claims paternity (C1/C8)" {
    mkdir -p "$_OS_ROOT/usr/lib"
    printf '%s\n' 'NAME="OnlyName"' > "$_OS_ROOT/usr/lib/os-release"
    lib
    detect_os
    [ "$OS_ID" = "linux" ]
    [ "$OS_SOURCE" = "uname" ]
    [ "$OS_FALLBACK_USED" = "1" ]
}

@test "legacy lsb-release file parsed without the lsb_release command" {
    printf '%s\n' \
        'DISTRIB_ID=Ubuntu' \
        'DISTRIB_RELEASE=22.04' \
        'DISTRIB_CODENAME=jammy' \
        'DISTRIB_DESCRIPTION="Ubuntu 22.04.3 LTS"' \
        > "$_OS_ROOT/etc/lsb-release"
    lib
    detect_os
    [ "$OS_ID" = "ubuntu" ]
    [ "$OS_VERSION_ID" = "22.04" ]
    [ "$OS_FALLBACK_USED" = "1" ]
}

@test "legacy arch-release marker (empty file) resolves to arch" {
    : > "$_OS_ROOT/etc/arch-release"
    lib
    detect_os
    [ "$OS_ID" = "arch" ]
    [ "$OS_SOURCE" = "$_OS_ROOT/etc/arch-release" ]
}

@test "legacy debian_version resolves to debian with version" {
    printf '%s\n' '12.4' > "$_OS_ROOT/etc/debian_version"
    lib
    detect_os
    [ "$OS_ID" = "debian" ]
    [ "$OS_VERSION_ID" = "12.4" ]
}

@test "debian_version codename/sid lines leave OS_VERSION_ID empty" {
    printf '%s\n' 'bookworm' > "$_OS_ROOT/etc/debian_version"
    lib
    detect_os
    [ "$OS_ID" = "debian" ]
    [ -z "$OS_VERSION_ID" ]

    printf '%s\n' '12' > "$_OS_ROOT/etc/debian_version"
    lib
    detect_os
    [ "$OS_VERSION_ID" = "12" ]
}

@test "legacy redhat-release maps Fedora family vendors" {
    printf '%s\n' 'Red Hat Enterprise Linux release 9.3 (Plano)' > "$_OS_ROOT/etc/redhat-release"
    lib
    detect_os
    [ "$OS_ID" = "rhel" ]
    [ "$OS_VERSION_ID" = "9.3" ]

    printf '%s\n' 'Rocky Linux release 9.3 (Blue Onyx)' > "$_OS_ROOT/etc/redhat-release"
    lib
    detect_os
    [ "$OS_ID" = "rocky" ]
    [ "$OS_VERSION_ID" = "9.3" ]
}

@test "legacy system-release resolves Amazon Linux to amzn" {
    printf '%s\n' 'Amazon Linux release 2023 (Amazon Linux)' > "$_OS_ROOT/etc/system-release"
    lib
    detect_os
    [ "$OS_ID" = "amzn" ]
    [ "$OS_VERSION_ID" = "2023" ]
    [[ " $OS_ID_LIKE " == *" rhel "* ]]
    [[ " $OS_ID_LIKE " == *" fedora "* ]]
}

@test "unrecognized system-release text falls through, never false-claims" {
    printf '%s\n' 'Mystery Ops release 1.0' > "$_OS_ROOT/etc/system-release"
    lib
    detect_os
    [ "$OS_SOURCE" = "uname" ]
    [ "$OS_ID" = "linux" ]
}

@test "oracle-release resolves to ol: beats RHEL-compatible redhat-release, never catch-all oracle (C10)" {
    printf '%s\n' 'Oracle Linux Server release 8.9' > "$_OS_ROOT/etc/oracle-release"
    printf '%s\n' 'Red Hat Enterprise Linux Server release 8.9' > "$_OS_ROOT/etc/redhat-release"
    lib
    detect_os
    [ "$OS_ID" = "ol" ]
    [ "$OS_NAME" = "Oracle Linux" ]
    [ "$OS_VERSION_ID" = "8.9" ]
    [[ " $OS_ID_LIKE " == *" rhel "* ]]
    [ "$OS_SOURCE" = "$_OS_ROOT/etc/oracle-release" ]

    rm -f "$_OS_ROOT/etc/redhat-release"
    lib
    detect_os
    [ "$OS_ID" = "ol" ]
    [ "$OS_VERSION_ID" = "8.9" ]
    [[ " $OS_ID_LIKE " == *" rhel "* ]]
    [ "$OS_SOURCE" = "$_OS_ROOT/etc/oracle-release" ]
}

@test "system-release happy path via Fedora-family text" {
    printf '%s\n' 'CentOS Linux release 9.0' > "$_OS_ROOT/etc/system-release"
    lib
    detect_os
    [ "$OS_ID" = "centos" ]
    [ "$OS_VERSION_ID" = "9.0" ]
}

@test "legacy SuSE-release resolves openSUSE variants" {
    printf '%s\n' 'openSUSE Leap 15.5' > "$_OS_ROOT/etc/SuSE-release"
    lib
    detect_os
    [ "$OS_ID" = "opensuse-leap" ]
    [ "$OS_VERSION_ID" = "15.5" ]

    printf '%s\n' 'openSUSE Tumbleweed 20230913' > "$_OS_ROOT/etc/SuSE-release"
    lib
    detect_os
    [ "$OS_ID" = "opensuse-tumbleweed" ]
}

@test "rolling opensuse-tumbleweed reports empty OS_VERSION_ID" {
    printf '%s\n' 'openSUSE Tumbleweed 20230913' > "$_OS_ROOT/etc/SuSE-release"
    lib
    detect_os
    [ "$OS_ID" = "opensuse-tumbleweed" ]
    [ -z "$OS_VERSION_ID" ]
}

@test "catch-all claims unknown <id>-release files (nobara-style)" {
    printf '%s\n' 'Nobara release 38' > "$_OS_ROOT/etc/nobara-release"
    lib
    detect_os
    [ "$OS_ID" = "nobara" ]
    [ "$OS_VERSION_ID" = "38" ]
}

@test "catch-all tolerates _OS_ROOT containing a space" {
    local sp="$BATS_TEST_TMPDIR/root with space"
    mkdir -p "$sp/etc"
    printf '%s\n' 'Nobara release 38' > "$sp/etc/nobara-release"
    _OS_ROOT="$sp" run bash -c 'lsb_release(){ return 1; }; timeout(){ shift; "$@"; }; . "'"$BATS_TEST_DIRNAME"'/../fx-detect-os.sh"; detect_os; printf "%s" "$OS_ID"'
    [ "$status" -eq 0 ]
    [ "$output" = "nobara" ]
}

@test "empty root falls back to uname and never reports undetected on Linux" {
    lib
    detect_os
    [ "$OS_DETECTED" = "1" ]
    [ "$OS_SOURCE" = "uname" ]
    [ "$OS_ID" = "linux" ]
    # Kernel metadata must not leak from the RUNNER's host into a fixture:
    # OS_KERNEL/OS_KERNEL_RELEASE/OS_ARCH stay empty (the uname identity
    # fallback above is the last-resort PATH, deliberately separate).
    [ -z "$OS_KERNEL" ]
    [ -z "$OS_KERNEL_RELEASE" ]
    [ -z "$OS_ARCH" ]
}

@test "os-release beats legacy files (precedence)" {
    printf '%s\n' 'ID=ubuntu' > "$_OS_ROOT/etc/os-release"
    : > "$_OS_ROOT/etc/arch-release"
    lib
    detect_os
    [ "$OS_ID" = "ubuntu" ]
    [ "$OS_FALLBACK_USED" = "0" ]
}

@test "container metadata set independently of identity" {
    mkdir -p "$_OS_ROOT/run"
    printf '%s\n' \
        'name="testcontainer"' \
        'id=1234' \
        'version=1.0' \
        'engine="crun"' \
        > "$_OS_ROOT/run/.containerenv"
    : > "$_OS_ROOT/etc/arch-release"
    lib
    detect_os
    [ "$OS_CONTAINER" = "podman" ]
    [ "$OS_ID" = "arch" ]

    : > "$_OS_ROOT/.dockerenv"
    lib
    detect_os
    [ "$OS_CONTAINER" = "docker" ]
}

@test "os_container accessor is empty before detection" {
    lib
    [ -z "$(os_container)" ]
}

@test ".containerenv engine=runc maps to oci (runc is not podman-branded)" {
    mkdir -p "$_OS_ROOT/run"
    printf '%s\n' 'engine="runc"' > "$_OS_ROOT/run/.containerenv"
    : > "$_OS_ROOT/etc/arch-release"
    lib
    detect_os
    [ "$OS_CONTAINER" = "oci" ]
}

@test "field accessors echo detected values, never trip set -u" {
    printf '%s\n' 'ID=minimal' > "$_OS_ROOT/etc/os-release"
    lib
    detect_os
    run bash -c 'set -u; . "'"$BATS_TEST_DIRNAME"'/../fx-detect-os.sh"; detect_os; os_id; os_distro'
    [ "$status" -eq 0 ]
    [ "${lines[0]}" = "minimal" ]
    [ "${lines[1]}" = "minimal" ]
}

@test "safe inside a strict-mode caller" {
    lib
    run bash -c 'set -euo pipefail; . "'"$BATS_TEST_DIRNAME"'/../fx-detect-os.sh"; detect_os; printf "ok:%s" "$OS_ID"'
    [ "$status" -eq 0 ]
    [[ "$output" == ok:* ]]
}

@test "canary secret never reaches the log; auto-created log is 0600 with markers" {
    printf '%s\n' 'ID=canarytest' > "$_OS_ROOT/etc/os-release"
    export _OS_DEBUG=1
    export SECRET_CANARY="canary-VALUE-7391"
    unset _OS_LOG_FILE
    lib
    detect_os
    local L="${_os_log_file:-}"
    [ -n "$L" ] && [ -f "$L" ]

    run stat -c '%a' "$L"
    [ "$output" = "600" ]

    run grep -F "$SECRET_CANARY" "$L"
    [ "$status" -eq 1 ]

    run grep -E 'START|STAGE:|ENTER detect_os|EXEC:|RC=|STATE DUMP' "$L"
    [ "$status" -eq 0 ]
    rm -f "$L"
}

@test "caller-supplied _OS_LOG_FILE keeps its mode, never forced to 0600 (C6)" {
    printf 'seed\n' > "$BATS_TEST_TMPDIR/caller.log"
    chmod 0644 "$BATS_TEST_TMPDIR/caller.log"
    export _OS_DEBUG=1 _OS_LOG_FILE="$BATS_TEST_TMPDIR/caller.log"
    lib
    _os_ensure_log_file
    [ -s "$_OS_LOG_FILE" ]
    run stat -c '%a' "$_OS_LOG_FILE"
    [ "$output" = "644" ]
    rm -f "$_OS_LOG_FILE"
}

@test "no mktemp: debug log degrades to off, never a predictable PID path (C6)" {
    run bash -c '
        export PATH=""
        . "'"$BATS_TEST_DIRNAME"'/../fx-detect-os.sh"
        _os_ensure_log_file
        if [ -e "/tmp/osdetect.$$.log" ]; then pred=present; else pred=absent; fi
        printf "log=[%s] pred=%s" "${_os_log_file-}" "$pred"
    '
    [ "$status" -eq 0 ]
    [[ "$output" == *"log=[]"* ]]
    [[ "$output" == *"pred=absent"* ]]
}

@test "redaction: uppercase secret names are caught and replaced" {
    lib
    AWS_ACCESS_KEY_ID="deadbeefUpper" run _os_redact "token is deadbeefUpper"
    [ "$status" -eq 0 ]
    [[ "$output" == *"[REDACTED]"* ]]
    [[ "$output" != *"deadbeefUpper"* ]]
    [[ "$output" != *"[REDACTED]/"* ]]
}

@test "redaction: short common values never corrupt log lines" {
    lib
    local out
    out="$(FREAKY=/ _os_redact "/usr/bin/cat /etc/os-release")"
    [ "$out" = "/usr/bin/cat /etc/os-release" ]
}

@test "redaction: psk/bearer/otp/mfa/dsn/jdbc values are redacted" {
    lib
    PSK='psk-abcd-123def' BEARER='bearer-tok-9876' OTP='398812' MFA='987654' DSN='dbname=x' JDBC_URL='jdbc:postgresql://h:5432' run _os_redact "cfg psk-abcd-123def bearer-tok-9876 398812 987654 dbname=x jdbc:postgresql://h:5432"
    [ "$status" -eq 0 ]
    [ "$output" = "cfg [REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED]" ]
}

@test "redaction: connection-string var values are redacted (DATABASE_URL)" {
    lib
    DATABASE_URL='postgres://u:pw@h/db' run _os_redact "loaded postgres://u:pw@h/db from cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "loaded [REDACTED] from cfg" ]
}

@test "redaction: public URL fields (HOME_URL/BUG_REPORT_URL) stay intact" {
    lib
    HOME_URL='https://x.example' BUG_REPORT_URL='https://bugs/x.example' run _os_redact "home: https://x.example  bugs: https://bugs/x.example"
    [ "$status" -eq 0 ]
    [ "$output" = "home: https://x.example  bugs: https://bugs/x.example" ]
}

@test "redaction: short values redact in NAME=value context, bare values stay" {
    lib
    TOKEN=abc run _os_redact "TOKEN=abc"
    [ "$status" -eq 0 ]
    [ "$output" = "[REDACTED]" ]
    run _os_redact "/a/abc/"
    [ "$status" -eq 0 ]
    [ "$output" = "/a/abc/" ]
}

@test "redaction: a secret word anywhere in the NAME drives redaction" {
    lib
    run _os_redact " xdMYTOKEN=abc MY_TOKEN=abc "
    [ "$status" -eq 0 ]
    [ "$output" = " [REDACTED] [REDACTED] " ]
}

@test "redaction: '=' inside values is parsed exactly (no trailing residue)" {
    lib
    TOKEN='abcdef=' run _os_redact "cfg abcdef= tail"
    [ "$status" -eq 0 ]
    [ "$output" = "cfg [REDACTED] tail" ]
}

@test "redaction: longest value wins, no [REDACTED]def residuum" {
    lib
    KEY=abc TOKEN=abcdef run _os_redact "conn abcdef ready"
    [ "$status" -eq 0 ]
    [ "$output" = "conn [REDACTED] ready" ]
    [[ "$output" != *"def"* ]]
}

@test "redaction: value embedded in a URL is still redacted" {
    lib
    TOKEN=xyz789 run _os_redact "https://u:xyz789@h"
    [ "$status" -eq 0 ]
    [ "$output" = "https://u:[REDACTED]@h" ]
}

@test "redaction: multiple secret names in one line all redact" {
    lib
    DATABASE_URL='postgres://u:pw@h/db' run _os_redact "alpha MY_TOKEN=abc beta; DATABASE_URL=postgres://u:pw@h/db xMY_TOKEN=zz"
    [ "$status" -eq 0 ]
    [ "$output" = "alpha [REDACTED] beta; [REDACTED] [REDACTED]" ]
}

@test "redaction: debug log redacts '='-value and short psk through _os_log" {
    printf '%s\n' 'ID=e2e' > "$_OS_ROOT/etc/os-release"
    export _OS_DEBUG=1 _OS_LOG_FILE="$BATS_TEST_TMPDIR/e2e.log"
    export TOKEN='pa=ss' _OS_PSK='xy'
    lib
    _os_log "line with pa=ss and PSK=xy token"
    run grep -F 'pa=ss' "$_OS_LOG_FILE"
    [ "$status" -eq 1 ]
    run grep -F 'PSK=xy' "$_OS_LOG_FILE"
    [ "$status" -eq 1 ]
    run grep -F '[REDACTED]' "$_OS_LOG_FILE"
    [ "$status" -eq 0 ]
    rm -f "$_OS_LOG_FILE"
}

@test "redaction: token value containing a space redacts whole (S5)" {
    lib
    SECRET_PROBE='probe val=1=x' run _os_redact "handling SECRET_PROBE=probe val=1=x now"
    [ "$status" -eq 0 ]
    [ "$output" = "handling [REDACTED] now" ]
    [[ "$output" != *"val=1=x"* ]]
}

@test "redaction: token falls back when line lacks the full env value (S5)" {
    lib
    TOKEN='probe val=1=x' run _os_redact "TOKEN=probe OTHER"
    [ "$status" -eq 0 ]
    [ "$output" = "[REDACTED] OTHER" ]
}

@test "redaction: _os_log catches space-containing secret value in log (S5 e2e)" {
    printf '%s\n' 'ID=e2e5' > "$_OS_ROOT/etc/os-release"
    export _OS_DEBUG=1 _OS_LOG_FILE="$BATS_TEST_TMPDIR/e2e5.log"
    export SECRET_PROBE='probe val=1=x'
    lib
    _os_log "cfg SECRET_PROBE=probe val=1=x tail"
    run grep -F 'val=1=x' "$_OS_LOG_FILE"
    [ "$status" -eq 1 ]
    run grep -F '[REDACTED]' "$_OS_LOG_FILE"
    [ "$status" -eq 0 ]
    rm -f "$_OS_LOG_FILE"
}

@test "_os_error_log_path defaults under XDG_STATE_HOME, never the source tree" {
    export XDG_STATE_HOME="$BATS_TEST_TMPDIR/xdgstate"
    lib
    run _os_error_log_path
    [ "$status" -eq 0 ]
    [ "$output" = "$XDG_STATE_HOME/osdetect/osdetect-failures.jsonl" ]
    [[ "$output" != *OSDetectFailureLog* ]]

    unset XDG_STATE_HOME
    export HOME="$BATS_TEST_TMPDIR/home"
    run _os_error_log_path
    [ "$status" -eq 0 ]
    [ "$output" = "$HOME/.local/state/osdetect/osdetect-failures.jsonl" ]
}

@test "_os_ensure_error_log creates default dir+file with mode 0600 (and cleans up)" {
    local default_path mode
    export XDG_STATE_HOME="$BATS_TEST_TMPDIR/xdgstate"
    lib
    default_path="$(_os_error_log_path)"
    rm -rf "${default_path%/*}"          # avoid any pre-existing artifact
    run _os_ensure_error_log
    [ "$status" -eq 0 ]
    [ -f "$default_path" ]
    mode=$(stat -c '%a' "$default_path")
    [ "$mode" = "600" ]
    rm -rf "$XDG_STATE_HOME"             # leave no state behind
}

@test "_os_ensure_error_log does not chmod a caller-supplied path" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/custom.log"
    lib
    touch "$_OS_ERROR_LOG"
    chmod 644 "$_OS_ERROR_LOG"
    run _os_ensure_error_log
    [ "$status" -eq 0 ]
    local mode
    mode=$(stat -c '%a' "$_OS_ERROR_LOG")
    [ "$mode" = "644" ]
    rm -f "$_OS_ERROR_LOG"
}

@test "_os_ensure_error_log returns 1 when target is an existing directory (fail-open)" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/root"    # a directory
    lib
    run _os_ensure_error_log
    [ "$status" -eq 1 ]
}

@test "_os_json_escape escapes backslash, quote, and control chars" {
    lib
    run _os_json_escape 'a\b"c'
    [ "$status" -eq 0 ]
    [ "$output" = 'a\\b\"c' ]

    run _os_json_escape $'line1\nline2'
    [ "$status" -eq 0 ]
    [ "$output" = 'line1\nline2' ]
run _os_json_escape $'tab-->\t here'
    [ "$status" -eq 0 ]
    [ "$output" = 'tab-->\t here' ]
}

@test "identity-unresolved appends one NDJSON event to the error log" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/failures.jsonl"
    run bash -c '
        # uname absent at source (PATH=/nonexistent) forces identity-unresolved;
        # the other pinned slots are supplied as caller-owned so the error log
        # can still be written after PATH is restored.
        _OS_MKDIR="$(command -v mkdir)"
        _OS_CHMOD="$(command -v chmod)"
        _OS_DATE="$(command -v date)"
        _OS_ENV="$(command -v env)"
        export PATH=/nonexistent
        . "$1"
        export PATH=/usr/bin:/bin
        detect_os
        printf "rc=%s\n" "$?"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"rc=1"* ]]
    [ -f "$_OS_ERROR_LOG" ]
    local lines
    lines=$(wc -l < "$_OS_ERROR_LOG")
    [ "$lines" -eq 1 ]
    if command -v jq >/dev/null 2>&1; then
        jq -e . < "$_OS_ERROR_LOG" >/dev/null
    else
        run grep -F '{' "$_OS_ERROR_LOG"
        [ "$status" -eq 0 ]
        run grep -F '}' "$_OS_ERROR_LOG"
        [ "$status" -eq 0 ]
    fi
    run grep -F '"outcome":"identity-unresolved"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    run grep -F '"source":"os-release"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    run grep -F '"source":"uname-fallback"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    rm -f "$_OS_ERROR_LOG"
}

@test "identity-resolved does NOT create the error log" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/failures-ok.jsonl"
    printf '%s\n' 'NAME="Suc"' 'ID=suc' > "$_OS_ROOT/etc/os-release"
    lib
    detect_os
    [ "$OS_ID" = "suc" ]
    [ ! -f "$_OS_ERROR_LOG" ]
}

@test "failure log honors _OS_ERROR_LOG override" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/override-log.txt"
    run bash -c '
        _OS_MKDIR="$(command -v mkdir)"
        _OS_CHMOD="$(command -v chmod)"
        _OS_DATE="$(command -v date)"
        _OS_ENV="$(command -v env)"
        export PATH=/nonexistent
        . "$1"
        export PATH=/usr/bin:/bin
        detect_os
        printf "rc=%s\n" "$?"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [ -f "$_OS_ERROR_LOG" ]
    run grep -F '"outcome":"identity-unresolved"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    rm -f "$_OS_ERROR_LOG"
}

@test "unwritable error log path does not change detect_os rc (fail-open)" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/root"    # an existing directory: append fails
    run bash -c '
        export PATH=/nonexistent
        . "$1"
        export PATH=/usr/bin:/bin
        detect_os
        printf "rc=%s\n" "$?"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"rc=1"* ]]
}

@test "error log redacts space-containing secret values in event fields (S5 guard)" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/redact-err.jsonl"
    export SECRET_PROBE='probe val=1=x'
    lib
    _os_steps=("os-release" "1" "commit SECRET_PROBE=probe val=1=x tail msg=probe val=1=x")
    _os_failure_record
    [ -f "$_OS_ERROR_LOG" ]
    run grep -F 'val=1=x' "$_OS_ERROR_LOG"
    [ "$status" -eq 1 ]
    run grep -F '[REDACTED]' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    run grep -F '"outcome":"identity-unresolved"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    rm -f "$_OS_ERROR_LOG"
}

@test "error log records os-release and legacy step details for legacy-only failure" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/legacy-err.jsonl"
    printf '%s\n' 'NAME="NoID Distro"' > "$_OS_ROOT/etc/os-release"
    printf '%s\n' 'Unknown Linux' > "$_OS_ROOT/etc/system-release"
    run bash -c '
        _OS_MKDIR="$(command -v mkdir)"
        _OS_CHMOD="$(command -v chmod)"
        _OS_DATE="$(command -v date)"
        _OS_ENV="$(command -v env)"
        export PATH=/nonexistent
        . "$1"
        export PATH=/usr/bin:/bin
        detect_os
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ -f "$_OS_ERROR_LOG" ]
    run grep -F '"source":"os-release"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    run grep -F '"source":"legacy"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    run grep -F '/etc/os-release' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    rm -f "$_OS_ERROR_LOG"
}

@test "direct execution refuses with exit 2" {
    run "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 2 ]
}

@test "debug log defaults to a mktemp path (not a predictable PID path)" {
    unset _OS_LOG_FILE
    lib
    _os_ensure_log_file
    [[ "$_os_log_file" == /tmp/osdetect.* ]]
    [ "$_os_log_file" != "/tmp/osdetect.$$.log" ]
    [ -f "$_os_log_file" ]
    rm -f "$_os_log_file"
}

@test "pre-planted predictable PID log path is ignored when mktemp exists" {
    unset _OS_LOG_FILE
    local trap_path="/tmp/osdetect.$$.log"
    : > "$trap_path"
    lib
    _os_ensure_log_file
    [ "$_os_log_file" != "$trap_path" ]
    rm -f "$_os_log_file" "$trap_path"
}

@test "lsb_release is wrapped in coreutils timeout when available" {
    unset _OS_ROOT   # lsb command is host-only; never runs against a fake root
    export _OS_DEBUG=1 _OS_LOG_FILE="$BATS_TEST_TMPDIR/t.log"
    lib
    _os_run_lsb_cmd || true
    run grep -E 'EXEC: timeout 5 lsb_release' "$_OS_LOG_FILE"
    [ "$status" -eq 0 ]
}

@test "timeout reported failure (rc 124) is treated as lsb_release unavailable" {
    unset _OS_ROOT
    lib
    timeout() { return 124; }
    lsb_release() { printf '%s\n' 'ubuntu'; return 0; }
    run _os_run_lsb_cmd
    [ "$status" -eq 1 ]
    [ -z "${OS_ID:-}" ]
}

@test "lsb_release still used unbounded when coreutils timeout is absent" {
    local lib_path="$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    run bash -c '
        lsb_release() { printf "ubuntu\n"; return 0; }
        # Timeout absent at source time (PATH with no timeout): unbounded
        # legacy behavior must still detect. The PATH pin happens BEFORE
        # sourcing, because tool paths are resolved at load.
        PATH=/nonexistent
        unset _OS_ROOT
        . "$1"
        _os_run_lsb_cmd
        printf "rc=%s id=%s\n" "$?" "${OS_ID:-}"
    ' dummy "$lib_path"
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=ubuntu"* ]]
}

@test "strict-mode caller survives an unwritable debug log (C1)" {
    printf '%s\n' 'ID=c1test' > "$_OS_ROOT/etc/os-release"
    run bash -c '
        set -euo pipefail
        export _OS_DEBUG=1
        export _OS_LOG_FILE=/nonexistent-dir/osdetect.log
        . "$1"
        detect_os
        printf "rc=%s id=%s\n" "$?" "${OS_ID:-}"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"rc=0"* ]]
    [[ "$output" == *"id=c1test"* ]]
}

@test "caller-owned readonly OS_ID blocks detect_os with rc 1 and a warning" {
    printf '%s\n' 'ID=blocked' > "$_OS_ROOT/etc/os-release"
    run bash -c '
        set -euo pipefail
        . "$1"
        readonly OS_ID=pre
        detect_os || rc=$?
        printf "rc=%s id=%s detected=%s\n" "${rc:-0}" "${OS_ID:-}" "${OS_DETECTED:-0}"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"rc=1"* ]]
    [[ "$output" == *"id=pre"* ]]
    [[ "$output" == *"detected=0"* ]]
}

@test "caller-owned readonly OS_ID raises a human-readable collision warning" {
    printf '%s\n' 'ID=blocked' > "$_OS_ROOT/etc/os-release"
    run bash -c '
        set -euo pipefail
        . "$1"
        readonly OS_ID=pre
        detect_os || true
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"readonly"* ]]
    [[ "$output" == *"OS_ID"* ]]
}

@test "forged _DETECT_OS_SOURCED flag alone does not skip loading (C2)" {
    printf '%s\n' 'ID=forgedtest' > "$_OS_ROOT/etc/os-release"
    run bash -c '
        _DETECT_OS_SOURCED=1
        . "$1"
        detect_os
        printf "id=%s\n" "${OS_ID:-}"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=forgedtest"* ]]
}

@test "CRLF os-release: CR stripped, VERSION_ID stays plain (C4)" {
    printf 'NAME="X"\r\nID=crlftest\r\nVERSION_ID="12"\r\n' > "$_OS_ROOT/etc/os-release"
    lib
    detect_os
    [ "$OS_ID" = "crlftest" ]
    [ "$OS_VERSION_ID" = "12" ]
}

@test "shell-hostile VERSION_ID is sanitized, never executed or echoed raw (C4)" {
    # shellcheck disable=SC2016  # $() must reach the fixture verbatim, expanded only when detect_os parses it
    printf '%s\n' 'ID=evil' 'VERSION_ID="$(rm -rf /)"; hacked; echo x' > "$_OS_ROOT/etc/os-release"
    lib
    detect_os
    [ "$OS_ID" = "evil" ]
    case "$OS_VERSION_ID" in
        *[!0-9a-zA-Z._+-]*) return 1 ;;
    esac
    [[ "$(os_version)" != *";"* ]]
}

@test "lsb DISTRIB_RELEASE is sanitized too (C4)" {
    printf '%s\n' 'DISTRIB_ID=Ubuntu' 'DISTRIB_RELEASE=22.04' > "$_OS_ROOT/etc/lsb-release"
    lib
    detect_os
    [ "$OS_ID" = "ubuntu" ]
    [ "$OS_VERSION_ID" = "22.04" ]

    printf '%s\n' 'DISTRIB_ID=Ubuntu' 'DISTRIB_RELEASE="22.04"; rm -rf /' > "$_OS_ROOT/etc/lsb-release"
    lib
    detect_os
    case "$OS_VERSION_ID" in
        *[!0-9a-zA-Z._+-]*) return 1 ;;
    esac
    [[ "$OS_VERSION_ID" != *";"* ]]
    [[ "$OS_VERSION_ID" != *"/"* ]]
}

@test "detect_os returns 1 and OS_DETECTED=0 when uname is unavailable at source" {
    run bash -c '
        # uname is resolved at source time, so an unavailable uname must be
        # created by a PATH WITHOUT it BEFORE the library is loaded. The empty
        # _OS_ROOT fixture (inherited from setup) makes every ladder step fail,
        # so rc=1 is deterministic; under Fix 4 the fixture isolates kernel
        # metadata from the runner, so OS_KERNEL/OS_ARCH stay empty.
        PATH=/nonexistent
        . "$1"
        detect_os
        printf "rc=%s detected=%s kernel=%s arch=%s\n" "$?" "${OS_DETECTED:-}" "${OS_KERNEL:-}" "${OS_ARCH:-}"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"rc=1"* && "$output" == *"detected=0"* && "$output" == *"kernel="* && "$output" != *"kernel=unknown"* && "$output" == *"arch="* && "$output" != *"arch=unknown"* ]]
    [[ "$output" == *"uname was not found"* ]]
}

@test "UTF-8 BOM before the first os-release key is stripped" {
    printf '\xef\xbb\xbfID=bomtest\nVERSION_ID="1"\n' > "$_OS_ROOT/etc/os-release"
    lib
    detect_os
    [ "$OS_ID" = "bomtest" ]
    [ "$OS_VERSION_ID" = "1" ]
}

@test "0-byte os-release defers, ID=linux only via uname (C1)" {
    : > "$_OS_ROOT/etc/os-release"
    lib
    detect_os
    [ "$OS_ID" = "linux" ]
    [ "$OS_SOURCE" = "uname" ]
    [ "$OS_FALLBACK_USED" = "1" ]
}

@test "0-byte os-release lets a legacy marker win (no ID=linux shortcut)" {
    : > "$_OS_ROOT/etc/os-release"
    : > "$_OS_ROOT/etc/arch-release"
    lib
    detect_os
    [ "$OS_ID" = "arch" ]
    [ "$OS_FALLBACK_USED" = "1" ]
}

@test "ID-less os-release clears partial fields for the ladder winner (C1)" {
    printf '%s\n' 'NAME="LeftoverName"' > "$_OS_ROOT/etc/os-release"
    : > "$_OS_ROOT/etc/arch-release"
    lib
    detect_os
    [ "$OS_ID" = "arch" ]
    [ "${OS_NAME:-}" != "LeftoverName" ]
    [ "$OS_FALLBACK_USED" = "1" ]
}

@test "POSIX-mode readonly OS_ID is caught, no shell abort (C2)" {
    printf '%s\n' 'ID=blocked' > "$_OS_ROOT/etc/os-release"
    run bash -c '
        set -o posix
        set -euo pipefail
        readonly OS_ID
        . "$1"
        detect_os || rc=$?
        printf "rc=%s id=%s\n" "${rc:-0}" "${OS_ID:-}"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"rc=1"* ]]
}

@test "caller-owned readonly _DETECT_OS_SOURCED never aborts sourcing (C2)" {
    printf '%s\n' 'ID=rdtest' > "$_OS_ROOT/etc/os-release"
    run bash -c '
        set -euo pipefail
        readonly _DETECT_OS_SOURCED
        . "$1"
        detect_os
        printf "id=%s\n" "${OS_ID:-}"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=rdtest"* ]]
}

@test "host lsb_release can never contaminate a _OS_ROOT detection (C3)" {
    # shellcheck disable=SC2016  # payload $vars expand in the child at runtime
    run bash -c '
        lsb_release() { printf "cachyos\n"; return 0; }
        timeout() { shift; "$@"; }
        export _OS_ROOT="$1"
        mkdir -p "$_OS_ROOT/etc"
        . "$2"
        detect_os
        printf "id=%s src=%s fb=%s\n" "$OS_ID" "$OS_SOURCE" "$OS_FALLBACK_USED"
    ' dummy "$_OS_ROOT" "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=linux src=uname fb=1"* ]]
    [[ "$output" != *"cachyos"* ]]
}

@test "FIFO planted at os-release never blocks detection (C7-DoS)" {
    local tb
    tb="$(command -v timeout 2>/dev/null)" || skip "no timeout(1) on PATH"
    mkfifo "$_OS_ROOT/etc/os-release"
    # shellcheck disable=SC2016  # payload $vars expand in the child at runtime
    run "$tb" 5 bash -c '
        lsb_release() { return 1; }
        timeout() { shift; "$@"; }
        . "$1"
        detect_os
        printf "id=%s src=%s fb=%s\n" "$OS_ID" "$OS_SOURCE" "$OS_FALLBACK_USED"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=linux src=uname fb=1"* ]]
}

@test "FIFO planted at lsb-release never blocks detection (C7-DoS)" {
    local tb
    tb="$(command -v timeout 2>/dev/null)" || skip "no timeout(1) on PATH"
    mkfifo "$_OS_ROOT/etc/lsb-release"
    # shellcheck disable=SC2016  # payload $vars expand in the child at runtime
    run "$tb" 5 bash -c '
        lsb_release() { return 1; }
        timeout() { shift; "$@"; }
        . "$1"
        detect_os
        printf "id=%s src=%s fb=%s\n" "$OS_ID" "$OS_SOURCE" "$OS_FALLBACK_USED"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=linux src=uname fb=1"* ]]
}

@test "os-release as a symlink to a directory is skipped, never read" {
    mkdir -p "$_OS_ROOT/etc/notafile"
    ln -s "$_OS_ROOT/etc/notafile" "$_OS_ROOT/etc/os-release"
    lib
    detect_os
    [ "$OS_ID" = "linux" ]
    [ "$OS_SOURCE" = "uname" ]
}

@test "display fields strip ESC/control bytes (C4)" {
    printf 'ID=esctest\nPRETTY_NAME="Red \033[1;31mX\033[0m"\nNAME="N\033[1m"\nVERSION="v\a"\nVERSION_CODENAME="\033[codename"\nID_LIKE="\033[like"\n' > "$_OS_ROOT/etc/os-release"
    lib
    detect_os
    [ "$OS_ID" = "esctest" ]
    case "$OS_PRETTY_NAME" in *$'\e'*) return 1 ;; esac
    case "$OS_NAME" in *$'\e'*) return 1 ;; esac
    case "$OS_VERSION" in *$'\e'*|*$'\a'*) return 1 ;; esac
    case "$OS_VERSION_CODENAME" in *$'\e'*) return 1 ;; esac
    case "$OS_ID_LIKE" in *$'\e'*) return 1 ;; esac
    case "$(os_distro)" in *$'\e'*) return 1 ;; esac
    [[ "$OS_PRETTY_NAME" == Red* ]]
}

@test "legacy release-file display line is sanitized (C4)" {
    printf 'Red Hat Enterprise Linux release 9.3 (Plano)\033[0m\n' > "$_OS_ROOT/etc/redhat-release"
    lib
    detect_os
    [ "$OS_ID" = "rhel" ]
    case "$OS_PRETTY_NAME" in *$'\e'*) return 1 ;; esac
}

# --- adversarial gap coverage (eval round 2, fixes 1-5) ---

@test "PATH mutation after source cannot disable redaction (pinned env)" {
    printf '%s\n' 'ID=pathtest' > "$_OS_ROOT/etc/os-release"
    run bash -c '
        export SECRET_PROBE=leakme7391
        . "$1"
        forge="$1.forge"
        mkdir -p "$forge"
        # A hostile env that drops SECRET_PROBE from the environment it prints.
        printf "%s\n" "export PATH=" > /dev/null
        : > "$forge/env"
        chmod +x "$forge/env"
        export PATH="$forge:$PATH"
        out=$(_os_redact "token leakme7391")
        printf "out=%s\n" "$out"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"[REDACTED]"* ]]
    [[ "$output" != *"leakme7391"* ]]
}

@test "refresh semantics: detect_os re-runs cleanly across changed fixtures" {
    printf '%s\n' 'ID=v1' > "$_OS_ROOT/etc/os-release"
    lib
    detect_os
    [ "$OS_ID" = "v1" ]
    printf '%s\n' 'ID=v2' > "$_OS_ROOT/etc/os-release"
    detect_os
    [ "$OS_ID" = "v2" ]
    [ "$OS_DETECTED" = "1" ]
}

@test "display fields strip shell metacharacters ; $ backtick and quotes/glob (fix)" {
    # shellcheck disable=SC2016  # metachars are literal fixture payload
    printf '%s\n' 'ID=mtest' \
        'PRETTY_NAME="X;Y$Z`W\q"'"'"'*?[]v"' \
        'NAME="A$B;C`D"' \
        'VERSION="1;2"' \
        'VERSION_CODENAME="cd;x"' \
        'ID_LIKE="li;ke rhel *"' \
        > "$_OS_ROOT/etc/os-release"
    lib
    detect_os
    case "$OS_PRETTY_NAME" in *';'*|*'$'*|*'`'*) return 1 ;; esac
    case "$OS_NAME" in *';'*|*'$'*|*'`'*) return 1 ;; esac
    case "$OS_VERSION" in *';'*|*'$'*|*'`'*) return 1 ;; esac
    case "$OS_VERSION_CODENAME" in *';'*|*'$'*|*'`'*) return 1 ;; esac
    case "$OS_ID_LIKE" in *';'*|*'$'*|*'`'*) return 1 ;; esac
    [[ "$OS_PRETTY_NAME" == "XYZWqv" ]]
    [[ "$OS_ID_LIKE" == "like rhel" ]]
}

@test "stale OS_DETECTED from an earlier run clears on later refusal (fix)" {
    printf '%s\n' 'ID=ok' > "$_OS_ROOT/etc/os-release"
    run bash -c '
        . "$1"
        detect_os
        printf "first det=%s\n" "$OS_DETECTED"
        readonly ID_OLD="x"    # unrelated name: must not trip the scan
        readonly OS_NAME=pre   # now collide
        detect_os || rc=$?
        printf "rc=%s det=%s\n" "${rc:-0}" "${OS_DETECTED:-}"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"first det=1"* ]]
    [[ "$output" == *"rc=1"* ]]
    [[ "$output" == *"det=0"* ]]
}

@test "readonly internal scratch _os_last_detail refuses, never aborts (fix)" {
    printf '%s\n' 'ID=blocked' > "$_OS_ROOT/etc/os-release"
    run bash -c '
        set -euo pipefail
        . "$1"
        readonly _os_last_detail=pre
        detect_os || rc=$?
        printf "rc=%s detail=%s\n" "${rc:-0}" "${_os_last_detail:-}"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"rc=1"* ]]
}

@test "sanitizer units: id/version/display scrub their char classes (fix)" {
    lib
    # shellcheck disable=SC2016  # $() is literal fixture payload
    # 'Ubuntu;$(id)' -> allowed [0-9a-zA-Z._-], lowercased; the rest become _.
    run _os_sanitize_id 'Ubuntu;$(id)'
    [ "$status" -eq 0 ]
    [ "$output" = "ubuntu___id_" ]

    # shellcheck disable=SC2016  # backticks are literal fixture payload
    # '1.2;3`rm`$x' -> allowed [0-9a-zA-Z._+-]; every other byte becomes _.
    run _os_sanitize_version '1.2;3`rm`$x'
    [ "$status" -eq 0 ]
    [ "$output" = "1.2_3_rm__x" ]

    run _os_sanitize_display $'A;\tB$C`D\033[0m'
    [ "$status" -eq 0 ]
    case "$output" in *';'*|*'$'*|*'`'*|*$'\e'*|*$'\t'*) return 1 ;; esac
    [ "$output" = "ABCD0m" ]

    # multibyte UTF-8 passes through untouched; quotes/glob still stripped.
    run _os_sanitize_display "Debian GNU/Linux 12 — bookworm é"
    [ "$status" -eq 0 ]
    [ "$output" = "Debian GNU/Linux 12 — bookworm é" ]
    run _os_sanitize_display "A'\"\\*?[]{}|&<>v"
    [ "$status" -eq 0 ]
    [ "$output" = "Av" ]
}

# --- adversarial gap coverage (eval round 6, fixes C1 S1 S2 S3 C2 Q1) ---

@test "ID-less lsb-release partials never mix into the legacy winner (C1-mix)" {
    printf '%s\n' 'NAME="NoID Distro"' > "$_OS_ROOT/etc/os-release"
    printf '%s\n' 'DISTRIB_RELEASE="22.04"' \
                  'DISTRIB_DESCRIPTION="Ubuntu 22.04 LTS"' > "$_OS_ROOT/etc/lsb-release"
    : > "$_OS_ROOT/etc/arch-release"
    lib
    detect_os
    [ "$OS_ID" = "arch" ]
    [ "$OS_SOURCE" = "$_OS_ROOT/etc/arch-release" ]
    [ -z "$OS_VERSION_ID" ]
    [ -z "$OS_VERSION_CODENAME" ]
    [ -z "$OS_PRETTY_NAME" ]
}

@test "ID-less lsb_release command partials never survive (C1-mix cmd)" {
    local stub="$BATS_TEST_TMPDIR/lsb-stub"
    cat > "$stub" <<'STUB'
#!/usr/bin/env bash
case "$1" in
    -is) exit 1 ;;
    -rs) printf '%s\n' '22.04' ;;
    -cs) printf '%s\n' 'jammy' ;;
    -ds) printf '%s\n' 'Ubuntu 22.04 LTS' ;;
esac
STUB
    chmod +x "$stub"
    # shellcheck disable=SC2016  # fixture payload $vars expand in the child at runtime
    run env _OS_LSBRELEASE="$stub" bash -c '
        . "$1"
        unset _OS_ROOT
        _detect() { _os_run_lsb_cmd; }
        _detect; rc=$?
        printf "rc=%s\nOS_VERSION_ID=%s\nOS_VERSION_CODENAME=%s\nOS_PRETTY_NAME=%s\n" "$rc" "$OS_VERSION_ID" "$OS_VERSION_CODENAME" "$OS_PRETTY_NAME"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    printf '%s\n' "$output" | grep -q '^rc=1$'
    printf '%s\n' "$output" | grep -q '^OS_VERSION_ID=$'
    printf '%s\n' "$output" | grep -q '^OS_VERSION_CODENAME=$'
    printf '%s\n' "$output" | grep -q '^OS_PRETTY_NAME=$'
    rm -f "$stub"
}

@test "redaction: quoted NAME=\"sec ret\" form redacts whole, no tail (S1)" {
    lib
    TOKEN='sec ret' run _os_redact 'TOKEN="sec ret" tail'
    [ "$status" -eq 0 ]
    [ "$output" = "[REDACTED] tail" ]
}

@test "redaction: single-quoted NAME='sec ret' form redacts whole (S1)" {
    lib
    TOKEN='sec ret' run _os_redact "TOKEN='sec ret' tail"
    [ "$status" -eq 0 ]
    [ "$output" = "[REDACTED] tail" ]
}

@test "redaction: declare -p dump of a secret is fully redacted (S1)" {
    lib
    TOKEN='sec ret' run _os_redact 'declare -- TOKEN="sec ret"'
    [ "$status" -eq 0 ]
    [ "$output" = "declare -- [REDACTED]" ]
}

@test "pre-planted error-log symlink is never followed (S2)" {
    local default_path dir victim
    export XDG_STATE_HOME="$BATS_TEST_TMPDIR/xdgstate"
    lib
    default_path="$(_os_error_log_path)"
    dir="${default_path%/*}"
    victim="$BATS_TEST_TMPDIR/victim"
    rm -rf "$dir"
    mkdir -p "$dir"
    printf '%s\n' 'victim-original' > "$victim"
    chmod 644 "$victim"
    ln -s "$victim" "$default_path"
    run _os_ensure_error_log
    [ "$status" -eq 1 ]
    [ "$(cat "$victim")" = "victim-original" ]
    [ "$(stat -c '%a' "$victim")" = "644" ]
    rm -rf "$dir"
    rm -f "$victim"
}

@test "failure-log lib field escapes hostile basename quotes (S3)" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/s3.jsonl"
    cp "$BATS_TEST_DIRNAME/../fx-detect-os.sh" "$BATS_TEST_TMPDIR/lib\"x.sh"
    run bash -c '
        . "$1"
        _os_steps=("os-release" "1" "detail")
        _os_failure_record
    ' dummy "$BATS_TEST_TMPDIR/lib\"x.sh"
    [ -f "$_OS_ERROR_LOG" ]
    run grep -F '"lib":"lib\"x.sh"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    rm -f "$_OS_ERROR_LOG" "$BATS_TEST_TMPDIR/lib\"x.sh"
}

@test "all-invalid os-release ID defers down the ladder, never fabricated (C2)" {
    printf '%s\n' 'ID=@@@@' 'NAME="Hostile"' > "$_OS_ROOT/etc/os-release"
    : > "$_OS_ROOT/etc/arch-release"
    lib
    detect_os
    [ "$OS_ID" = "arch" ]
    [ "$OS_SOURCE" = "$_OS_ROOT/etc/arch-release" ]
    [ "$OS_NAME" = "Arch Linux" ]
}

@test "sanitize_id: all-invalid input prints empty, still rc 0 (C2)" {
    lib
    run _os_sanitize_id '@@@@'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
    run _os_sanitize_id 'Manjaro;23'
    [ "$status" -eq 0 ]
    [ "$output" = "manjaro_23" ]
    run _os_sanitize_id 'ubuntu'
    [ "$status" -eq 0 ]
    [ "$output" = "ubuntu" ]
}

@test "_OS_NO_ERROR_LOG=1 opts out of the failure log entirely (Q1)" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/optout.jsonl"
    export _OS_NO_ERROR_LOG=1
    lib
    _os_steps=("os-release" "1" "detail")
    _os_failure_record
    [ ! -f "$_OS_ERROR_LOG" ]
}

@test "identity-unresolved honors _OS_NO_ERROR_LOG end-to-end (Q1)" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/optout-e2e.jsonl"
    export _OS_NO_ERROR_LOG=1
    run bash -c '
        _OS_MKDIR="$(command -v mkdir)"
        _OS_CHMOD="$(command -v chmod)"
        _OS_DATE="$(command -v date)"
        _OS_ENV="$(command -v env)"
        export PATH=/nonexistent
        . "$1"
        export PATH=/usr/bin:/bin
        detect_os
        printf "rc=%s\n" "$?"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"rc=1"* ]]
    [ ! -f "$_OS_ERROR_LOG" ]
}

@test "fuzz: random hostile lines never leak wordlist values (property)" {
    # The 200-iteration loop runs in an untrapped child shell (see
    # test/fuzz_redact.sh). bats installs a DEBUG trap on @test bodies; the
    # per-command tax turns this loop into ~30s under the trap, milliseconds
    # without it. Coverage is identical: the loop only calls _os_redact.
    run bash "$BATS_TEST_DIRNAME/fuzz_redact.sh" "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
}

@test "wordlist: separator-delimited key/auth names stay redacted (fix)" {
    lib
    local name
    for name in AWS_ACCESS_KEY_ID OPENAI_API_KEY PRIVATE_KEY ACCESS_KEY KEY_ID AUTH_TOKEN CDN_AUTH_KEY AUTH KEY; do
        run _os_redact "$name=vAlUe123"
        [ "$status" -eq 0 ]
        [ "$output" = "[REDACTED]" ] || { printf 'not redacted: %s -> %s\n' "$name" "$output"; return 1; }
    done
}

@test "wordlist: key/auth substrings in innocuous names are NOT redacted (fix)" {
    lib
    local name
    for name in MONKEY KEYRING KEYBOARD HOCKEY TURKEY KEYMAP GIT_AUTHOR_NAME AUTHOR GIT_AUTHOR; do
        run _os_redact "$name=vAlUe123"
        [ "$status" -eq 0 ]
        [ "$output" = "$name=vAlUe123" ] || { printf 'over-redacted: %s -> %s\n' "$name" "$output"; return 1; }
    done
}

@test "failure-log caller and lib fields are redacted (fix)" {
    export _OS_ERROR_LOG="$BATS_TEST_TMPDIR/s4.jsonl"
    cp "$BATS_TEST_DIRNAME/../fx-detect-os.sh" "$BATS_TEST_TMPDIR/lib-TOKEN=abc.sh"
    run bash -c '
        . "$1"
        _os_steps=("os-release" "1" "detail")
        _os_failure_record
    ' 'TOKEN=abc' "$BATS_TEST_TMPDIR/lib-TOKEN=abc.sh"
    [ -f "$_OS_ERROR_LOG" ]
    run grep -F '"caller":"[REDACTED]"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    run grep -F '"lib":"lib-[REDACTED]"' "$_OS_ERROR_LOG"
    [ "$status" -eq 0 ]
    run grep -F 'TOKEN=abc' "$_OS_ERROR_LOG"
    [ "$status" -ne 0 ]
    rm -f "$_OS_ERROR_LOG" "$BATS_TEST_TMPDIR/lib-TOKEN=abc.sh"
}

@test "debug-log path echo is redacted on stderr (fix)" {
    lib
    export _OS_DEBUG=1 _OS_LOG_FILE="$BATS_TEST_TMPDIR/dir-TOKEN=abc/osdetect.log"
    mkdir -p "$(dirname "$_OS_LOG_FILE")"
    run _os_log "hello"
    [ "$status" -eq 0 ]
    [[ "$output" != *"TOKEN=abc"* ]]
    [[ "$output" == *"[REDACTED]"* ]]
    rm -rf "$(dirname "$_OS_LOG_FILE")"
}

# --- round-6 hardening: trust level, size guard, warnings, guard (v1.7.0) ---

@test "trust: os-release step is high, lsb file is medium, catch-all and uname are low" {
    lib
    # step 1 os-release -> high
    printf '%s\n' 'ID=debian' 'VERSION_ID="12"' > "$_OS_ROOT/etc/os-release"
    detect_os
    [ "$OS_ID" = "debian" ]
    [ "$OS_TRUST_LEVEL" = "high" ]
    # step 2 legacy lsb-release file -> medium
    rm -f "$_OS_ROOT/etc/os-release"
    printf '%s\n' 'DISTRIB_ID=Ubuntu' > "$_OS_ROOT/etc/lsb-release"
    detect_os
    [ "$OS_ID" = "ubuntu" ]
    [ "$OS_TRUST_LEVEL" = "medium" ]
    # step 4 named legacy file -> medium
    rm -f "$_OS_ROOT/etc/lsb-release"
    printf '%s\n' '12.9' > "$_OS_ROOT/etc/debian_version"
    detect_os
    [ "$OS_ID" = "debian" ]
    [ "$OS_TRUST_LEVEL" = "medium" ]
    # catch-all legacy glob -> low
    rm -f "$_OS_ROOT/etc/debian_version"
    printf '%s\n' 'Nobara 40' > "$_OS_ROOT/etc/nobara-release"
    detect_os
    [ "$OS_ID" = "nobara" ]
    [ "$OS_TRUST_LEVEL" = "low" ]
    # step 5 uname last resort -> low
    rm -f "$_OS_ROOT/etc/nobara-release"
    detect_os
    [ "$OS_ID" = "linux" ]
    [ "$OS_TRUST_LEVEL" = "low" ]
}

@test "trust: lsb_release command step is medium (stub)" {
    local stub="$BATS_TEST_TMPDIR/lsb-trust-stub"
    cat > "$stub" <<'STUB'
#!/usr/bin/env bash
case "$1" in
    -is) printf '%s\n' 'Ubuntu' ;;
    *)   printf '%s\n' 'x' ;;
esac
STUB
    chmod +x "$stub"
    # shellcheck disable=SC2016  # fixture payload $vars expand in the child at runtime
    run env _OS_LSBRELEASE="$stub" bash -c '
        . "$1"
        unset _OS_ROOT
        _os_run_lsb_cmd
        printf "id=%s trust=%s\n" "$OS_ID" "$OS_TRUST_LEVEL"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    printf '%s\n' "$output" | grep -q '^id=ubuntu trust=medium$'
    rm -f "$stub"
}

@test "trust: unresolved identity is none and lands in failure-log finals" {
    run bash -c '
        export _OS_ERROR_LOG="$2"
        readonly _OS_UNAME=
        . "$1"
        detect_os; rc=$?
        printf "rc=%s trust=%s\n" "$rc" "$OS_TRUST_LEVEL"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh" "$BATS_TEST_TMPDIR/trust-none.jsonl"
    [ "$status" -eq 0 ]
    printf '%s\n' "$output" | grep -q '^rc=1 trust=none$'
    run grep -F '"TRUST_LEVEL":"none"' "$BATS_TEST_TMPDIR/trust-none.jsonl"
    [ "$status" -eq 0 ]
    rm -f "$BATS_TEST_TMPDIR/trust-none.jsonl"
}

@test "trust: cleared between runs (no bleed from a prior high into uname low)" {
    lib
    printf '%s\n' 'ID=debian' > "$_OS_ROOT/etc/os-release"
    detect_os
    [ "$OS_TRUST_LEVEL" = "high" ]
    rm -f "$_OS_ROOT/etc/os-release"
    detect_os
    [ "$OS_TRUST_LEVEL" = "low" ]   # fell to uname; must not keep "high"
}

@test "size guard: oversized single-line os-release defers, never slurped" {
    { printf '%s\n' 'ID=huge'; head -c 300000 /dev/zero | tr '\0' 'A'; } > "$_OS_ROOT/etc/os-release"
    : > "$_OS_ROOT/etc/arch-release"
    lib
    detect_os
    [ "$OS_ID" = "arch" ]
    [ "$OS_TRUST_LEVEL" = "medium" ]
}

@test "size guard: oversized lsb-release defers to the next legacy step" {
    { printf '%s\n' 'DISTRIB_ID=Huge'; head -c 300000 /dev/zero | tr '\0' 'A'; } > "$_OS_ROOT/etc/lsb-release"
    : > "$_OS_ROOT/etc/arch-release"
    lib
    detect_os
    [ "$OS_ID" = "arch" ]
}

@test "size guard: oversized containerenv is ignored (container stays none)" {
    printf '%s\n' 'ID=debian' > "$_OS_ROOT/etc/os-release"
    mkdir -p "$_OS_ROOT/run"
    { printf '%s\n' 'engine="podman"'; head -c 8192 /dev/zero | tr '\0' 'A'; } > "$_OS_ROOT/run/.containerenv"
    lib
    detect_os
    [ "$OS_ID" = "debian" ]
    [ "$OS_CONTAINER" = "none" ]
}

@test "size guard: _os_file_ok empty file passes (presence marker), giant file rejected" {
    lib
    local small="$BATS_TEST_TMPDIR/small-ok" big="$BATS_TEST_TMPDIR/big-no"
    : > "$small"
    { printf 'x\n'; head -c 300000 /dev/zero | tr '\0' 'A'; } > "$big"
    run _os_file_ok "$small"
    [ "$status" -eq 0 ]
    run _os_file_ok "$small" 16
    [ "$status" -eq 0 ]
    run _os_file_ok "$big"
    [ "$status" -ne 0 ]
    rm -f "$small" "$big"
}

@test "env absence at source time warns once (redaction value-pass disabled)" {
    run bash -c '
        readonly _OS_ENV=
        . "$1"
        echo loaded
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"env was not found on PATH at source time"* ]]
    [[ "$output" == *"loaded"* ]]
}

@test "world-visible caller log warns but keeps its mode (B3)" {
    lib
    [ -n "$_OS_STAT" ] || skip "stat not available"
    local log="$BATS_TEST_TMPDIR/ww.log"
    : > "$log"
    chmod 0644 "$log"
    export _OS_DEBUG=1 _OS_LOG_FILE="$log"
    run _os_log "hello"
    [ "$status" -eq 0 ]
    [[ "$output" == *"world-visible mode"* ]]
    [ "$(stat -c %a "$log")" = "644" ]
    chmod 0600 "$log"
    run _os_log "hi"
    [[ "$output" != *"world-visible"* ]]
    unset _OS_DEBUG
    rm -f "$log"
}

@test "forged load flag + one helper marker alone cannot fake a load (B4)" {
    run bash -c '
        _DETECT_OS_SOURCED=1
        _os_debug_active() { :; }
        . "$1"
        command -v detect_os >/dev/null && echo LOADED
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [ "$output" = "LOADED" ]
}

@test "double-source still a no-op after the EOF-marker guard (B4)" {
    . "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    . "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    detect_os
    [ "${OS_DETECTED:-0}" = "1" ]
}

@test "catch-all never preempts a named legacy family source (C2 ordering)" {
    lib
    printf '%s\n' 'aaa 1.0' > "$_OS_ROOT/etc/aaa-release"
    printf '%s\n' 'CentOS Linux release 7.9.2009 (Core)' > "$_OS_ROOT/etc/centos-release"
    detect_os
    [ "$OS_ID" = "centos" ]
    [ "$OS_TRUST_LEVEL" = "medium" ]   # named branch, not the catch-all "low"
}

@test "_os_unquote strips both quote flavors and leaves bare values intact" {
    lib
    run _os_unquote '"quoted"'
    [ "$status" -eq 0 ]; [ "$output" = "quoted" ]
    run _os_unquote "'quoted'"
    [ "$status" -eq 0 ]; [ "$output" = "quoted" ]
    run _os_unquote '"a"b"'
    [ "$status" -eq 0 ]; [ "$output" = "a\"b" ]
    run _os_unquote 'plain'
    [ "$status" -eq 0 ]; [ "$output" = "plain" ]
    run _os_unquote '""'
    [ "$status" -eq 0 ]; [ -z "$output" ]
}

@test "_os_field_listed recognizes vocabulary and rejects near-misses" {
    lib
    _os_field_listed OS_DETECTED
    _os_field_listed OS_TRUST_LEVEL
    _os_field_listed _os_last_detail
    if _os_field_listed OS_FUTURE; then return 1; fi
    if _os_field_listed OS_DETECTE; then return 1; fi
    if _os_field_listed OS_SOURCES; then return 1; fi
}

@test "_os_is_readonly detects declare -r, -ra and -rA forms" {
    lib
    # shellcheck disable=SC2034  # the declarations ARE the test subjects
    declare -r ro_scalar=one
    # shellcheck disable=SC2034  # the declarations ARE the test subjects
    declare -ra ro_array=()
    # shellcheck disable=SC2034  # the declarations ARE the test subjects
    declare -rA ro_assoc=()
    # shellcheck disable=SC2034  # the negative control is consumed via _os_is_readonly
    declare rw_local=three
    _os_is_readonly ro_scalar
    _os_is_readonly ro_array
    _os_is_readonly ro_assoc
    if _os_is_readonly rw_local; then return 1; fi
}

@test "containerenv without engine= resolves OS_CONTAINER=containers" {
    lib
    mkdir -p "$_OS_ROOT/run"
    : > "$_OS_ROOT/run/.containerenv"
    _os_detect_container
    [ "$OS_CONTAINER" = "containers" ]
}

@test "SuSE-release without Tumbleweed/Leap/openSUSE resolves sles" {
    lib
    printf '%s\n' 'SUSE Linux Enterprise Server 15' > "$_OS_ROOT/etc/SuSE-release"
    detect_os
    [ "$OS_ID" = "sles" ]
    [ "$OS_NAME" = "SUSE Linux Enterprise" ]
    [ "$OS_TRUST_LEVEL" = "medium" ]
}

@test "_release (underscore) catch-all suffix yields a usable ID" {
    lib
    printf '%s\n' 'MegaOS 1.0' > "$_OS_ROOT/etc/mega_release"
    detect_os
    [ "$OS_ID" = "mega" ]
    [ "$OS_TRUST_LEVEL" = "low" ]
}

@test "SCRIPT_DEBUG=1 alone activates the debug path" {
    lib
    unset _OS_DEBUG
    export SCRIPT_DEBUG=1
    run _os_debug_active
    [ "$status" -eq 0 ]
    export SCRIPT_DEBUG=0
    if _os_debug_active; then return 1; fi
}

@test "error-log path falls back to TMPDIR when XDG_STATE_HOME and HOME are unset" {
    local exp="$BATS_TEST_TMPDIR/alt-tmp/osdetect/osdetect-failures.jsonl"
    run bash -c '
        unset XDG_STATE_HOME HOME
        export TMPDIR="$2"
        . "$1"
        _os_error_log_path
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh" "$BATS_TEST_TMPDIR/alt-tmp"
    [ "$status" -eq 0 ]
    [ "$output" = "$exp" ]
}

@test "redaction name-pass survives a missing env (no env, no value-pass)" {
    run bash -c '
        readonly _OS_ENV=
        export MY_TOKEN="supersecretvalue123"
        . "$1"
        _os_redact "prefix MY_TOKEN=supersecretvalue123 tail"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"prefix [REDACTED] tail"* ]]
    [[ "$output" != *"supersecretvalue123"* ]]
}

@test "OS_DISTRO composes from NAME plus VERSION_ID when PRETTY_NAME/VERSION absent" {
    lib
    printf '%s\n' 'NAME="MegaOS"' 'ID=mega' 'VERSION_ID="7.2"' > "$_OS_ROOT/etc/os-release"
    detect_os
    [ "$OS_DISTRO" = "MegaOS 7.2" ]
    [ "$OS_TRUST_LEVEL" = "high" ]
}

@test "fuzz: sanitizer invariants and trust vocabulary hold for random inputs" {
    # Child shell for the same reason as the redaction fuzz: bats' DEBUG trap
    # on the @test body makes a 200-iteration loop ~9s; the helper sources the
    # lib and runs the identical invariants without the per-command tax.
    run bash "$BATS_TEST_DIRNAME/fuzz_sanitize.sh" "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
}

@test "fuzz: detect_os always rc 0/1 and a valid trust level for random-size release files" {
    # Child shell (test/fuzz_detect.sh): each detect_os run executes hundreds
    # of commands, and bats' DEBUG trap on the @test body taxes every one
    # (~1.7s/run here). The helper sources the lib, isolates itself with a
    # fresh _OS_ROOT, and refuses to write failure records, like the design.
    run bash "$BATS_TEST_DIRNAME/fuzz_detect.sh" "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
}

# --- adversarial eval fixes (2026-09-17) ---

@test "command-step run does not unset _os_lsb (F2)" {
    run bash -c '
        lsb_release() { printf "ubuntu\n"; return 0; }
        . "$1"
        unset _OS_ROOT
        before=$(declare -F _os_lsb >/dev/null 2>&1 && echo yes || echo no)
        _os_run_lsb_cmd >/dev/null 2>&1 || true
        after=$(declare -F _os_lsb >/dev/null 2>&1 && echo yes || echo no)
        printf "before=%s after=%s\n" "$before" "$after"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"before=yes"* ]]
    [[ "$output" == *"after=yes"* ]]
}

@test "debug requested with no log target warns once (F1)" {
    run bash -c '
        export PATH=""
        export _OS_DEBUG=1
        . "$1"
        _os_ensure_log_file
        _os_ensure_log_file
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [ "$(printf '%s\n' "$output" | grep -c 'debug log is OFF')" -eq 1 ]
}

@test "world-visible caller error log warns but keeps its mode (F3)" {
    lib
    [ -n "$_OS_STAT" ] || skip "stat not available"
    local log="$BATS_TEST_TMPDIR/fw.log"
    : > "$log"
    chmod 0644 "$log"
    export _OS_ERROR_LOG="$log"
    run _os_ensure_error_log
    [ "$status" -eq 0 ]
    [[ "$output" == *"world-visible mode"* ]]
    [ "$(stat -c %a "$log")" = "644" ]
    chmod 0600 "$log"
    run _os_ensure_error_log
    [[ "$output" != *"world-visible"* ]]
    rm -f "$log"
}

@test "redaction: digit-leading secret names redact in NAME=value form (F7)" {
    lib
    run _os_redact 'cfg 3DES_KEY=value123 tail'
    [ "$status" -eq 0 ]
    [ "$output" = "cfg [REDACTED] tail" ]
}

# --- adversarial review fixes (2026-09-18, redteam round) ---

@test "redaction: insertion sort survives caller set -e (RT-errexit)" {
    run bash -c '
        set -e
        export KEY=abcd TOKEN=abcdef
        . "$1"
        _os_redact "now handling key=abcd token=abcdef"
        printf "SURVIVED\n"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"SURVIVED"* ]]
}

@test "sanitizer: C1 controls dropped in lone-byte and UTF-8 pair forms (RT-C1)" {
    lib
    # Lone C1 bytes (0x80..0x9F) cannot survive display scrubbing.
    run _os_sanitize_display 'X'$'\x80''Y'$'\x9b''Z'$'\x9f''W'
    [ "$status" -eq 0 ]
    [ "$output" = "XYZW" ]
    # Their valid UTF-8 encodings (C2 80..9F, U+0080..U+009F) are dropped too.
    run _os_sanitize_display "X$(printf '\302\200')Y$(printf '\302\233')Z$(printf '\302\237')W"
    [ "$status" -eq 0 ]
    [ "$output" = "XYZW" ]
    # Valid non-control multibyte keeps fidelity: é (C3 A9), em-dash (E2 80 94).
    run _os_sanitize_display "Debian — bookworm é"
    [ "$status" -eq 0 ]
    [ "$output" = "Debian — bookworm é" ]
}

@test "function preflight: pre-existing generic name is reported and detect_os refuses" {
    run bash -c '
        os_id() { printf "caller-owned\n"; }
        . "$1"
        detect_os
        printf "rc=%s\n" "$?"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"osdetect: function-namespace collision"* ]]
    [[ "$output" == *"os_id"* ]]
    [[ "$output" == *"refusing to run"* ]]
    [[ "$output" == *"rc=1"* ]]
}

@test "function preflight: collision on the entry point itself also refuses (RT-F1b)" {
    run bash -c '
        detect_os() { printf "caller-owned\n"; }
        . "$1"
        detect_os
        printf "rc=%s\n" "$?"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"function-namespace collision"* ]]
    [[ "$output" == *"rc=1"* ]]
}

@test "identity-unresolved warns loudly on stderr (RT-F2)" {
    run bash -c '
        _OS_MKDIR="$(command -v mkdir)"
        _OS_CHMOD="$(command -v chmod)"
        _OS_DATE="$(command -v date)"
        _OS_ENV="$(command -v env)"
        export PATH=/nonexistent
        . "$1"
        export PATH=/usr/bin:/bin
        detect_os
        printf "rc=%s\n" "$?"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"osdetect:"* ]]
    [[ "$output" == *"identity could not be resolved"* ]]
    [[ "$output" == *"rc=1"* ]]
}

@test "wordlist: pw/pwd/passwd suffix names redact, PWD/OLDPWD paths do not (RT-F5)" {
    lib
    run _os_redact 'cfg MAILPW=secret1 USERPW=secret2 MYSQL_PWD=secret3 tail'
    [ "$status" -eq 0 ]
    [ "$output" = "cfg [REDACTED] [REDACTED] [REDACTED] tail" ]
    # The working-directory variables are paths, never credentials: unredacted.
    run _os_redact 'PWD=/home/user and OLDPWD=/home tail'
    [ "$status" -eq 0 ]
    [ "$output" = "PWD=/home/user and OLDPWD=/home tail" ]
    # Separator-less compound-key spellings now redact too.
    run _os_redact 'tok S3ACCESSKEY=secret4 APPKEY=secret5 tail'
    [ "$status" -eq 0 ]
    [ "$output" = "tok [REDACTED] [REDACTED] tail" ]
    # Innocuous neighbors stay untouched (no pw-suffix overcatch).
    run _os_redact 'MONKEY=one KEYBOARD=two TURKEY=three KEYMAP=four GIT_AUTHOR_NAME=jim'
    [ "$status" -eq 0 ]
    [ "$output" = "MONKEY=one KEYBOARD=two TURKEY=three KEYMAP=four GIT_AUTHOR_NAME=jim" ]
}

@test "redaction: multi-line env value tail is reassembled and redacted (RT-F6)" {
    local forge
    forge="$BATS_TEST_TMPDIR/forge"
    mkdir -p "$forge"
    printf '#!/bin/sh\nprintf "TOKEN=abcdefgh\\nijklmnop\\n"\n' > "$forge/env"
    chmod +x "$forge/env"
    run bash -c '
        export PATH="$1:$PATH"
        . "$2"
        _os_redact "saw the tail ijklmnop leaked alone"
        printf "---\n"
        _os_redact "log TOKEN=abcdefgh then ijklmnop separately"
        printf "---\n"
        _os_redact "PWD=/home and OLDPWD=/old stay plain"
    ' dummy "$forge" "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"saw the tail [REDACTED] leaked alone"* ]]
    [[ "$output" == *"log [REDACTED] then [REDACTED] separately"* ]]
    [[ "$output" == *"PWD=/home and OLDPWD=/old stay plain"* ]]
}

@test "reset: kernel/arch metadata never bleeds across a fresh run (RT-H1)" {
    printf '%s\n' 'ID=ok' > "$_OS_ROOT/etc/os-release"
    run bash -c '
        . "$1"
        OS_KERNEL=leakedkernel OS_KERNEL_RELEASE=9.9.9-host OS_ARCH=leakedarch
        OS_ID=stale OS_TRUST_LEVEL=high
        detect_os
        printf "rc=%s id=%s kern=[%s] rel=[%s] arch=[%s] trust=%s\n" \
            "$?" "${OS_ID:-}" "${OS_KERNEL:-}" "${OS_KERNEL_RELEASE:-}" "${OS_ARCH:-}" "$OS_TRUST_LEVEL"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"rc=0"* && "$output" == *"id=ok"* && "$output" == *"trust=high"* ]]
    [[ "$output" != *"leakedkernel"* && "$output" != *"9.9.9-host"* && "$output" != *"leakedarch"* ]]
}

@test "refusal clears stale identity fields so rc 1 cannot masquerade as truth (RT-H2)" {
    printf '%s\n' 'ID=ok' > "$_OS_ROOT/etc/os-release"
    run bash -c '
        . "$1"
        detect_os
        printf "first id=%s trust=%s det=%s\n" "$OS_ID" "$OS_TRUST_LEVEL" "$OS_DETECTED"
        readonly OS_PRETTY_NAME=pre
        detect_os || rc=$?
        printf "rc=%s id=[%s] trust=[%s] distro=[%s] det=%s\n" \
            "${rc:-0}" "${OS_ID:-}" "${OS_TRUST_LEVEL:-}" "${OS_DISTRO:-}" "${OS_DETECTED:-}"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"first id=ok"* && "$output" == *"trust=high"* && "$output" == *"det=1"* ]]
    [[ "$output" == *"rc=1"* && "$output" == *"id=[]"* && "$output" == *"trust=[]"* && "$output" == *"distro=[]"* && "$output" == *"det=0"* ]]
}

@test "legacy fedora/rocky/almalinux release files get medium trust (RT-H3)" {
    lib
    printf '%s\n' 'Fedora release 39 (Thirty Nine)' > "$_OS_ROOT/etc/fedora-release"
    detect_os
    [ "$OS_ID" = "fedora" ]
    [ "$OS_TRUST_LEVEL" = "medium" ]
    [ "$OS_SOURCE" = "$_OS_ROOT/etc/fedora-release" ]
    rm -f "$_OS_ROOT/etc/fedora-release"
    printf '%s\n' 'Rocky Linux release 9.3 (Blue Onyx)' > "$_OS_ROOT/etc/rocky-release"
    detect_os
    [ "$OS_ID" = "rocky" ]
    [ "$OS_TRUST_LEVEL" = "medium" ]
    rm -f "$_OS_ROOT/etc/rocky-release"
    printf '%s\n' 'AlmaLinux release 9.2 (Turquoise Kodkod)' > "$_OS_ROOT/etc/almalinux-release"
    detect_os
    [ "$OS_ID" = "almalinux" ]
    [ "$OS_TRUST_LEVEL" = "medium" ]
}

@test "OS_DISTRO stays empty when identity is unresolved (RT-H4)" {
    run bash -c '
        export _OS_UNAME=
        . "$1"
        detect_os || rc=$?
        printf "rc=%s id=[%s] distro=[%s]\n" "${rc:-0}" "${OS_ID:-}" "${OS_DISTRO:-}"
    ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"rc=1"* && "$output" == *"distro=[]"* ]]
}

@test "wordlist: obfuscation/typo variants never leak their values (RT-H5)" {
    lib
    DB_PASWRD='paswrdvalue123' SESSION_AUTHID='authidtoken456' SVC_KEYID='keyidsecret789' CRDT='badcrdtvalue1' SECRT='secrvalue7890' \
        run _os_redact 'tok paswrdvalue123 authidtoken456 keyidsecret789 badcrdtvalue1 secrvalue7890'
    [ "$status" -eq 0 ]
    [[ "$output" != *"paswrdvalue123"* && "$output" != *"authidtoken456"* ]]
    [[ "$output" != *"keyidsecret789"* && "$output" != *"badcrdtvalue1"* && "$output" != *"secrvalue7890"* ]]
    [[ "$output" == *"[REDACTED]"* ]]
}

@test "redaction: exported assoc-array component values are scrubbed (RT-H6)" {
    lib
    declare -Ax CREDS=([token]='assocsecrettok1' [other]='x')
    export CREDS
    run _os_redact '--token assocsecrettok1 verbatim'
    [ "$status" -eq 0 ]
    [[ "$output" != *"assocsecrettok1"* ]]
    [[ "$output" == *"[REDACTED]"* ]]
}
@test "bash4.0: error-log mode check never uses negative-offset substring (R18-402)" {
    rg -n '\$\{emode: -' "$BATS_TEST_DIRNAME/../fx-detect-os.sh" && return 1
    return 0
}

@test "bash4.0: real runtime smoke via docker bash:4.0 image (R18-403)" {
    if ! command -v docker >/dev/null 2>&1; then
        skip "docker not installed"
    fi
    if ! docker info >/dev/null 2>&1; then
        skip "docker daemon not running"
    fi
    run docker run --rm -v "$BATS_TEST_DIRNAME/..:/work:ro" -w /work bash:4.0 \
        bash /work/test/bash40_smoke.sh /work/fx-detect-os.sh
    if [ "$status" -ne 0 ]; then
        printf 'bash-4.0 docker smoke failed (rc=%s):\n%s\n' "$status" "$output" >&3
    fi
    [ "$status" -eq 0 ]
}

@test "cap-probe: multi-line file at/below cap acceptable when stat and wc absent (R18-C1)" {
    export PATH=/nonexistent
    lib
    : > "$_OS_ROOT/etc/arch-release"
    printf 'ID=debian\nVERSION_ID="12"\nNAME="Debian GNU/Linux"\n' > "$_OS_ROOT/etc/os-release"
    run _os_file_ok "$_OS_ROOT/etc/os-release"
    [ "$status" -eq 0 ]
    detect_os
    [ "$OS_ID" = "debian" ]
    export PATH=/usr/bin:/bin
}

@test "cap-probe: oversized file still rejected when stat and wc absent (R18-C2)" {
    local big="$BATS_TEST_TMPDIR/big"
    { printf '%s\n' 'ID=huge'; head -c 300000 /dev/zero | tr '\0' 'A'; } > "$big"
    export PATH=/nonexistent
    lib
    run _os_file_ok "$big"
    [ "$status" -eq 1 ]
    export PATH=/usr/bin:/bin
}

@test "catch-all exclusion arms: malformed known-family files never re-claimed low (R18-A2)" {
    local base want
    for base in redhat-release centos-release fedora-release rocky-release \
                almalinux-release system-release lsb-release; do
        _OS_ROOT="$BATS_TEST_TMPDIR/t_$base"
        mkdir -p "$_OS_ROOT/etc"
        printf '%s\n' 'unrecognized vendor string' > "$_OS_ROOT/etc/$base"
        want=$(_OS_ROOT="$BATS_TEST_TMPDIR/t_$base" bash -c '
            lsb_release(){ return 1; }; timeout(){ shift; "$@"; }
            . "$1"
            detect_os
            printf "%s|%s|%s" "$OS_SOURCE" "$OS_ID" "$OS_TRUST_LEVEL"
        ' dummy "$BATS_TEST_DIRNAME/../fx-detect-os.sh")
        # Exclusion arm held: falls through to uname (low), never claims <id>.
        [[ "$want" == "uname|linux|low" ]] || { echo "arm $base leaked: $want"; return 1; }
    done
}

@test "shape: Authorization: Bearer header token redacted (R18-S1)" {
    lib
    run _os_redact_shapes 'curl -H "Authorization: Bearer eyJhbGciOi.eyJzdWIiOiJP.6mM8hzQYMi"'
    [ "$status" -eq 0 ]
    [[ "$output" == *"Bearer [REDACTED]"* ]]
    [[ "$output" != *"eyJhbGciOi"* ]]
}

@test "shape: bare Bearer token >=20 chars redacted (R18-S2)" {
    lib
    run _os_redact_shapes 'using Bearer 1234567890abcdefghijk in url'
    [ "$status" -eq 0 ]
    [[ "$output" == *"Bearer [REDACTED]"* ]]
    [[ "$output" != *"1234567890abcdefghijk"* ]]
}

@test "shape: AWS AKIA access-key id redacted (R18-S3)" {
    lib
    run _os_redact_shapes 'key=AKIAIOSFODNN7EXAMPLE rest'
    [ "$status" -eq 0 ]
    [[ "$output" != *"AKIAIOSFODNN7EXAMPLE"* ]]
    [[ "$output" == *"[REDACTED]"* ]]
}

@test "shape: JWT eyJ blob redacted (R18-S4)" {
    lib
    run _os_redact_shapes 'token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U rest'
    [ "$status" -eq 0 ]
    [[ "$output" != *"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"* ]]
    [[ "$output" == *"[REDACTED]"* ]]
}

@test "shape: PEM private-key banner collapses whole line (R18-S5)" {
    lib
    run _os_redact_shapes '-----BEGIN RSA PRIVATE KEY----- MIIEow...'
    [ "$status" -eq 0 ]
    [ "$output" = "[REDACTED]" ]
}

@test "shape: JSON credential pair redacted (R18-S6)" {
    lib
    run _os_redact_shapes '{"api_key":"sk-1234567890abcdef"}'
    [ "$status" -eq 0 ]
    [[ "$output" == *'"api_key":"[REDACTED]"'* ]]
    [[ "$output" != *"sk-1234567890abcdef"* ]]
}

@test "shape: value-shape pass fires through _os_redact e2e (R18-S7)" {
    lib
    run _os_redact 'loaded token AKIAIOSFODNN7EXAMPLE into cfg'
    [ "$status" -eq 0 ]
    [[ "$output" != *"AKIAIOSFODNN7EXAMPLE"* ]]
    [[ "$output" == *"[REDACTED]"* ]]
}

@test "redaction non-empty _OS_ENV failure warns once, scrub off (D3)" {
    _OS_ENV=/nonexistent/env
    lib
    local e1="$BATS_TEST_TMPDIR/e1" e2="$BATS_TEST_TMPDIR/e2"
    local o1="$BATS_TEST_TMPDIR/o1" o2="$BATS_TEST_TMPDIR/o2"
    _os_redact 'K=V' >"$o1" 2>"$e1"
    _os_redact 'K=V' >"$o2" 2>"$e2"
    rg -q 'osdetect: caller-supplied _OS_ENV|environment value-scrub is OFF' "$e1" || return 1
    if rg -q 'osdetect: caller-supplied _OS_ENV' "$e2"; then return 1; fi
}

@test "container: rootless /run/user/<uid>/.containerenv maps to containers (R18-C5)" {
    _OS_ROOT="$BATS_TEST_TMPDIR/c"
    mkdir -p "$_OS_ROOT/run/user/1000"
    : > "$_OS_ROOT/run/user/1000/.containerenv"
    mkdir -p "$_OS_ROOT/etc"
    printf '%s\n' 'ID=debian' 'VERSION_ID="12"' > "$_OS_ROOT/etc/os-release"
    lib
    detect_os
    [ "$OS_CONTAINER" = "containers" ]
}

#!/usr/bin/env bats
# SC1091: `$BATS_TEST_DIRNAME/../fx-detect-os.sh` is a runtime-variable path.
# shellcheck disable=SC1091
# SC2317: bats runs @test functions indirectly, so every block looks
# "unreachable" to shellcheck.
# SC2016: the metacharacter payloads in the hostile-marker test are purposefully
# literal — they must reach the fixture and the library unexpanded, which is
# the whole point of the assertion.
# shellcheck disable=SC2317,SC2016
#
# Legacy-ladder coverage against a REAL root filesystem.
#
# Every distro image in the CI matrix ships a conforming /etc/os-release, so
# detect_os always resolves at ladder step 1 and the named legacy branches
# never execute there. This file is run by the `legacy` CI job, which deletes
# /etc/os-release, /usr/lib/os-release, /etc/debian_version and
# /etc/lsb-release first, so the ladder is forced down the file-based steps.
#
# What this buys over the _OS_ROOT fixture tests in detect_os.bats: the branches
# run against a real filesystem with real stat/wc, real ownership and real
# permissions, and with the library's own path resolution — no fake root, no
# per-test fixture. debian_version is removed too because it is checked FIRST
# among the legacy markers and would otherwise short-circuit every test here.
#
# Each test restores /etc afterwards so ordering cannot matter.

setup() {
    LIB="$BATS_TEST_DIRNAME/../fx-detect-os.sh"
    MARKER=""
}

# plant a legacy marker file and detect
detect_with() {
    MARKER="$1"
    shift
    printf '%s\n' "$1" > "$MARKER"
    run bash -c '
        . "$1"
        detect_os
        printf "id=%s trust=%s source=%s version=%s\n" \
            "$OS_ID" "$OS_TRUST_LEVEL" "$OS_SOURCE" "$OS_VERSION_ID"
    ' dummy "$LIB"
    rm -f "$MARKER"
}

@test "legacy ladder: centos-release resolves to centos at medium trust" {
    detect_with /etc/centos-release 'CentOS release 7.9.2009 (Core)'
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=centos"* ]]
    [[ "$output" == *"trust=medium"* ]]
    [[ "$output" == *"source=/etc/centos-release"* ]]
    [[ "$output" == *"version=7.9"* ]]
}

@test "legacy ladder: SuSE-release resolves a fixed openSUSE release" {
    detect_with /etc/SuSE-release 'openSUSE Leap 15.5'
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=opensuse-leap"* ]]
    [[ "$output" == *"trust=medium"* ]]
    [[ "$output" == *"source=/etc/SuSE-release"* ]]
}

@test "legacy ladder: lowercase suse-release is also probed" {
    detect_with /etc/suse-release 'openSUSE Leap 15.5'
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=opensuse-leap"* ]]
    [[ "$output" == *"source=/etc/suse-release"* ]]
}

@test "legacy ladder: tumbleweed wins over its opensuse substring" {
    detect_with /etc/SuSE-release 'openSUSE Tumbleweed'
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=opensuse-tumbleweed"* ]]
}

@test "legacy ladder: arch-release (empty marker) resolves to arch" {
    detect_with /etc/arch-release ''
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=arch"* ]]
    [[ "$output" == *"trust=medium"* ]]
}

@test "legacy ladder: alpine-release resolves to alpine" {
    detect_with /etc/alpine-release '3.21.0'
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=alpine"* ]]
    [[ "$output" == *"source=/etc/alpine-release"* ]]
}

@test "legacy ladder: gentoo-release resolves to gentoo" {
    detect_with /etc/gentoo-release 'Gentoo Base System 2.14'
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=gentoo"* ]]
    [[ "$output" == *"source=/etc/gentoo-release"* ]]
}

@test "legacy ladder: oracle-release beats a RHEL-compatible redhat-release" {
    # Order matters: oracle-release is checked BEFORE the fedora-family loop, or
    # a host shipping both would be mislabelled rhel.
    printf '%s\n' 'Oracle Linux Server release 9.4' > /etc/oracle-release
    printf '%s\n' 'Red Hat Enterprise Linux release 9.4 (Plow)' > /etc/redhat-release
    run bash -c '
        . "$1"
        detect_os
        printf "id=%s trust=%s source=%s\n" "$OS_ID" "$OS_TRUST_LEVEL" "$OS_SOURCE"
    ' dummy "$LIB"
    rm -f /etc/oracle-release /etc/redhat-release
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=ol"* ]]
    [[ "$output" == *"source=/etc/oracle-release"* ]]
}

@test "legacy ladder: system-release resolves Amazon Linux" {
    detect_with /etc/system-release 'Amazon Linux release 2023 (Amazon Linux)'
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=amzn"* ]]
    [[ "$output" == *"source=/etc/system-release"* ]]
}

@test "legacy ladder: an unknown *-release file falls to the catch-all at low trust" {
    # The catch-all is the only branch that yields OS_TRUST_LEVEL=low from a
    # file (the other low case is the uname last resort). The id is the basename
    # minus the suffix.
    detect_with /etc/nobara-release 'Nobara 41'
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=nobara"* ]]
    [[ "$output" == *"trust=low"* ]]
}

@test "legacy ladder: with no marker at all, detection falls to the uname last resort" {
    # Nothing left for any step to claim: OS_ID=linux at low trust, never a
    # fabricated identity, and never an empty-string failure masquerading as one.
    run bash -c '
        . "$1"
        detect_os
        printf "id=%s trust=%s source=%s detected=%s\n" \
            "$OS_ID" "$OS_TRUST_LEVEL" "$OS_SOURCE" "$OS_DETECTED"
    ' dummy "$LIB"
    [ "$status" -eq 0 ]
    [[ "$output" == *"id=linux"* ]]
    [[ "$output" == *"trust=low"* ]]
    [[ "$output" == *"source=uname"* ]]
    [[ "$output" == *"detected=1"* ]]
}

@test "legacy ladder: a hostile marker cannot smuggle shell metacharacters out" {
    # The sanitizer is the whole point of the display fields: a value carrying
    # command substitution, a semicolon and a backtick must not survive.
    printf '%s\n' 'Distro $(id) `id`;rm -rf /' > /etc/evil-release
    run bash -c '
        . "$1"
        detect_os
        printf "id=%s distro=[%s]\n" "$OS_ID" "$OS_DISTRO"
    ' dummy "$LIB"
    rm -f /etc/evil-release
    [ "$status" -eq 0 ]
    [[ "$output" != *'$('* ]]
    [[ "$output" != *'`'*  ]]
    [[ "$output" != *';'*   ]]
}

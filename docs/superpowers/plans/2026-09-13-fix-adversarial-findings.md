# Plan — Fix adversarial-review findings in fx-detect-os.sh

Status: EXECUTED (all tasks complete, 35/35 bats green, bash -n + shellcheck clean)
Date: 2026-09-14. No git (approved: "no git for now"). Plan location approved.

## Decisions (user-approved)
- M4 runc: doc-fix => README/code-comment now say runc -> `oci` (container kept).
- O1 timeout: `timeout 5` wrapper with graceful degradation + error handling
  (killed run rc 124 == unavailable; absent timeout == unbounded legacy; missing
  coreutils never aborts, never stalls).
- O2 PATH: capture `uname|mktemp|lsb_release|timeout` once at source time.
- O3 reset: /usr/lib takeover resets partial /etc identity fields (no mixing),
  detection still correct (fedora case verified).
- 5) no git. 6) plan saved here.

## Findings addressed
- H1 Rolling opensuse-tumbleweed: `OS_VERSION_ID` now empty (build-date "20230913"
  no longer treated as a version).
- H2 Redaction: wordlist matched case-insensitively; values <4 chars never
  replaced (short common tokens can no longer corrupt log lines).
- M1 Predictable `/tmp/osdetect.$$.log`: random `mktemp` name by default,
  PID-name only as last resort; symlink planting verified rendered ineffective.
- M2 Catch-all glob: quoted array iteration, space-safe, `-f` rejects dirs.
- M3 `readonly _OS_VERSION`: caller-owned name respected (no source-time abort
  under `set -euo pipefail`).
- M4 runc doc/contract aligned (runc -> oci, locking test added).
- M5 `os_container()`: empty before detection (README-consistent).
- O1 lsb_release: wrapped in `timeout(1) 5`; absent timeout / rc 124 handled.
- O2 External commands pinned at source via readonly `_OS_UNAME/_OS_MKTEMP/
  _OS_LSBRELEASE/_OS_TIMEOUT`.
- O3 os-release field mixing killed (`_os_parse_os_release_file "$f_u" reset`).
- O4 debian_version `bookworm`/`sid` => empty `OS_VERSION_ID` (numeric-token rule).
- O5 Directory-as-release-target rejected (`-f`, not `-e`).

## Verification
- `bats test/detect_os.bats` -> 35/35 ok (was 21/21). New tests cover: redaction
  upper/short, Tumbleweed rolling, spaced root, readonly collision, os_container
  pre-detection, runc->oci, mktemp default + planted-path, timeout wiring/124/
  unbounded, no-mixing takeover, debian codename.
- `bash -n fx-detect-os.sh` -> OK.
- `shellcheck -S style -x fx-detect-os.sh test/detect_os.bats` -> clean.
- Live host detection: `detected=1 id=cachyos distro=CachyOS arch=x86_64
  container=none source=/etc/os-release kernel=Linux`, debug log at a mktemp path.
- Version bumped 1.0.0 -> 1.1.0 (direct-exec banner prints `$_OS_VERSION`).

## Notes
- bats `setup()` gains a `timeout(){ shift; "$@"; }` shim alongside the existing
  `lsb_release(){ return 1; }` shim: external coreutils `timeout` cannot invoke
  bash-function stubs, so all fixtures stay in a pure-function world.
- Tests 32/35 pin PATH BEFORE sourcing now, the new capture-at-source contract.
- `_os_log_raw`/`_os_log` append to `${_os_log_file:-/dev/null}`: the mktemp
  discovery logs generated before the final path is chosen are dropped, never
  error.
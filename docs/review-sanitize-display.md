# Review brief: `_os_sanitize_display`

Requested review target: `_os_sanitize_display` in `fx-detect-os.sh`, and the
`_os_byte_table` helper it depends on. This function carries the library's
terminal-injection and invisible-character defences, and it was rewritten late
in a hardening pass. It is the change most in need of a second pair of eyes.

## 1. Contract

From the function's own header comment:

> allowlist-scrubs a human display field (PRETTY_NAME/NAME/VERSION/
> CODENAME/ID_LIKE). ASCII bytes outside the printable-safe set are removed
> outright; high bytes pass only as part of a well-formed UTF-8 multibyte
> sequence so terminal display keeps its fidelity. C1 control characters
> (U+0080-009F), overlong encodings, invalid or truncated sequences, surrogates,
> noncharacters, and the invisible format controls (zero-width U+200B-200F, bidi
> U+202A-202E, interlinear annotation U+2066-206F) are dropped, as are any
> codepoints past U+10FFFF. Leading/trailing whitespace is trimmed. The kept set
> is [A-Za-z0-9] plus space and `. _ : / , + = ( ) @ % ^`.

The kept set is the security-relevant part. Every quote, backslash, backtick,
glob and brace metacharacter, `;`, `$`, all C0 controls and DEL sit **outside**
it, so a hostile `/etc/os-release` cannot smuggle a terminal escape, a
bidi-reordering payload, a shell metacharacter, a glob pattern, or an
unquoted-`for`-loop word into a caller that interpolates the field.

## 2. Threat model

The input is the contents of a release file. The realistic attacker is anyone
who can write `/etc/os-release` (already root) or who controls a
`/etc/*-release` file, a container image's baked-in os-release, or a build
environment. `_OS_ROOT` lets callers point the library at an untrusted tree.

The consequence of a bug here is not a crash. It is that a value like
`$'\e[2J'` or `$'\xe2\x80\xae'` reaches a caller's terminal or an unquoted shell
word. So the bar is *fail-closed*: anything not provably safe is dropped.

Two consequences worth stating explicitly:

- Dropping too much is a **fidelity** bug, not a security bug. It is still
  worth fixing, but it is not urgent.
- Passing something through is a **security** bug. Always.

## 3. What changed, and why

Three rewrites, in order:

1. **Per-byte subshell → `printf -v`.** The old code computed each byte's value
   with `code="$(printf '%d' "'$c")"`, forking a subshell per byte. That made
   sanitizing a field quadratic in wall time: a 40KB field cost ~5.5s, and a
   200KB one — *under* `_os_file_ok`'s own 262144-byte cap — hung `detect_os`
   past 120s, defeating the cap's stated purpose.

2. **Whole-string walk → chunked walk.** bash's `${var:off:len}` is
   O(length-of-var), so indexing a 256KB value once per byte was the dominant
   cost. The walk now takes a 4096-byte chunk with one substring operation and
   indexes within that (small) chunk, making the pass linear.

3. **`printf '%d' "'$c"` → a 255-byte lookup table.** This is the change most
   likely to be wrong, and it exists because of a real bug: on **musl**, the
   `C` locale is UTF-8 capable, so bash resolves the character to a *wide*
   value. Byte `0xE2` came back as **57314** instead of 226, so every multibyte
   lead byte missed its range test and **all non-ASCII was silently stripped on
   Alpine**. The replacement builds `_os_byte_tbl` (bytes 1..255) from explicit
   `\xHH` escapes via `printf %b`; a byte's value is the length of the table
   prefix before its first occurrence, plus 1.

## 4. Invariants a reviewer should confirm

- **I1.** Every byte of the input is either emitted exactly once, in order, or
  dropped. No duplication, no reordering, no loss beyond a deliberate drop.
- **I2.** A byte's computed value is always in 1..255. (Byte 0 cannot appear;
  bash strings are NUL-terminated.)
- **I3.** The value is computed the same way on glibc and musl. The old idiom
  did not, which is the whole reason the table exists.
- **I4.** A multi-byte sequence is emitted only if **all** its bytes are present
  and valid, and its codepoint passes every rejection test.
- **I5.** A sequence split across a chunk boundary is handled exactly as if the
  string had been walked in one pass.
- **I6.** The allowlist is unchanged from the pre-rewrite version. This is the
  single most security-critical line in the function and the rewrite should not
  have moved it.
- **I7.** No fork, no external command, no `$( )` in the per-byte path.
- **I8.** The `bash 4.0` floor holds: no negative substring offsets, no
  `declare -n`, nothing newer than bash 4.0.

## 5. Specific questions

1. **Is the boundary realignment provably correct?** The scan-back walks back at
   most 3 bytes looking for a lead byte in `0xC2..0xF4`, then borrows exactly
   `want - have` bytes. An earlier, simpler rule ("keep borrowing while the last
   byte is a continuation byte") both over-borrowed past a complete sequence and
   under-borrowed after a lead byte, and silently dropped any character
   straddling the cut. Is the current rule correct for 2-, 3- and 4-byte
   sequences, and for a truncated sequence at end-of-input?

2. **Can `out` desynchronise from `piece`?** The loop is `while [ -n "$rest" ]`
   with the inner `for (( i = 0; i < ${#piece}; i++ ))`. Is there any input for
   which the outer and inner loops disagree about position?

3. **Is the table lookup provably in range?** `${_os_byte_tbl%%"$c"*}` yields a
   prefix; `${#prefix}` under `LC_ALL=C`. Both were verified to count *bytes* on
   glibc and musl. Is there any input where the prefix is the whole table (byte
   absent from it) and the computed value silently exceeds 255?

4. **What happens for an unpaired continuation byte at a chunk boundary?** The
   scan-back requires a lead byte; a piece that *starts* with a continuation byte
   (0x80-0xBF) is not preceded by anything in that piece. Is it handled, and
   does handling it differ from the single-pass case?

5. **Does the drop of the `cp -gt 1114111` branch change anything?** Mutation
   testing suggests that check may be unreachable, because valid lead bytes
   `F0..F4` cannot encode a codepoint above U+10FFFF. If so, is it dead code
   that should be removed, or defensive depth worth keeping?

6. **Is the trim correct for an all-whitespace or all-dropped input?** The trim
   is two `${var#...}` / `${var%...}` expansions after the walk.

7. **Anything in `_os_json_escape` that should have been changed too?** It had the
   same per-byte `printf '%d' "'$c"` idiom and was switched to the same table.
   Its only consumer is the NDJSON failure log, and it only cares about values
   below 32, which the old idiom got right even on musl. Was changing it
   necessary, and is it correct?

## 6. What has already been verified, and how

So the reviewer can spend effort on what is *not* covered:

- The full 172-test suite passes on glibc, musl (Alpine 3.21) and on a host
  with neither glibc nor `sed`/`awk` (NixOS).
- All three fuzz suites pass on glibc and musl.
- 21 targeted mutation tests (see `test/mutants.txt`) are all caught, including
  widening the allowlist with `"`, `;` and `$`, and dropping each of the C1,
  overlong, surrogate and noncharacter rejections individually.
- 20 further cases: a multibyte character straddling the chunk cut is
  byte-exact across 4 characters x 5 offsets; the hostile-marker test confirms
  `$(`, backtick and `;` cannot escape.
- ShellCheck 0.11.0 at full default severity reports nothing.

The mutation coverage in this area is the reason I am less worried about
*silent* regressions here than about a *design* flaw the tests cannot see — a
case the tests assert the wrong thing about, or an input class nobody thought to
try. Question 4 is the one I would most want a second opinion on.

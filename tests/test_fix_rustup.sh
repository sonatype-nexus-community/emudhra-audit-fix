#!/usr/bin/env bash
#
# Tests `emudhra-audit-fix.sh --fix --only=rustup` with a stub `rustup` binary: no network, no real rustup, throwaway HOME.
#
#   1. official     - rustup-init install in ~/.cargo/bin: `self update` runs, version re-read and reported (version check, not TLS)
#   2. decline      - answering n changes nothing
#   3. dry run      - prints the command, changes nothing
#   4. homebrew     - never given `self update`; the brew command is printed
#   5. CARGO_HOME   - an override is honoured when locating the binary
#   6. failed update - update that does nothing leaves the working binary and counts as failed
#   7. broken update - update that breaks the binary is rolled back
# Needs: python3 (for a pseudo-terminal).

HERE=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="$HERE/emudhra-audit-fix.sh"
command -v python3 >/dev/null 2>&1 || { echo "python3 is required"; exit 2; }
W=$(mktemp -d "${TMPDIR:-/tmp}/emudhra-rustup.XXXXXX") || exit 2
trap 'rm -rf "$W"' EXIT
fails=0
check() { if [ "$2" -eq 0 ]; then echo "  ok   $1"; else echo "  FAIL $1"; fails=$((fails + 1)); [ -n "${DEBUG_FAILS:-}" ] && printf '%s\n' "$out" | sed 's/^/        | /'; fi; }
yes_if() { if "$@"; then echo 0; else echo 1; fi; }

# new_env LAYOUT UPDATE : LAYOUT official|brew|cargohome ; UPDATE ok|nothing|break
new_env() {
  rm -rf "$W/home"; H="$W/home"
  CH=
  case $1 in
    official)   UVBIN="$H/.cargo/bin/rustup" ;;
    brew)       UVBIN="$H/opt/homebrew/Cellar/rustup/1.28.0/bin/rustup" ;;
    cargohome)  CH="$H/custom-cargo"; UVBIN="$CH/bin/rustup" ;;
  esac
  mkdir -p "$(dirname "$UVBIN")"; echo 1.28.0 > "$W/ver"; : > "$W/calls"
  cat > "$UVBIN" <<EOS
#!/bin/sh
case "\$1" in
  --version) [ -f "$W/broken" ] && exit 1; echo "rustup \$(cat "$W/ver") (abc123 2026-01-01)" ;;
  self) echo "self \$*" >> "$W/calls"
        case "$2" in nothing) ;; break) touch "$W/broken" ;; *) echo 1.29.2 > "$W/ver" ;; esac ;;
esac
EOS
  chmod +x "$UVBIN"; rm -f "$W/broken"
}

run_pty() {  # ANSWER [ARGS...]
  CH="$CH" python3 -I - "$SCRIPT" "$H" "$UVBIN" "$@" <<'PY'
import os, pty, re, select, sys, time
script, home, uvbin, answer, extra = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]
ch = os.environ.get("CH", "")
pid, fd = pty.fork()
if pid == 0:
    env = dict(os.environ, HOME=home, **({"CARGO_HOME": ch} if ch else {}), EMUDHRA_AUDIT_ONLY="rustup",
               PATH=os.path.dirname(uvbin) + ":/usr/bin:/bin")
    os.execve("/bin/bash", ["/bin/bash", script, "--fix", "--only=rustup"] + extra, env)
out = b""; sent = 0; deadline = time.time() + 120
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 0.05)
    if fd in r:
        try: chunk = os.read(fd, 4096)
        except OSError: break
        if not chunk: break
        out += chunk
        if out.count(b"[y/N]") > sent:
            os.write(fd, answer.encode() + b"\n"); sent += 1
    else:
        try:
            if os.waitpid(pid, os.WNOHANG)[0]: break
        except ChildProcessError: break
print(re.sub(rb"\x1b\[[0-9;]*m", b"", out).decode("utf-8", "replace"))
PY
}
run_plain() {
  env HOME="$H" ${CH:+CARGO_HOME="$CH"} PATH="$(dirname "$UVBIN"):/usr/bin:/bin" EMUDHRA_AUDIT_ONLY=rustup /bin/bash "$SCRIPT" --fix --only=rustup "$@" </dev/null 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
}
calls() { cat "$W/calls"; }

echo "1. official install, answer y"
new_env official ok; out=$(run_pty y)
check "ran self update" $(yes_if grep -q 'self update' <<<"$(calls)")
check "reports the new version" $(yes_if grep -q 'now reports 1.29.2' <<<"$out")
check "says version check, not TLS probe" $(yes_if grep -q 'not a TLS probe' <<<"$out")
check "points at Cargo.lock / webpki" $(yes_if grep -q 'rustls-webpki' <<<"$out")
check "Changed: 1" $(yes_if grep -q 'Changed: 1 ' <<<"$out")

echo "2. decline"
new_env official ok; out=$(run_pty n)
check "no self update" $(yes_if test -z "$(calls)")
check "Changed: 0" $(yes_if grep -q 'Changed: 0 ' <<<"$out")

echo "3. dry run"
new_env official ok; out=$(run_plain --dry-run)
check "prints the command" $(yes_if grep -q 'self update' <<<"$out")
check "changed nothing" $(yes_if test -z "$(calls)")
check "version unchanged" $(yes_if test "$(cat "$W/ver")" = 1.28.0)

echo "4. Homebrew install"
new_env brew ok; out=$(run_plain --yes)
check "never ran self update" $(yes_if test -z "$(calls)")
check "printed brew upgrade rustup" $(yes_if grep -q 'brew upgrade rustup' <<<"$out")

echo "5. CARGO_HOME override"
new_env cargohome ok; out=$(run_plain --yes)
check "ran self update on the overridden location" $(yes_if grep -q 'self update' <<<"$(calls)")
check "reports the new version" $(yes_if grep -q 'now reports 1.29.2' <<<"$out")

echo "6. update that does nothing"
new_env official nothing
out=$(run_pty y)
check "reported failure" $(yes_if grep -q 'still behind' <<<"$out")
check "counted as failed" $(yes_if grep -q 'Failed or refused: 1' <<<"$out")
check "binary still works" $(yes_if test "$("$UVBIN" --version)" = "rustup 1.28.0 (abc123 2026-01-01)")

echo "7. update that breaks the binary"
new_env official break
out=$(run_pty y)
check "rolled back" $(yes_if grep -q 'restoring the previous binary' <<<"$out")
check "counted as failed" $(yes_if grep -q 'Failed or refused: 1' <<<"$out")

echo
[ "$fails" -eq 0 ] && echo "all passed" || { echo "$fails failed"; exit 1; }

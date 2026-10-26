#!/usr/bin/env bash
#
# Tests `../emudhra-audit-fix.sh --fix --only=uv` with a stub `uv` binary: no network, no real uv, throwaway HOME.
#
#   1. standalone   - receipt present: `self update` runs, version re-read and reported (version check, not TLS)
#   2. decline      - answering n changes nothing
#   3. dry run      - prints the command, changes nothing
#   4. homebrew     - never given `self update`; the brew command is printed
#   5. pipx         - never given `self update`; the pipx command is printed
#   6. failed update - update that does nothing leaves the working binary and counts as failed
#   7. broken update - update that breaks the binary is rolled back
# Needs: python3 (for a pseudo-terminal).

HERE=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="$HERE/../emudhra-audit-fix.sh"
command -v python3 >/dev/null 2>&1 || { echo "python3 is required"; exit 2; }
W=$(mktemp -d "${TMPDIR:-/tmp}/emudhra-uv.XXXXXX") || exit 2
trap 'rm -rf "$W"' EXIT
fails=0
check() { if [ "$2" -eq 0 ]; then echo "  ok   $1"; else echo "  FAIL $1"; fails=$((fails + 1)); [ -n "${DEBUG_FAILS:-}" ] && printf '%s\n' "$out" | sed 's/^/        | /'; fi; }
yes_if() { if "$@"; then echo 0; else echo 1; fi; }

# new_env LAYOUT UPDATE : LAYOUT standalone|brew|pipx ; UPDATE ok|nothing|break
new_env() {
  rm -rf "$W/home"; H="$W/home"
  case $1 in
    standalone) UVBIN="$H/.local/bin/uv"; mkdir -p "$H/.config/uv"
                printf '{"binaries":["uv"],"install_prefix":"%s"}\n' "$H/.local/bin" > "$H/.config/uv/uv-receipt.json" ;;
    brew)       UVBIN="$H/opt/homebrew/Cellar/uv/0.9.0/bin/uv" ;;
    pipx)       UVBIN="$H/.local/pipx/venvs/uv/bin/uv" ;;
  esac
  mkdir -p "$(dirname "$UVBIN")"; echo 0.9.0 > "$W/ver"; : > "$W/calls"
  cat > "$UVBIN" <<EOS
#!/bin/sh
case "\$1" in
  --version) [ -f "$W/broken" ] && exit 1; echo "uv \$(cat "$W/ver")" ;;
  self) echo "self \$*" >> "$W/calls"
        case "$2" in nothing) ;; break) touch "$W/broken" ;; *) echo 0.13.4 > "$W/ver" ;; esac ;;
esac
EOS
  chmod +x "$UVBIN"; rm -f "$W/broken"
}

run_pty() {  # ANSWER [ARGS...]
  python3 -I - "$SCRIPT" "$H" "$UVBIN" "$@" <<'PY'
import os, pty, re, select, sys, time
script, home, uvbin, answer, extra = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]
pid, fd = pty.fork()
if pid == 0:
    env = dict(os.environ, HOME=home, XDG_CONFIG_HOME=home + "/.config", EMUDHRA_AUDIT_ONLY="uv",
               PATH=os.path.dirname(uvbin) + ":" + os.environ["PATH"])
    os.execve("/bin/bash", ["/bin/bash", script, "--fix", "--only=uv"] + extra, env)
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
  HOME="$H" XDG_CONFIG_HOME="$H/.config" PATH="$(dirname "$UVBIN"):$PATH" EMUDHRA_AUDIT_ONLY=uv /bin/bash "$SCRIPT" --fix --only=uv "$@" </dev/null 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
}
calls() { cat "$W/calls"; }

echo "1. standalone install, answer y"
new_env standalone ok; out=$(run_pty y)
check "ran self update" $(yes_if grep -q 'self update' <<<"$(calls)")
check "reports the new version" $(yes_if grep -q 'now reports 0.13.4' <<<"$out")
check "says version check, not TLS probe" $(yes_if grep -q 'not a TLS probe' <<<"$out")
check "mentions Python/tools not upgraded" $(yes_if grep -q 'Python versions and tools' <<<"$out")
check "Changed: 1" $(yes_if grep -q 'Changed: 1 ' <<<"$out")

echo "2. decline"
new_env standalone ok; out=$(run_pty n)
check "no self update" $(yes_if test -z "$(calls)")
check "Changed: 0" $(yes_if grep -q 'Changed: 0 ' <<<"$out")

echo "3. dry run"
new_env standalone ok; out=$(run_plain --dry-run)
check "prints the command" $(yes_if grep -q 'self update' <<<"$out")
check "changed nothing" $(yes_if test -z "$(calls)")
check "version unchanged" $(yes_if test "$(cat "$W/ver")" = 0.9.0)

echo "4. Homebrew install"
new_env brew ok; out=$(run_plain --yes)
check "never ran self update" $(yes_if test -z "$(calls)")
check "printed brew upgrade uv" $(yes_if grep -q 'brew upgrade uv' <<<"$out")

echo "5. pipx install"
new_env pipx ok; out=$(run_plain --yes)
check "never ran self update" $(yes_if test -z "$(calls)")
check "printed pipx upgrade uv" $(yes_if grep -q 'pipx upgrade uv' <<<"$out")

echo "6. update that does nothing"
new_env standalone nothing
out=$(run_pty y)
check "reported failure" $(yes_if grep -q 'still behind' <<<"$out")
check "counted as failed" $(yes_if grep -q 'Failed or refused: 1' <<<"$out")
check "binary still works" $(yes_if test "$("$UVBIN" --version)" = "uv 0.9.0")

echo "7. update that breaks the binary"
new_env standalone break
out=$(run_pty y)
check "rolled back" $(yes_if grep -q 'restoring the previous binary' <<<"$out")
check "counted as failed" $(yes_if grep -q 'Failed or refused: 1' <<<"$out")

echo
[ "$fails" -eq 0 ] && echo "all passed" || { echo "$fails failed"; exit 1; }

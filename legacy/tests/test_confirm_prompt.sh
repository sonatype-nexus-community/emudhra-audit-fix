#!/usr/bin/env bash
#
# Regression test for the --fix confirmation prompt.
#
# History: the fix loop read its plan from a here-document, which replaced stdin, so confirm() saw "no terminal"
# and skipped every change even on a real terminal. Every earlier test used --yes or had no terminal, so nothing
# noticed. This test runs the script under a real pseudo-terminal and checks that:
#   1. the prompt IS shown (not "no terminal to ask on"),
#   2. answering "n" applies nothing,
#   3. with no terminal at all, and no --yes, nothing is applied either.
#
# It never answers "y", so it cannot change anything real. To work on any machine (including one whose JDKs are
# already fixed) it builds a throwaway JDK in a temp directory whose cacerts still contains the roots, and points
# the script at it with EMUDHRA_JAVA_HOMES. Needs: python3, a JDK with keytool, and a pristine cacerts source.

HERE=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="$HERE/../emudhra-audit-fix.sh"
ONLY=java      # the throwaway JDK exercises the java fix, which is the one with per-item prompts

command -v python3 >/dev/null 2>&1 || { echo "python3 is required"; exit 2; }

W=$(mktemp -d "${TMPDIR:-/tmp}/emudhra-confirm.XXXXXX") || exit 2
trap 'chmod -R u+w "$W" 2>/dev/null; rm -rf "$W"' EXIT

# Find a JDK to copy: JAVA_HOME, then java on PATH.
SRC=${JAVA_HOME:-}
[ -z "$SRC" ] && command -v java >/dev/null 2>&1 && SRC=$(dirname "$(dirname "$(python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$(command -v java)")")")
[ -x "$SRC/bin/keytool" ] || { echo "need a JDK with keytool (set JAVA_HOME)"; exit 2; }

# Copy the whole JDK: the java launcher resolves its runtime relative to the install directory, and a partial
# copy (bin/ and lib/ only) did not run as a JDK the script would plan a fix for.
SRC=$(python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$SRC")   # follow SDKMAN-style "current" symlinks
cp -R "$SRC" "$W/jdk" 2>/dev/null || { echo "could not copy $SRC"; exit 2; }
CAC="$W/jdk/lib/security/cacerts"

# Make sure the throwaway store still HAS the roots: if this JDK was already fixed, restore the oldest backup.
roots_in() { "$SRC/bin/keytool" -J-Duser.language=en -list -v -keystore "$1" -storepass changeit 2>/dev/null | grep -c -E '^Owner:.*(AAA Certificate Services|emSign ECC Root CA - G3)'; }
if [ "$(roots_in "$CAC")" -eq 0 ]; then
  bak=$(ls -1 "$SRC"/lib/security/cacerts.pre-emudhra-* 2>/dev/null | head -1)
  [ -n "$bak" ] && cp "$bak" "$CAC"
fi
[ "$(roots_in "$CAC")" -gt 0 ] || { echo "cannot build an unpatched cacerts from $SRC; nothing to test"; exit 2; }
export EMUDHRA_JAVA_HOMES="$W/jdk"

fails=0
check() { if [ "$2" -eq 0 ]; then echo "  ok   $1"; else echo "  FAIL $1"; fails=$((fails + 1)); fi; }

run_pty() {  # ANSWERS : run under a pty, feeding ANSWERS (one per line) to the prompts
  python3 -I - "$SCRIPT" "$ONLY" "$1" <<'PY'
import os, pty, re, sys, select, time
script, only, answers = sys.argv[1], sys.argv[2], sys.argv[3].encode().decode("unicode_escape").encode()
pid, fd = pty.fork()
if pid == 0:
    os.execv("/bin/bash", ["/bin/bash", script, "--fix", "--only=" + only])
out = b""
sent = 0
deadline = time.time() + 600
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 1)
    if fd in r:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
        # answer each prompt as it appears
        while out.count(b"[y/N]") > sent and sent * 2 < len(answers) + 1:
            os.write(fd, answers[sent * 2:sent * 2 + 2] or b"n\n")
            sent += 1
    else:
        try:
            if os.waitpid(pid, os.WNOHANG)[0]:
                break
        except ChildProcessError:
            break
text = re.sub(rb"\x1b\[[0-9;]*m", b"", out).decode("utf-8", "replace")
print(text)
PY
}

run_detached() {  # run with no controlling terminal and no --yes
  python3 -I - "$SCRIPT" "$ONLY" <<'PY'
import os, re, subprocess, sys
os.setsid()
r = subprocess.run(["/bin/bash", sys.argv[1], "--fix", "--only=" + sys.argv[2]], stdin=subprocess.DEVNULL,
                   capture_output=True, text=True)
print(re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr))
PY
}

echo "1. terminal present, every prompt answered n  (throwaway JDK, --only=$ONLY)"
out=$(run_pty 'n\nn\nn\nn\nn\nn\nn\nn\nn\nn\n')
prompts=$(printf '%s\n' "$out" | grep -c '\[y/N\]')
# "Nothing to fix" / "Nothing matched" means no fix is planned here, so there is nothing to test. But a
# plan that exists and never prompts is exactly the bug this test guards against, so that must FAIL.
if printf '%s' "$out" | grep -q 'Nothing to fix\|Nothing matched'; then
  echo "  (no fix is planned for --only=$ONLY on this machine; try another kind)"; exit 0
fi
planned=$(printf '%s\n' "$out" | grep -c -E '^  (Java cacerts|Homebrew ca-certificates|macOS built-in pip|System trust store)')
check "a fix was planned ($planned item(s)) - otherwise this test proves nothing" $([ "$planned" -ge 1 ] && echo 0 || echo 1)
check "the prompt was shown ($prompts time(s))" $([ "$prompts" -ge 1 ] && echo 0 || echo 1)
check "no 'no terminal' message on a real terminal" $(printf '%s' "$out" | grep -q 'no terminal to ask on' && echo 1 || echo 0)
check "answering n changed nothing" $(printf '%s' "$out" | grep -q 'Changed: 0 ' && echo 0 || echo 1)

echo "2. no terminal and no --yes"
out=$(run_detached)
check "refuses with the 'no terminal' message" $(printf '%s' "$out" | grep -q 'no terminal to ask on' && echo 0 || echo 1)
check "changed nothing" $(printf '%s' "$out" | grep -q 'Changed: 0 ' && echo 0 || echo 1)

echo
if [ "$fails" -eq 0 ]; then echo "all checks passed"; exit 0; fi
echo "$fails check(s) FAILED"; exit 1

#!/usr/bin/env bash
#
# Tests `emudhra-audit-fix.sh --fix --only=node` (Node.js installed via nvm) without touching the network or
# any real nvm. It builds a throwaway NVM_DIR containing a stub nvm.sh and fake "node" binaries, and checks:
#
#   1. happy path     - installs the fixed version beside the old one, verifies it, switches the default
#   2. decline        - answering n at the install prompt changes nothing
#   3. default kept   - answering n at the default prompt installs but leaves the default alone
#   4. failed install - an install that does nothing leaves everything as it was and counts as failed
#   5. other default  - a default that is not the old version is left alone (no prompt)
#   6. no fix         - a major line with no published fix is refused, not guessed
#   7. not published  - a fixed release nvm does not offer yet is refused
#   8. dry run        - prints the commands and changes nothing
#   9. removal gate   - the old version is only removed after typing exactly "I AGREE"; "y", "yes", "i agree",
#                       empty input and --yes do not remove it; a default or aliased version is kept
#  19. active version - real nvm refuses to uninstall the currently-active version; the script must deactivate
#                       in its own subshell first, show nvm's message if it still fails, and never claim success
#
# The fake node answers --version and acts as the TLS probe target by printing "rejected" lines when it is the
# fixed version, "trusted" lines otherwise, so the post-install verification is exercised too.
# Needs: python3 (for a pseudo-terminal). Never touches the real ~/.nvm.

HERE=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="$HERE/emudhra-audit-fix.sh"
command -v python3 >/dev/null 2>&1 || { echo "python3 is required"; exit 2; }

W=$(mktemp -d "${TMPDIR:-/tmp}/emudhra-node.XXXXXX") || exit 2
trap 'chmod -R u+w "$W" 2>/dev/null; rm -rf "$W"' EXIT

fails=0
# On failure, show what the script printed in this scenario (set \$out) so the cause is visible, not just the symptom.
check() {
  if [ "$2" -eq 0 ]; then echo "  ok   $1"; return; fi
  echo "  FAIL $1"; fails=$((fails + 1))
  if [ -n "${DEBUG_FAILS:-}" ]; then
    printf '%s\n' "${out:-}" | sed -n '/Node.js (nvm)/,$p' | head -30 | sed 's/^/        | /'
    printf '        | nvm calls: %s\n' "$(calls | tr '\n' ';')"
  fi
}
yes_if() { if "$@"; then echo 0; else echo 1; fi; }

# make_fake_node DIR VERSION RESULT : a "node" that reports VERSION and mimics the TLS probe.
# The probe verdict (rejected|trusted) is read from a file beside the binary, so a stub nvm can choose it
# per install without rewriting the script text.
make_fake_node() {
  mkdir -p "$1/bin"
  printf '%s\n' "$3" > "$1/bin/verdict"
  printf '%s\n' "$2" > "$1/bin/version"
  cat > "$1/bin/node" <<'EOF'
#!/bin/sh
here=$(cd "$(dirname "$0")" && pwd)
case "$1" in
  --version) echo "v$(cat "$here/version")"; exit 0 ;;
  -e) exit 0 ;;
esac
# probe invocation: node probe.js CONTROL BAD1 BAD2  -> one "<result> <url>" per URL
shift
# the real probe prints "ok <url>" when the connection succeeded and "certerr <url>" on a certificate error
verdict=$(cat "$here/verdict")
[ "$verdict" = rejected ] && verdict=certerr
[ "$verdict" = trusted ] && verdict=ok
for u in "$@"; do
  case "$u" in
    *we-have-a-problem*) echo "$verdict $u" ;;
    *) echo "ok $u" ;;
  esac
done
EOF
  chmod +x "$1/bin/node"
}

# new_env OLD_VERSION : build a fake NVM_DIR in $W/nvm with the old version installed. Environment knobs:
#   FIXED_RESULT=rejected|trusted   what a newly installed node's probe reports
#   REMOTE=<ver>                    what `nvm version-remote <major>` returns
#   DEFAULT=<ver>                   what `nvm version default` returns
#   INSTALL=ok|nothing              whether `nvm install` actually installs
#   EXTRA="v24.10.0 ..."            additional older versions to install alongside
#   ALIASES="name:vX name2:vY"      aliases `nvm alias` should report (resolved targets)
#   UNINSTALL=ok|fail               whether `nvm uninstall` really removes the directory
#   ACTIVE=vX.Y.Z                   the version real nvm would consider active in the shell (it refuses to
#                                   uninstall that one until `nvm deactivate` has run); unset = nothing active
#   DEACTIVATE=works|broken         whether `nvm deactivate` clears the active version
new_env() {
  local old=$1 x
  NVM="$W/nvm"; rm -rf "$NVM"; mkdir -p "$NVM/versions/node"
  make_fake_node "$NVM/versions/node/v$old" "$old" trusted
  for x in ${EXTRA:-}; do make_fake_node "$NVM/versions/node/$x" "${x#v}" trusted; done
  cat > "$NVM/nvm.sh" <<EOF
# stub nvm: records calls in \$NVM_DIR/calls.log
nvm() {
  echo "nvm \$*" >> "\$NVM_DIR/calls.log"
  case "\$1" in
    version-remote) echo "v${REMOTE:-24.22.1}" ;;
    version)
      if [ "\$2" = default ]; then
        if [ -s "\$NVM_DIR/default.state" ]; then cat "\$NVM_DIR/default.state"; else echo "v${DEFAULT:-$old}"; fi
      fi ;;
    install)
      [ "${INSTALL:-ok}" = nothing ] && return 1
      v=\${2#v}
      d="\$NVM_DIR/versions/node/v\$v"
      mkdir -p "\$d/bin"
      cp "\$NVM_DIR/versions/node/v$old/bin/node" "\$d/bin/node"
      printf '%s\n' "\$v" > "\$d/bin/version"
      printf '%s\n' "${FIXED_RESULT:-rejected}" > "\$d/bin/verdict" ;;
    alias)
      if [ -n "\$2" ]; then
        echo "alias \$2 \$3" >> "\$NVM_DIR/aliases.log"
        [ "\$2" = default ] && echo "\$3" > "\$NVM_DIR/default.state"
      else for a in ${ALIASES:-}; do echo "\${a%%:*} -> x (-> \${a#*:})"; done; fi ;;
    deactivate)
      [ "${DEACTIVATE:-works}" = works ] && ACTIVE_NOW=""
      return 0 ;;
    uninstall)
      if [ -n "\${ACTIVE_NOW-${ACTIVE:-}}" ] && [ "\${ACTIVE_NOW-${ACTIVE:-}}" = "\$2" ]; then
        echo "nvm: Cannot uninstall currently-active node version, \$2 (inferred from \$2)." >&2
        return 1
      fi
      [ "${UNINSTALL:-ok}" = fail ] && { echo "nvm: stub could not remove \$2" >&2; return 1; }
      rm -rf "\$NVM_DIR/versions/node/\$2" ;;
  esac
}
EOF
}

# run_pty ANSWERS... : run --fix --only=node under a real terminal, answering prompts in order.
run_pty() {
  python3 -I - "$SCRIPT" "$NVM" "$@" <<'PY'
import os, pty, re, select, sys, time
script, nvm, answers = sys.argv[1], sys.argv[2], sys.argv[3:]
pid, fd = pty.fork()
if pid == 0:
    env = dict(os.environ, NVM_DIR=nvm, EMUDHRA_NODE_BINS=nvm + "/versions/node", EMUDHRA_AUDIT_ONLY="node")
    extra = os.environ.get("RUN_EXTRA_ARGS", "").split()
    os.execve("/bin/bash", ["/bin/bash", script, "--fix", "--only=node"] + extra, env)
out = b""; sent = 0; deadline = time.time() + 300
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 0.05)
    if fd in r:
        try: chunk = os.read(fd, 4096)
        except OSError: break
        if not chunk: break
        out += chunk
        # answer each prompt in order: the [y/N] questions and the "Type I AGREE" removal gate
        while out.count(b"[y/N]") + out.count(b"anything else cancels:") > sent:
            os.write(fd, (answers[sent] if sent < len(answers) else "n").encode() + b"\n"); sent += 1
    else:
        try:
            if os.waitpid(pid, os.WNOHANG)[0]: break
        except ChildProcessError: break
print(re.sub(rb"\x1b\[[0-9;]*m", b"", out).decode("utf-8", "replace"))
PY
}

run_plain() {  # ARGS... : run with no terminal (for --dry-run)
  NVM_DIR="$NVM" EMUDHRA_NODE_BINS="$NVM/versions/node" EMUDHRA_AUDIT_ONLY=node /bin/bash "$SCRIPT" "$@" </dev/null 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
}

calls() { cat "$NVM/calls.log" 2>/dev/null; }
installed() { [ -x "$NVM/versions/node/v$1/bin/node" ]; }

echo "1. happy path: 24.16.0 -> 24.22.1, default is the old version, answer y to both prompts"
FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=24.16.0 INSTALL=ok new_env 24.16.0
out=$(run_pty y y n)
check "planned a Node fix" $(yes_if grep -q 'Node.js (nvm)' <<<"$out")
check "ran nvm install v24.22.1 with --reinstall-packages-from" $(yes_if grep -q 'nvm install v24.22.1 --reinstall-packages-from=24.16.0\|install v24.22.1 --reinstall-packages-from=v24.16.0' <<<"$(calls)")
check "fixed version is installed beside the old one" $(yes_if installed 24.22.1)
check "old version is still installed" $(yes_if installed 24.16.0)
check "verified the new binary" $(yes_if grep -q 'verified:' <<<"$out")
check "switched the default alias" $(yes_if grep -q 'alias default v24.22.1' "$NVM/aliases.log")
check "declined removal: nvm uninstall was not run" $(yes_if test -z "$(calls | grep uninstall)")
check "reported Changed: 1" $(yes_if grep -q 'Changed: 1 ' <<<"$out")

echo "2. decline the install prompt"
FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=24.16.0 new_env 24.16.0
out=$(run_pty n)
check "did not install" $(yes_if test ! -x "$NVM/versions/node/v24.22.1/bin/node")
check "did not touch aliases" $(yes_if test ! -e "$NVM/aliases.log")
check "reported Changed: 0" $(yes_if grep -q 'Changed: 0 ' <<<"$out")

echo "3. install yes, default prompt no"
FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=24.16.0 new_env 24.16.0
out=$(run_pty y n)
check "installed" $(yes_if installed 24.22.1)
check "left the default alone" $(yes_if test ! -e "$NVM/aliases.log")

echo "4. install that does nothing (offline / interrupted)"
INSTALL=nothing REMOTE=24.22.1 DEFAULT=24.16.0 new_env 24.16.0
out=$(run_pty y y)
check "reported failure" $(yes_if grep -q 'nvm did not install' <<<"$out")
check "counted as failed" $(yes_if grep -q 'Failed or refused: 1' <<<"$out")
check "old version untouched" $(yes_if installed 24.16.0)
check "no alias change" $(yes_if test ! -e "$NVM/aliases.log")

echo "5. default is a different version"
FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=22.0.0 new_env 24.16.0
out=$(run_pty y y)
check "installed" $(yes_if installed 24.22.1)
check "did not offer to change the default" $(yes_if test "$(grep -c 'Make v24.22.1 the default' <<<"$out")" -eq 0)
check "said the default was left alone" $(yes_if grep -q 'not changing it' <<<"$out")
check "no alias change" $(yes_if test ! -e "$NVM/aliases.log")

echo "6. a verified-bad new install must not become the default"
FIXED_RESULT=trusted REMOTE=24.22.1 DEFAULT=24.16.0 new_env 24.16.0
out=$(run_pty y y)
check "reported the new binary does not reject the chain" $(yes_if grep -q 'does not reject the chain' <<<"$out")
check "left the default alone" $(yes_if test ! -e "$NVM/aliases.log")
check "counted as failed" $(yes_if grep -q 'Failed or refused: 1' <<<"$out")

echo "7. fixed release not published yet"
REMOTE=24.20.0 DEFAULT=24.16.0 new_env 24.16.0
out=$(run_pty y y)
check "refused" $(yes_if grep -q 'not available yet' <<<"$out")
check "installed nothing" $(yes_if test -z "$(calls | grep '^nvm install')")

echo "8. a major line with no published fix (v25)"
REMOTE=25.9.0 DEFAULT=25.1.0 new_env 25.1.0
out=$(run_pty y y)
check "the planner does not schedule a fix for it" $(yes_if test -z "$(calls | grep '^nvm install')")
# The planner already skips this case, so also call fix_node_nvm directly to prove the guard inside it holds
# (defence in depth: it must never pick another major if the planner is ever loosened).
direct=$(NVM_DIR="$NVM" EMUDHRA_NODE_BINS="$NVM/versions/node" /bin/bash -c '
  eval "$(sed -n "/^nvm_dir()/,/^# ---- orchestration/p" "'"$SCRIPT"'" | sed "$d")"
  fx_say() { echo "$*"; }; fx_warn() { echo "WARN $*"; }; fx_cmd() { echo "CMD $*"; }
  confirm() { echo "ASKED $1"; return 0; }
  SKIPPED_N=0 FAILED_N=0 FIXED_N=0 DRY=0 FIX_NOTES=; C_BLD=; C_OFF=
  fix_node_nvm "$NVM_DIR/versions/node/v25.1.0/bin/node"; echo "skipped=$SKIPPED_N failed=$FAILED_N fixed=$FIXED_N"' 2>&1)
check "fix_node_nvm itself refuses a major with no fix" $(yes_if grep -q 'no fixed Node.js release is published' <<<"$direct")
check "it never asked to install anything" $(yes_if test -z "$(grep ASKED <<<"$direct")")
check "it ran no nvm install" $(yes_if test -z "$(calls | grep '^nvm install')")

echo "10. removal: typing exactly I AGREE removes the old version (and only that one)"
FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=24.16.0 ALIASES="default:v24.22.1" new_env 24.16.0
out=$(run_pty y y "I AGREE")
check "warned about the impact" $(yes_if grep -q 'permanently deletes Node.js v24.16.0' <<<"$out")
check "listed the consequences (pins, global packages, cannot be undone)" $(yes_if grep -q '.nvmrc' <<<"$out")
check "ran nvm uninstall v24.16.0" $(yes_if grep -q '^nvm uninstall v24.16.0' <<<"$(calls)")
check "the old version is gone" $(yes_if test ! -d "$NVM/versions/node/v24.16.0")
check "the fixed version is still there" $(yes_if installed 24.22.1)
check "recorded how to reinstall" $(yes_if grep -q 'reinstall with: nvm install v24.16.0' <<<"$out")

echo "11. removal: anything other than exactly I AGREE keeps it"
for ans in "y" "yes" "Y" "i agree" "I agree" "I AGREE " " I AGREE" "I  AGREE" ""; do
  FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=24.16.0 ALIASES="default:v24.22.1" new_env 24.16.0
  out=$(run_pty y y "$ans")
  check "answer [$ans] does not remove it" $(yes_if test -d "$NVM/versions/node/v24.16.0")
  check "answer [$ans]: no uninstall was run" $(yes_if test -z "$(calls | grep '^nvm uninstall')")
done

echo "12. removal: --yes alone must never remove anything"
FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=24.16.0 ALIASES="default:v24.22.1" new_env 24.16.0
out=$(RUN_EXTRA_ARGS="--yes" run_pty)
check "--yes installed the fixed version" $(yes_if installed 24.22.1)
check "--yes did not remove the old version" $(yes_if test -d "$NVM/versions/node/v24.16.0")
check "no nvm uninstall was run" $(yes_if test -z "$(calls | grep '^nvm uninstall')")

echo "13. removal: with no terminal, nothing is removed"
FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=24.16.0 ALIASES="default:v24.22.1" new_env 24.16.0
out=$(python3 -I - "$SCRIPT" "$NVM" <<'PY'
import os, re, subprocess, sys
os.setsid()
env = dict(os.environ, NVM_DIR=sys.argv[2], EMUDHRA_NODE_BINS=sys.argv[2] + "/versions/node", EMUDHRA_AUDIT_ONLY="node")
r = subprocess.run(["/bin/bash", sys.argv[1], "--fix", "--yes", "--only=node"], stdin=subprocess.DEVNULL,
                   capture_output=True, text=True, env=env)
print(re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr))
PY
)
check "installed under --yes" $(yes_if installed 24.22.1)
check "said it will not remove without a terminal" $(yes_if grep -q 'not removing anything' <<<"$out")
check "the old version is still there" $(yes_if test -d "$NVM/versions/node/v24.16.0")

echo "14. removal: the default and aliased versions are kept, with the reason"
FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=24.16.0 ALIASES="default:v24.16.0 work:v24.16.0" new_env 24.16.0
out=$(run_pty y n "I AGREE")          # decline switching the default, so the old one stays the default
check "kept it because it is the default" $(yes_if grep -q 'keeping v24.16.0: it is your nvm default' <<<"$out")
check "named the aliases pointing at it" $(yes_if grep -q 'aliases point at it' <<<"$out")
check "no removal prompt was shown" $(yes_if test "$(grep -c 'Type I AGREE' <<<"$out")" -eq 0)
check "the old version is still there" $(yes_if test -d "$NVM/versions/node/v24.16.0")
FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=22.0.0 ALIASES="work:v24.16.0" new_env 24.16.0
out=$(run_pty y "I AGREE")
check "an alias alone keeps it (default is elsewhere)" $(yes_if test -d "$NVM/versions/node/v24.16.0")
check "said which alias" $(yes_if grep -q 'aliases point at it: work' <<<"$out")

echo "15. two old versions on one major line: ONE upgrade, a separate prompt for each old version"
FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=22.0.0 ALIASES="default:v22.0.0" EXTRA="v24.10.0" new_env 24.16.0
out=$(run_pty y "I AGREE" n)
installs=$(grep -c '^nvm install' <<<"$(calls)")
prompts=$(grep -c 'Type I AGREE' <<<"$out")
check "upgraded once, not once per old version ($installs install)" $(yes_if test "$installs" -eq 1)
# The install count alone is weak: a second per-binary pass finds the fixed version already installed and does not
# install again. So also count how many times the Node section is opened, and how often "Use the already-installed"
# is asked, which only happens on a redundant second pass.
sections=$(grep -c 'Node.js (nvm)' <<<"$out")
check "the Node fix ran as one section ($sections), not one per old binary" $(yes_if test "$sections" -eq 1)
check "no redundant 'use the already-installed' question" $(yes_if test "$(grep -c 'already-installed' <<<"$out")" -eq 0)
check "asked once per old version ($prompts prompts)" $(yes_if test "$prompts" -eq 2)
check "agreeing for one did not remove the other" $(yes_if test "$(ls "$NVM/versions/node" | grep -c '^v24\.')" -eq 2)
check "the fixed version is still there" $(yes_if installed 24.22.1)
check "exactly one old version was removed" $(yes_if test "$(grep -c '^nvm uninstall' <<<"$(calls)")" -eq 1)
check "never offered the fixed version" $(yes_if test -z "$(grep 'nvm uninstall v24.22.1' <<<"$out")")

echo "16. removal: a failed uninstall is reported, not claimed"
FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=24.16.0 ALIASES="default:v24.22.1" UNINSTALL=fail new_env 24.16.0
out=$(run_pty y y "I AGREE")
check "reported it could not remove" $(yes_if grep -q 'could not remove v24.16.0' <<<"$out")
check "did not claim success" $(yes_if test -z "$(grep 'removed v24.16.0' <<<"$out")")

echo "17. removal: never offered after a failed install or a failed verification"
INSTALL=nothing REMOTE=24.22.1 DEFAULT=24.16.0 new_env 24.16.0
out=$(run_pty y y "I AGREE")
check "failed install: no removal prompt" $(yes_if test "$(grep -c 'Type I AGREE' <<<"$out")" -eq 0)
FIXED_RESULT=trusted REMOTE=24.22.1 DEFAULT=24.16.0 new_env 24.16.0
out=$(run_pty y y "I AGREE")
check "failed verification: no removal prompt" $(yes_if test "$(grep -c 'Type I AGREE' <<<"$out")" -eq 0)
check "failed verification: old version still there" $(yes_if test -d "$NVM/versions/node/v24.16.0")

echo "19. removal: nvm refuses to uninstall the currently-active version"
# This is the real-world case: the shell the script was started from still has the old version active.
FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=24.16.0 ALIASES="default:v24.22.1" ACTIVE=v24.16.0 new_env 24.16.0
out=$(run_pty y y "I AGREE")
check "removed the old version even though it was active in the calling shell" $(yes_if test ! -d "$NVM/versions/node/v24.16.0")
check "ran nvm deactivate before uninstalling" $(yes_if grep -q '^nvm deactivate' <<<"$(calls)")
check "deactivated BEFORE the uninstall" $(yes_if test "$(calls | grep -n -E '^nvm (deactivate|uninstall)' | head -1 | grep -c deactivate)" -eq 1)
check "reported success" $(yes_if grep -q 'removed v24.16.0' <<<"$out")

FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=24.16.0 ALIASES="default:v24.22.1" ACTIVE=v24.16.0 DEACTIVATE=broken new_env 24.16.0
out=$(run_pty y y "I AGREE")
check "if deactivate does not help, it is still there" $(yes_if test -d "$NVM/versions/node/v24.16.0")
check "shows nvm's own message, not just 'could not remove'" $(yes_if grep -q 'Cannot uninstall currently-active' <<<"$out")
check "tells the user how to finish it themselves" $(yes_if grep -q 'open a NEW shell' <<<"$out")
check "does not claim it removed it" $(yes_if test -z "$(grep 'removed v24.16.0' <<<"$out")")

FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=24.16.0 ALIASES="default:v24.22.1" UNINSTALL=fail new_env 24.16.0
out=$(run_pty y y "I AGREE")
check "any other uninstall failure also shows nvm's message" $(yes_if grep -q 'stub could not remove' <<<"$out")

echo "18. dry run"
FIXED_RESULT=rejected REMOTE=24.22.1 DEFAULT=24.16.0 new_env 24.16.0
out=$(run_plain --fix --dry-run --only=node)
check "prints the install command" $(yes_if grep -q 'nvm install v24.22.1 --reinstall-packages-from=v24.16.0' <<<"$out")
check "installs nothing" $(yes_if test ! -x "$NVM/versions/node/v24.22.1/bin/node")
check "no nvm install was run" $(yes_if test -z "$(calls | grep '^nvm install')")
check "no nvm uninstall was run" $(yes_if test -z "$(calls | grep '^nvm uninstall')")
check "says removal would be gated" $(yes_if grep -q 'type-I-AGREE' <<<"$out")

echo
if [ "$fails" -eq 0 ]; then echo "all checks passed"; exit 0; fi
echo "$fails check(s) FAILED"; exit 1

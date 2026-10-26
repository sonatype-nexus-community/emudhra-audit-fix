#!/usr/bin/env bash
# Audit fixtures use fake interpreters and uv, private directories, and no network.
# Catches omitted managed installs, collapsed venvs, unsafe guidance, and audit mutations.
HERE=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="$HERE/../emudhra-audit-fix.sh"
W=$(mktemp -d "${TMPDIR:-/tmp}/emudhra-uv-envs.XXXXXX") || exit 2
W=$(cd "$W" && pwd -P)
trap 'rm -rf "$W"' EXIT
H="$W/home with spaces"
mkdir -p "$H/bin" "$H/managed pythons" "$H/tool installs"
export UV_PYTHON_INSTALL_DIR="$H/managed pythons" UV_TOOL_DIR="$H/tool installs"
export UV_TEST_CALLS="$W/calls" UV_TEST_PROBES="$W/probes"
: > "$UV_TEST_CALLS"; : > "$UV_TEST_PROBES"
fails=0
check() {
  if "$@"; then return; fi
  printf '  FAIL %s\n' "$*"; fails=$((fails + 1))
  [ -n "${DEBUG_FAILS:-}" ] && printf '%s\n' "$out"
}
cat > "$H/bin/uv" <<'UV'
#!/bin/sh
printf '%s\n' "$*" >> "$UV_TEST_CALLS"
# Only directory discovery and offline catalogue inspection are permitted.
while [ "$#" -gt 0 ]; do
  case "$1" in
    --cache-dir) shift 2 ;;
    --offline|--no-config|--no-python-downloads) shift ;;
    python|tool) break ;;
    *) echo "UNEXPECTED uv operation" >> "$UV_TEST_CALLS"; exit 1 ;;
  esac
done
[ "${UV_TEST_DISCOVERY_FAIL:-}" = yes ] && exit 1
case "$*" in
  'python dir') printf '%s\n' "$UV_PYTHON_INSTALL_DIR" ;;
  'tool dir') printf '%s\n' "$UV_TOOL_DIR" ;;
  'python list --only-downloads --managed-python cpython@3.12') printf 'cpython-%s-macos-aarch64-none <download available>\n' "${UV_TEST_CATALOG_LATEST:-3.12.0}" ;;
  'python list --only-downloads --managed-python cpython@3.13') echo 'cpython-3.13.0-macos-aarch64-none <download available>' ;;
  *) echo "UNEXPECTED uv operation" >> "$UV_TEST_CALLS"; exit 1 ;;
esac
UV
chmod +x "$H/bin/uv"
managed="$UV_PYTHON_INSTALL_DIR/cpython-3.12.0-macos-aarch64-none"
mkdir -p "$managed/bin"
cat > "$managed/bin/python3" <<'PYTHON'
#!/bin/sh
# Distinguish the virtual environment from its common underlying Python.
p=$0
home=$(cd "$(dirname "$p")/.." && pwd)
if [ ! -f "$home/pyvenv.cfg" ]; then
  while [ -L "$p" ]; do p=$(readlink "$p"); done
  home=$(cd "$(dirname "$p")/.." && pwd)
fi
printf '%s|%s\n' "$home" "$*" >> "$UV_TEST_PROBES"
[ "$1" = -I ] && shift
[ "$1" = -B ] && shift
[ "$1" = -m ] && exit 1
shift
mode=$1; shift
case "$mode" in
  info)
    if [ -f "$home/pyver" ]; then echo "pyver=$(cat "$home/pyver")"; else echo pyver=3.12.0; fi
    real=$0
    while [ -L "$real" ]; do real=$(readlink "$real"); done
    echo "baseprefix=$(cd "$(dirname "$real")/.." && pwd)"
    echo implementation=cpython
    [ -f "$home/certifi-version" ] && echo "certifi=$(cat "$home/certifi-version")"
    echo cafile=/etc/ssl/cert.pem
    echo openssl=fixture
    exit 0 ;;
  default|certifi)
    for u in "$@"; do
      result=certerr
      [ "$mode" = default ] && [ -f "$home/affected-default" ] && result=ok
      [ -f "$home/inconclusive" ] && result=err
      case "$u" in *github.com*) result=ok ;; esac
      if [ "$mode" = certifi ] && [ -f "$home/affected" ]; then result=ok; fi
      [ "$mode" = certifi ] && [ -f "$home/certifi-inconclusive" ] && result=err
      printf '%s %s\n' "$result" "$u"
    done ;;
  *) exit 1 ;;
esac
PYTHON
chmod +x "$managed/bin/python3"
ln -s "$managed/bin/python3" "$managed/bin/python3.12"
ln -s "$managed" "$UV_PYTHON_INSTALL_DIR/cpython-3.12-macos-aarch64-none"
hidden="$UV_PYTHON_INSTALL_DIR/cpython-3.13.0-macos-aarch64-none"
mkdir -p "$hidden/bin"
cp "$managed/bin/python3" "$hidden/bin/python3"
echo 3.13.0 > "$hidden/pyver"
ln -s "$managed/bin/python3" "$H/bin/python3.12"
# Different certifi versions, identical real Python executable.
for name in alpha beta; do
  envdir="$UV_TOOL_DIR/$name"
  mkdir -p "$envdir/bin"
  : > "$envdir/uv-receipt.toml"; : > "$envdir/pyvenv.cfg"
  ln -s "$managed/bin/python3" "$envdir/bin/python"
done
echo 2026.7.22 > "$UV_TOOL_DIR/alpha/certifi-version"
echo 2026.10.19 > "$UV_TOOL_DIR/beta/certifi-version"
: > "$UV_TOOL_DIR/alpha/affected"
mkdir -p "$UV_TOOL_DIR/broken/bin" "$UV_TOOL_DIR/not-a-tool/bin"
: > "$UV_TOOL_DIR/broken/uv-receipt.toml"; : > "$UV_TOOL_DIR/broken/pyvenv.cfg"
ln -s "$W/missing-python" "$UV_TOOL_DIR/broken/bin/python"
ln -s "$managed/bin/python3" "$UV_TOOL_DIR/not-a-tool/bin/python"
# Load the real script up to main, then restrict legacy discovery in this test process.
# This avoids probing real machine installations in the live fixture scenarios.
sed '/^# ---* main/,$d' "$SCRIPT" > "$W/library.sh"
cat > "$W/run.sh" <<'RUN'
#!/bin/bash
. "$UV_TEST_LIBRARY" "$@"
eval "$(declare -f python_candidates | sed '1s/python_candidates/fixture_candidates/')"
python_candidates() { fixture_candidates | grep -F "$HOME"; }
audit_python
print_guidance
[ "$FIXMODE" -eq 1 ] && run_fixes
[ "$N_BAD" -gt 0 ] && exit 1
exit 0
RUN
run_audit() {
  HOME="$H" PATH="$H/bin:/usr/bin:/bin" UV_TEST_LIBRARY="$W/library.sh" \
    /bin/bash "$W/run.sh" "$@" > "$W/output" 2>&1
  rc=$?; out=$(cat "$W/output")
}
[ "${UV_TEST_FIXTURE_ONLY:-}" = 1 ] && return 0

echo '1. offline discovery includes managed installs and each tool environment'
run_audit --no-network -v
check grep -q 'uv tool: alpha' "$W/output"
check grep -q 'uv tool: beta' "$W/output"
check grep -q 'LIKELY-AFFECTED.*uv tool: alpha' "$W/output"
check grep -q 'LIKELY-OK.*uv tool: beta' "$W/output"
check grep -q 'UNKNOWN.*uv tool: broken' "$W/output"
check test "$(grep -F "$managed|" "$UV_TEST_PROBES" | grep -c ' info$')" = 1
check test "$(grep -c 'default\|certifi .*https:' "$UV_TEST_PROBES")" = 0
check test "$(grep -c 'not-a-tool' "$UV_TEST_PROBES")" = 0
check test "$(grep -F "$hidden|" "$UV_TEST_PROBES" | grep -c ' info$')" = 1
check test "$rc" = 1
check grep -q 'uv tool upgrade' "$W/output"
check test "$(grep -c 'pip install' "$W/output")" = 0
check grep -q -- '--offline' "$UV_TEST_CALLS"
check grep -q -- '--cache-dir' "$UV_TEST_CALLS"
check test "$(grep -c UNEXPECTED "$UV_TEST_CALLS")" = 0

echo '2. live probes distinguish tool certifi from its protected base interpreter'
: > "$UV_TEST_PROBES"
run_audit -v
check grep -q 'AFFECTED.*uv tool: alpha' "$W/output"
check grep -q 'OK.*uv tool: beta' "$W/output"
check grep -q 'application' "$W/output"
check test "$rc" = 1
check grep -q 'alpha|.* certifi ' "$UV_TEST_PROBES"
check grep -q 'beta|.* certifi ' "$UV_TEST_PROBES"
check test "$(grep -c UNEXPECTED "$UV_TEST_CALLS")" = 0

echo '3. one protected trust path cannot hide an inconclusive certifi probe'
: > "$UV_TOOL_DIR/alpha/certifi-inconclusive"
run_audit -v
check grep -q 'LIKELY-AFFECTED.*uv tool: alpha' "$W/output"
check test "$(grep -c '^\[OK\] uv tool: alpha' "$W/output")" = 0
rm "$UV_TOOL_DIR/alpha/certifi-inconclusive"

echo '4. failed uv discovery is visible and does not stop ordinary Python checks'
UV_TEST_DISCOVERY_FAIL=yes run_audit --no-network -v
check grep -q 'UNKNOWN.*uv.*discovery' "$W/output"
check grep -q 'Python 3.12.0' "$W/output"

echo '5. no uv is handled without failing ordinary Python discovery'
mv "$H/bin/uv" "$H/bin/uv-hidden"
run_audit --no-network -v
check grep -q 'Python 3.12.0' "$W/output"
check test "$(grep -c 'uv.*discovery' "$W/output")" = 0

if [ "$fails" -gt 0 ]; then echo "$fails failed"; exit 1; fi
echo 'all checks passed'

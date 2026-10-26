#!/usr/bin/env bash
# Fix regression tests use throwaway interpreters, receipts, executable links, and a stub uv.
# No real tool, resolver, network, or user installation is invoked.
HERE=$(cd "$(dirname "$0")/.." && pwd)
UV_TEST_FIXTURE_ONLY=1 . "$HERE/tests/test_uv_environments.sh"
cat > "$H/bin/uv" <<'UV'
#!/bin/sh
printf '%s\n' "$*" >> "$UV_TEST_CALLS"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --cache-dir|--directory) shift 2 ;;
    --offline|--no-config|--no-python-downloads) shift ;;
    *) break ;;
  esac
done
case $1 in
  --version) printf 'uv %s\n' "${UV_TEST_VERSION:-0.13.5}"; exit 0 ;;
esac
case "$1 $2" in
  'python dir')
    if [ "$3" = --bin ]; then printf '%s\n' "$HOME/bin"; else printf '%s\n' "$UV_PYTHON_INSTALL_DIR"; fi ;;
  'tool dir')
    if [ "$3" = --bin ]; then printf '%s\n' "$HOME/bin"; else printf '%s\n' "$UV_TOOL_DIR"; fi ;;
  'tool list')
    printf 'alpha v1.0 (%s/alpha)\n- alpha-cli (%s/alpha-cli)\n- .alpha-cli (%s/.alpha-cli)\n' "$UV_TOOL_DIR" "${UV_TEST_OLD_BINDIR:-$HOME/bin}" "${UV_TEST_OLD_BINDIR:-$HOME/bin}" ;;
  'python list')
    case "$*" in
      *cpython@3.12) printf 'cpython-%s-macos-aarch64-none <download available>\n' "${UV_TEST_CATALOG_LATEST:-3.12.0}" ;;
      *cpython@3.13) echo 'cpython-3.13.0-macos-aarch64-none <download available>' ;;
      *) exit 26 ;;
    esac ;;
  'python find')
    printf '%s\n' "$UV_PYTHON_INSTALL_DIR/cpython-3.12-macos-aarch64-none/bin/python3" ;;
  'python upgrade')
    [ "$3" = 3.12 ] || exit 21
    [ "${UV_TEST_UPDATE:-}" = no-upgrade ] && exit 0
    old="$UV_PYTHON_INSTALL_DIR/cpython-3.12.0-macos-aarch64-none"
    case "${UV_TEST_UPDATE:-}" in
      same-patch-*)
        printf '\n# replaced build\n' >> "$old/bin/python3"
        : > "$old/replaced-build"
        case "$UV_TEST_UPDATE" in
          same-patch-ok) rm -f "$old/affected-default" ;;
          same-patch-error) exit 22 ;;
        esac
        exit 0 ;;
    esac
    new="$UV_PYTHON_INSTALL_DIR/cpython-3.12.1-macos-aarch64-none"
    mkdir -p "$new/bin"
    cp "$old/bin/python3" "$new/bin/python3"
    echo 3.12.1 > "$new/pyver"
    [ "${UV_TEST_UPDATE:-}" = bad ] && : > "$new/affected-default"
    rm -f "$UV_PYTHON_INSTALL_DIR/cpython-3.12-macos-aarch64-none" "$HOME/bin/python3.12"
    ln -s "$new" "$UV_PYTHON_INSTALL_DIR/cpython-3.12-macos-aarch64-none"
    ln -s "$new/bin/python3" "$HOME/bin/python3.12"
    [ "${UV_TEST_UPDATE:-}" = disk-full ] && { : > "$UV_TEST_COPY_BLOCKED"; exit 22; }
    [ "${UV_TEST_UPDATE:-}" = error ] && exit 22
    exit 0 ;;
  'tool upgrade')
    [ "$3" = alpha ] && [ "$4" = --python ] && [ -x "$5" ] || exit 23
    d="$UV_TOOL_DIR/alpha"
    echo '# changed during upgrade' > "$d/uv-receipt.toml"
    echo 2026.10.19 > "$d/certifi-version"
    rm -f "$d/affected" "$HOME/bin/.alpha-cli"
    ln -s "$d/bin/python" "$HOME/bin/added-entrypoint"
    ln -s "$d/bin/python" "$HOME/bin/.added-hidden-entrypoint"
    if [ "${UV_TEST_UPDATE:-}" = bad ]; then : > "$d/affected"; fi
    if [ "${UV_TEST_UPDATE:-}" = stale-certifi ]; then echo 2026.7.22 > "$d/certifi-version"; fi
    if [ "${UV_TEST_UPDATE:-}" = inconclusive ]; then : > "$d/inconclusive"; fi
    if [ "${UV_TEST_UPDATE:-}" = wrong-minor ]; then echo 3.13.0 > "$d/pyver"; fi
    [ "${UV_TEST_UPDATE:-}" = disk-full ] && { : > "$UV_TEST_COPY_BLOCKED"; exit 24; }
    [ "${UV_TEST_UPDATE:-}" = error ] && exit 24
    exit 0 ;;
  'pip check')
    [ "${UV_TEST_UPDATE:-}" != dependency-error ] ;;
  *) echo 'UNEXPECTED uv operation' >> "$UV_TEST_CALLS"; exit 25 ;;
esac
UV
chmod +x "$H/bin/uv"
original_receipt='# exact version and local source must survive a failed update'
reset_tool() {
  rm -rf "${UV_TOOL_DIR}.emudhra-backups"
  printf '%s\n' "$original_receipt" > "$UV_TOOL_DIR/alpha/uv-receipt.toml"
  echo 2026.7.22 > "$UV_TOOL_DIR/alpha/certifi-version"
  : > "$UV_TOOL_DIR/alpha/affected"
  rm -f "$UV_TOOL_DIR/alpha/inconclusive" "$UV_TOOL_DIR/alpha/pyver" "$H/bin/added-entrypoint" "$H/bin/.added-hidden-entrypoint"
  ln -sf "$UV_TOOL_DIR/alpha/bin/python" "$H/bin/alpha-cli"
  ln -sf "$UV_TOOL_DIR/alpha/bin/python" "$H/bin/.alpha-cli"
  printf 'unrelated\n' > "$H/bin/untouched-file"
  : > "$UV_TEST_CALLS"
}
reset_python() {
  rm -rf "$UV_PYTHON_INSTALL_DIR/.emudhra-backups" "$UV_PYTHON_INSTALL_DIR/cpython-3.12.1-macos-aarch64-none"
  rm -f "$UV_PYTHON_INSTALL_DIR/cpython-3.12-macos-aarch64-none" "$H/bin/python3.12"
  ln -s "$managed" "$UV_PYTHON_INSTALL_DIR/cpython-3.12-macos-aarch64-none"
  ln -s "$managed/bin/python3" "$H/bin/python3.12"
  : > "$managed/affected-default"
  : > "$UV_TEST_CALLS"
}

echo '1. tool preview leaves receipts, packages, links, and backup directories unchanged'
reset_tool
run_audit --fix --only=uvtools --dry-run
check grep -q '^    \$ .*tool upgrade alpha' "$W/output"
check test "$(cat "$UV_TOOL_DIR/alpha/uv-receipt.toml")" = "$original_receipt"
check test ! -d "${UV_TOOL_DIR}.emudhra-backups"
check test "$(grep -c 'tool upgrade' "$UV_TEST_CALLS")" = 0

echo '2. a noninteractive fix without --yes skips the tool'
run_audit --fix --only=uvtools
check test "$(grep -c 'tool upgrade' "$UV_TEST_CALLS")" = 0
check grep -q 'Skipped: 1' "$W/output"

echo '3. a verified tool upgrade affects only that tool and saves a persistent backup'
run_audit --fix --only=uvtools --yes
check grep -q 'Changed: 1' "$W/output"
check test "$(grep -c 'tool upgrade alpha' "$UV_TEST_CALLS")" = 1
check test "$(grep -c 'tool upgrade beta\|tool upgrade --all' "$UV_TEST_CALLS")" = 0
check test ! -f "$UV_TOOL_DIR/alpha/affected"
check test -d "${UV_TOOL_DIR}.emudhra-backups"
check test "$(cat "$H/bin/untouched-file")" = unrelated

echo '4. failed commands, TLS failures, inconclusive probes, changed minor versions, and dependency conflicts restore the tool'
for failure in error bad inconclusive wrong-minor dependency-error stale-certifi; do
  reset_tool
  UV_TEST_UPDATE="$failure" run_audit --fix --only=uvtools --yes
  check grep -q 'Failed or refused: 1' "$W/output"
  check test "$(cat "$UV_TOOL_DIR/alpha/uv-receipt.toml")" = "$original_receipt"
  check test -f "$UV_TOOL_DIR/alpha/affected"
  check test -L "$H/bin/alpha-cli"
  check test ! -L "$H/bin/added-entrypoint"
  check test ! -L "$H/bin/.added-hidden-entrypoint"
  check test -L "$H/bin/.alpha-cli"
  check test "$(cat "$H/bin/untouched-file")" = unrelated
done

echo '5. conflicting or historical executable paths are refused before mutation'
reset_tool
mkdir -p "$H/old bin"
UV_TEST_OLD_BINDIR="$H/old bin" run_audit --fix --only=uvtools --yes
check test "$(grep -c 'tool upgrade' "$UV_TEST_CALLS")" = 0
check grep -q 'Nothing upgraded' "$W/output"
check test ! -d "${UV_TOOL_DIR}.emudhra-backups"
reset_tool
ln -sf "$UV_TOOL_DIR/beta/bin/python" "$H/bin/alpha-cli"
run_audit --fix --only=uvtools --yes
check test "$(grep -c 'tool upgrade' "$UV_TEST_CALLS")" = 0
check test "$(readlink "$H/bin/alpha-cli")" = "$UV_TOOL_DIR/beta/bin/python"
reset_tool

echo '6. Python preview does not upgrade or create backups'
reset_python
run_audit --fix --only=uvpython --dry-run
check grep -q 'python upgrade 3.12' "$W/output"
check test "$(grep -c 'python upgrade' "$UV_TEST_CALLS")" = 0
check test ! -d "$UV_PYTHON_INSTALL_DIR/.emudhra-backups"

echo '7. Python upgrades stay in the same minor and retain old interpreters'
run_audit --fix --only=uvpython --yes
check grep -q 'Changed: 1' "$W/output"
check test "$(grep -c 'python upgrade 3.12' "$UV_TEST_CALLS")" = 1
check test -x "$managed/bin/python3"
check test -x "$UV_PYTHON_INSTALL_DIR/cpython-3.12.1-macos-aarch64-none/bin/python3"
check test "$(readlink "$H/bin/python3.12")" = "$UV_PYTHON_INSTALL_DIR/cpython-3.12.1-macos-aarch64-none/bin/python3"

echo '8. failed or unprotected Python upgrades restore the preferred links'
for failure in error bad; do
  reset_python
  UV_TEST_UPDATE="$failure" run_audit --fix --only=uvpython --yes
  check grep -q 'Failed or refused: 1' "$W/output"
  check test "$(readlink "$H/bin/python3.12")" = "$managed/bin/python3"
  check test "$(readlink "$UV_PYTHON_INSTALL_DIR/cpython-3.12-macos-aarch64-none")" = "$managed"
  check test -x "$managed/bin/python3"
done

echo '9. replacing the same Python patch build is rolled back with its contents'
for failure in same-patch-error same-patch-bad; do
  reset_python
  cp "$managed/bin/python3" "$W/original-python"
  UV_TEST_UPDATE="$failure" run_audit --fix --only=uvpython --yes
  check grep -q 'Failed or refused: 1' "$W/output"
  check cmp -s "$W/original-python" "$managed/bin/python3"
  check test ! -f "$managed/replaced-build"
done

echo '10. protected environments with outdated trust packages still receive upgrade offers'
reset_python
rm "$managed/affected-default"
echo 2026.7.22 > "$managed/certifi-version"
run_audit --fix --only=uvpython --dry-run
check grep -q '^\[OK\] uv Python' "$W/output"
check grep -q 'python upgrade 3.12' "$W/output"
rm "$managed/certifi-version"
reset_tool
rm "$UV_TOOL_DIR/alpha/affected"
run_audit --fix --only=uvtools --dry-run
check grep -q '^\[OK\] uv tool: alpha' "$W/output"
check grep -q '^    \$ .*tool upgrade alpha' "$W/output"

echo '11. offline catalogue updates are offered without labelling protected runtimes affected'
UV_TEST_CATALOG_LATEST=3.12.1 run_audit --fix --only=uvpython --dry-run -v
check grep -q '^\[OK\] uv Python 3.12.0' "$W/output"
check grep -q 'available patch: 3.12.1' "$W/output"
check grep -q 'python upgrade 3.12' "$W/output"
check test "$(grep -c 'python upgrade' "$UV_TEST_CALLS")" = 0

echo '12. a no-op upgrade cannot claim the available patch was installed'
UV_TEST_CATALOG_LATEST=3.12.1 UV_TEST_UPDATE=no-upgrade run_audit --fix --only=uvpython --yes
check grep -q 'Failed or refused: 1' "$W/output"
check grep -q 'older than the available patch' "$W/output"

echo '13. a retained older patch does not requeue an update already installed'
echo 2026.7.22 > "$managed/certifi-version"
new="$UV_PYTHON_INSTALL_DIR/cpython-3.12.1-macos-aarch64-none"
mkdir -p "$new/bin"; cp "$managed/bin/python3" "$new/bin/python3"; echo 3.12.1 > "$new/pyver"
rm "$UV_PYTHON_INSTALL_DIR/cpython-3.12-macos-aarch64-none" "$H/bin/python3.12"
ln -s "$new" "$UV_PYTHON_INSTALL_DIR/cpython-3.12-macos-aarch64-none"
ln -s "$new/bin/python3" "$H/bin/python3.12"
UV_TEST_CATALOG_LATEST=3.12.1 run_audit --fix --only=uvpython --dry-run
check test "$(grep -c 'python upgrade 3.12' "$W/output")" = 0
check grep -q 'No uv Python upgrade scheduled' "$W/output"
check test "$(grep -c 'Nothing matched' "$W/output")" = 0

echo '14. a retained downloaded patch must not hide an older preferred interpreter'
rm "$UV_PYTHON_INSTALL_DIR/cpython-3.12-macos-aarch64-none"
ln -s "$managed" "$UV_PYTHON_INSTALL_DIR/cpython-3.12-macos-aarch64-none"
UV_TEST_CATALOG_LATEST=3.12.1 run_audit --fix --only=uvpython --dry-run
check grep -q 'python upgrade 3.12' "$W/output"
rm "$UV_PYTHON_INSTALL_DIR/cpython-3.12-macos-aarch64-none" "$H/bin/python3.12"
ln -s "$new" "$UV_PYTHON_INSTALL_DIR/cpython-3.12-macos-aarch64-none"
ln -s "$managed/bin/python3" "$H/bin/python3.12"
UV_TEST_CATALOG_LATEST=3.12.1 run_audit --fix --only=uvpython --dry-run
check grep -q 'python upgrade 3.12' "$W/output"

cp "$managed/bin/python3" "$W/seed-python"
echo '15. disk exhaustion during an upgrade must not require another full copy to restore'
cat > "$H/bin/cp" <<'COPY'
#!/bin/sh
if [ -n "${UV_TEST_COPY_BLOCKED:-}" ] && [ -e "$UV_TEST_COPY_BLOCKED" ]; then
  echo 'cp: No space left on device' >&2
  exit 1
fi
exec /bin/cp "$@"
COPY
chmod +x "$H/bin/cp"
reset_tool
UV_TEST_COPY_BLOCKED="$W/disk-full" UV_TEST_UPDATE=disk-full run_audit --fix --only=uvtools --yes
check grep -q 'original tool environment and links restored' "$W/output"
check test -f "$UV_TOOL_DIR/alpha/uv-receipt.toml"
check test "$(cat "$UV_TOOL_DIR/alpha/uv-receipt.toml" 2>/dev/null)" = "$original_receipt"
check test -L "$H/bin/alpha-cli"
rm -f "$W/disk-full"
reset_python
UV_TEST_COPY_BLOCKED="$W/disk-full" UV_TEST_UPDATE=disk-full run_audit --fix --only=uvpython --yes
check grep -q 'original interpreter contents and links restored' "$W/output"
check test -x "$managed/bin/python3"
check test "$(readlink "$H/bin/python3.12")" = "$managed/bin/python3"
rm -f "$W/disk-full" "$H/bin/cp"
# Restore fixture prerequisites even when testing a broken rollback implementation.
if [ ! -x "$managed/bin/python3" ]; then
  mkdir -p "$managed/bin"; cp "$W/seed-python" "$managed/bin/python3"
fi

echo '16. preview default aliases follow the new patch and survive failed upgrades'
reset_python
for alias in python python3; do
  ln -s "$UV_PYTHON_INSTALL_DIR/cpython-3.12-macos-aarch64-none/bin/python3" "$H/bin/$alias"
done
run_audit --fix --only=uvpython --yes
check grep -q 'Changed: 1' "$W/output"
check test "$("$H/bin/python" -I -B "$W/probe.py" info 2>/dev/null | sed -n 's/^pyver=//p')" = 3.12.1
reset_python
UV_TEST_UPDATE=bad run_audit --fix --only=uvpython --yes
check test "$("$H/bin/python3" -I -B "$W/probe.py" info 2>/dev/null | sed -n 's/^pyver=//p')" = 3.12.0
rm -f "$H/bin/python" "$H/bin/python3"

echo '17. a stale default launcher must prevent an upgrade from reporting success'
reset_python
ln -s "$managed/bin/python3" "$H/bin/python"
UV_TEST_CATALOG_LATEST=3.12.1 run_audit --fix --only=uvpython --yes
check grep -q 'Failed or refused: 1' "$W/output"
check grep -q 'launcher' "$W/output"
check test "$(readlink "$H/bin/python3.12")" = "$managed/bin/python3"
rm "$H/bin/python"

echo '18. filesystem names cannot inject additional fix kinds into the plan'
reset_python
rm -f "$managed/affected-default" "$managed/certifi-version"
malicious="$W/bad"$'\nuvpython|3.13'
mkdir -p "$malicious/bin"
: > "$malicious/uv-receipt.toml"; : > "$malicious/pyvenv.cfg"
echo 2026.7.22 > "$malicious/certifi-version"
ln -s "$managed/bin/python3" "$malicious/bin/python"
ln -s "$malicious" "$UV_TOOL_DIR/ordinary-name"
run_audit --fix --only=uvpython --dry-run
check test "$(grep -c '^    \$ .*python upgrade 3.13' "$W/output")" = 0
check grep -q 'unsupported tool name' "$W/output"
# Protect other plan producers even if their own filesystem validation regresses.
cat > "$W/plan-boundary.sh" <<'PLAN'
#!/bin/bash
# shellcheck source=/dev/null
. "$UV_TEST_LIBRARY" --no-network
plan_add uvtools $'ordinary\nuvpython|3.13'
plan_has_kind uvpython && exit 1
plan_add $'uvtools\nuvpython' '3.13'
plan_has_kind uvpython && exit 1
exit 0
PLAN
check env HOME="$H" PATH="$H/bin:/usr/bin:/bin" UV_TEST_LIBRARY="$W/library.sh" /bin/bash "$W/plan-boundary.sh"

echo '19. uv with an affected TLS implementation cannot download security upgrades'
for version in 0.13.3 0.13.4rc1 unknown; do
for kind in uvtools uvpython; do
  reset_tool; reset_python
  UV_TEST_VERSION="$version" run_audit --fix --only="$kind" --yes
  check test "$(grep -c '^tool upgrade\|^python upgrade' "$UV_TEST_CALLS")" = 0
  check grep -q 'upgrade uv itself first' "$W/output"
  check test ! -d "${UV_TOOL_DIR}.emudhra-backups"
  check test ! -d "$UV_PYTHON_INSTALL_DIR/.emudhra-backups"
done
done

echo '20. substituted backup roots are refused before changing installed tools'
reset_tool
mkdir -p "$W/unrelated-backups"
ln -s "$W/unrelated-backups" "${UV_TOOL_DIR}.emudhra-backups"
run_audit --fix --only=uvtools --yes
check test "$(grep -c '^tool upgrade' "$UV_TEST_CALLS")" = 0
check test "$(cat "$UV_TOOL_DIR/alpha/uv-receipt.toml")" = "$original_receipt"
check test -z "$(ls -A "$W/unrelated-backups")"
rm "${UV_TOOL_DIR}.emudhra-backups"

echo '21. backups on another filesystem are refused before upgrading'
reset_tool
cat > "$H/bin/stat" <<'STAT'
#!/bin/sh
case "$2" in %a|%Lp) echo 700 ;; *) case "$*" in *emudhra-backups*) echo 2 ;; *) echo 1 ;; esac ;; esac
STAT
chmod +x "$H/bin/stat"
run_audit --fix --only=uvtools --yes
check test "$(grep -c '^tool upgrade' "$UV_TEST_CALLS")" = 0
check test "$(cat "$UV_TOOL_DIR/alpha/uv-receipt.toml")" = "$original_receipt"
rm "$H/bin/stat"

echo '22. existing backup roots writable by other users are refused'
reset_tool
mkdir -p "${UV_TOOL_DIR}.emudhra-backups"
chmod 0777 "${UV_TOOL_DIR}.emudhra-backups"
run_audit --fix --only=uvtools --yes
check test "$(grep -c '^tool upgrade' "$UV_TEST_CALLS")" = 0
check test "$(cat "$UV_TOOL_DIR/alpha/uv-receipt.toml")" = "$original_receipt"
chmod 0700 "${UV_TOOL_DIR}.emudhra-backups"

if [ "$fails" -gt 0 ]; then echo "$fails failed"; exit 1; fi
echo 'all checks passed'

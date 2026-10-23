#!/usr/bin/env bash
# Real uv integration with local wheels, private tool/cache directories, and synthetic
# TLS responses. No network requests and no user Python or tool installs are changed.
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
UV_REAL=$(command -v uv) || { echo 'uv is required'; exit 2; }
PYTHON_REAL=$(command -v python3) || { echo 'python3 is required'; exit 2; }
W=$(mktemp -d "${TMPDIR:-/tmp}/emudhra-uv-integration.XXXXXX")
W=$(cd "$W" && pwd -P)
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/home" "$W/wheels" "$W/staged" "$W/bin" "$W/python"
# Start a child with isolated uv storage and no inherited configuration or credentials.
if [ "${UV_TEST_INTEGRATION_CHILD:-}" != 1 ]; then
  env -i PATH="$W/bin:$PATH" HOME="$W/home" TMPDIR="${TMPDIR:-/tmp}" \
    UV_TEST_INTEGRATION_CHILD=1 UV_TEST_ROOT="$W" UV_REAL="$UV_REAL" PYTHON_REAL="$PYTHON_REAL" \
    UV_TOOL_DIR="$W/tools" UV_TOOL_BIN_DIR="$W/bin" UV_CACHE_DIR="$W/cache" \
    UV_PYTHON_INSTALL_DIR="$W/python" UV_PYTHON_BIN_DIR="$W/bin" \
    UV_NO_CONFIG=1 UV_PYTHON_DOWNLOADS=never \
    /bin/bash "$0"
  exit $?
fi
# The parent owns cleanup. Avoid nesting a second disposable tree in the child.
rm -rf "$W"
W=$UV_TEST_ROOT
trap - EXIT
"$PYTHON_REAL" -I -B - "$W" <<'PY'
import sys
from pathlib import Path
from zipfile import ZipFile
root = Path(sys.argv[1])
def wheel(name, version, directory, files, metadata="", entrypoints=""):
    dist = f"{name}-{version}.dist-info"
    path = root / directory / f"{name}-{version}-py3-none-any.whl"
    files = dict(files)
    files[f"{dist}/METADATA"] = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n{metadata}\n"
    files[f"{dist}/WHEEL"] = "Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    if entrypoints:
        files[f"{dist}/entry_points.txt"] = entrypoints
    files[f"{dist}/RECORD"] = "".join(f"{key},,\n" for key in files) + f"{dist}/RECORD,,\n"
    with ZipFile(path, "w") as archive:
        for key, value in files.items():
            archive.writestr(key, value)
wheel("audit_fixture", "1.0", "wheels", {"audit_fixture.py": "def main():\n    print('fixture tool works')\n"},
      "Requires-Dist: certifi>=2026.1\n", "[console_scripts]\naudit-fixture=audit_fixture:main\n")
for version, directory in [("2026.7.22", "wheels"), ("2026.10.19", "staged")]:
    wheel("certifi", version, directory, {"certifi/__init__.py": f"__version__ = '{version}'\n"})
PY
"$UV_REAL" tool install "$W/wheels/audit_fixture-1.0-py3-none-any.whl" \
  --python "$PYTHON_REAL" --no-python-downloads --no-index --find-links "$W/wheels"
"$W/bin/audit-fixture" | grep -qx 'fixture tool works'
cp "$UV_TOOL_DIR/audit-fixture/uv-receipt.toml" "$W/original-receipt"
mv "$W/staged/"*.whl "$W/wheels/"
sed '/^# ---* main/,$d' "$HERE/emudhra-audit-fix.sh" > "$W/library.sh"
# Do not inherit this test's arguments or errexit into the legacy script.
set +e
# shellcheck source=/dev/null
. "$W/library.sh"
set -e
# Globals are consumed by the sourced production helpers.
export UV_BIN="$UV_REAL" UV_PYTHON_DIR="$UV_PYTHON_INSTALL_DIR" UV_TOOLS_DIR="$UV_TOOL_DIR" YES=1
# Keep real Python metadata and imports. Replace only the external TLS responses.
cat > "$TMP/py_probe.py" <<'PY'
import importlib.metadata as m
import os
import ssl
import sys
mode = sys.argv[1]
if mode == "info":
    print("pyver=%d.%d.%d" % sys.version_info[:3])
    print("baseprefix=" + os.path.realpath(sys.base_prefix))
    print("implementation=" + sys.implementation.name)
    print("certifi=" + m.version("certifi"))
    print("cafile=" + str(ssl.get_default_verify_paths().cafile))
    print("openssl=" + ssl.OPENSSL_VERSION)
else:
    for url in sys.argv[2:]:
        result = "ok" if "github.com" in url else "certerr"
        if mode == "certifi" and os.environ.get("UV_TEST_TLS_BAD") == "1":
            result = "ok"
        print(result, url)
PY
set +e
fix_uv_tool audit-fixture
set -e
[ "$FIXED_N" -eq 1 ] && [ "$FAILED_N" -eq 0 ]
"$UV_TOOL_DIR/audit-fixture/bin/python" -I -B -c 'import certifi; assert certifi.__version__ == "2026.10.19"'
"$W/bin/audit-fixture" | grep -qx 'fixture tool works'
# Persistent recovery data must not be mistaken for another installed uv tool.
"$UV_REAL" tool list --show-paths > "$W/tool-list" 2> "$W/tool-list-warnings"
[ ! -s "$W/tool-list-warnings" ]
# uv must retain the local wheel requirement and index options in its receipt.
grep -q 'audit_fixture-1.0-py3-none-any.whl' "$UV_TOOL_DIR/audit-fixture/uv-receipt.toml"
grep -q 'find-links' "$UV_TOOL_DIR/audit-fixture/uv-receipt.toml"
cp "$UV_TOOL_DIR/audit-fixture/uv-receipt.toml" "$W/good-receipt"
# Relative directory settings must keep their meaning during the mutation.
cd "$W"
export UV_TOOL_DIR=tools UV_TOOL_BIN_DIR=bin UV_PYTHON_INSTALL_DIR=python UV_PYTHON_BIN_DIR=bin UV_WORKING_DIR=.
set +e
UV_TEST_TLS_BAD=1 fix_uv_tool audit-fixture > "$W/rollback.log" 2>&1
set -e
cat "$W/rollback.log"
[ "$FAILED_N" -eq 1 ]
grep -q 'original tool environment and links restored' "$W/rollback.log"
cmp "$W/good-receipt" "$UV_TOOL_DIR/audit-fixture/uv-receipt.toml"
"$W/bin/audit-fixture" | grep -qx 'fixture tool works'
# A changed executable directory must be refused while the old entry point survives.
mkdir -p "$W/another-bin"
export UV_TOOL_BIN_DIR="$W/another-bin"
set +e
fix_uv_tool audit-fixture
set -e
[ "$FAILED_N" -eq 2 ]
[ ! -e "$W/another-bin/audit-fixture" ]
"$W/bin/audit-fixture" | grep -qx 'fixture tool works'
echo 'real uv local wheel upgrade, rollback, relative paths, and changed bin directory passed'

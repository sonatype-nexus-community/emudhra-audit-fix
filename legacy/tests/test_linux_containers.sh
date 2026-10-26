#!/usr/bin/env bash
#
# Exercises `../emudhra-audit-fix.sh --fix` / `--undo` inside throwaway Linux containers.
# Nothing on the host is modified: the repository is mounted read-only and each container is removed afterwards.
#
# Usage: tests/test_linux_containers.sh [IMAGE ...]
#   default images: ubuntu:24.04 debian:12 alpine:3.20 fedora:41

HERE=$(cd "$(dirname "$0")/.." && pwd)
IMAGES=${*:-"ubuntu:24.04 debian:12 alpine:3.20 fedora:41"}

command -v docker >/dev/null 2>&1 || { echo "docker not found"; exit 2; }
docker info >/dev/null 2>&1 || { echo "docker daemon is not running"; exit 2; }

setup_for() {
  case $1 in
    # Install the tools, then step ca-certificates back to the oldest available version so the
    # unpatched state exists to be fixed. (Current images already carry the vendor's fixed package.)
    ubuntu:*|debian:*) echo "apt-get update -qq >/dev/null && apt-get install -y -qq ca-certificates curl python3 git openssl >/dev/null 2>&1; old=\$(apt-cache madison ca-certificates | awk '{print \$3}' | tail -1); echo \"downgrading ca-certificates to \$old\"; apt-get install -y -qq --allow-downgrades ca-certificates=\$old >/dev/null 2>&1; dpkg-query -W -f='ca-certificates now: \${Version}\\n' ca-certificates" ;;
    alpine:*)          echo "apk add --no-cache bash ca-certificates curl python3 git openssl >/dev/null 2>&1" ;;
    fedora:*)          echo "dnf install -y -q ca-certificates curl python3 git openssl p11-kit >/dev/null 2>&1" ;;
  esac
}

# The in-container scenario. Prints a marker line per step so the host can grade the run.
scenario() {
  cat <<'EOS'
S=/src/../emudhra-audit-fix.sh
step() { printf '\n##### %s\n' "$*"; }
step "1. audit before"
bash $S -v --no-guidance 2>&1 | sed -n '/^== CA bundle\|^== System CA/,/^== OS CA/p' | grep -E '^\[|probe:|path:' | head -8
step "2. dry-run"
bash $S --fix --dry-run --only=sys --no-guidance 2>&1 </dev/null | sed -n '/^== Fix/,$p' | grep -v '^$'
step "3. real fix"
bash $S --fix --yes --only=sys --no-guidance 2>&1 </dev/null | sed -n '/^== Fix/,$p' | grep -v '^$'
step "4. audit after"
bash $S -v --no-guidance 2>&1 | sed -n '/^== System CA/,/^== OS CA/p' | grep -E '^\[|probe:|path:' | head -8
step "5. fix again (should be a no-op)"
bash $S --fix --yes --only=sys --no-guidance 2>&1 </dev/null | sed -n '/^== Fix/,$p' | grep -v '^$' | head -8
step "6. undo"
bash $S --undo --yes 2>&1 </dev/null | sed -n '/^== Undo/,$p' | grep -v '^$'
step "7. audit after undo"
bash $S -v --no-guidance 2>&1 | sed -n '/^== System CA/,/^== OS CA/p' | grep -E '^\[|probe:|path:' | head -8
EOS
}

# grade_run : read a finished run on stdin; exit 1 if any audit step printed no [OK]/[AFFECTED] verdict.
grade_run() {
  awk '/^##### [147]\./{ if (step != "" && !seen) { printf "  FAIL: step %s printed no verdict\n", step; bad=1 } step=$2; seen=0; next }
       /^##### /{ if (step != "" && !seen) { printf "  FAIL: step %s printed no verdict\n", step; bad=1 } step=""; next }
       /^\[(OK|AFFECTED|LIKELY-OK|LIKELY-AFFECTED|UNKNOWN)\]/{ seen=1 }
       { print }
       END { if (step != "" && !seen) { printf "  FAIL: step %s printed no verdict\n", step; bad=1 } exit bad }'
}

for img in $IMAGES; do
  echo
  echo "================================================================ $img"
  setup=$(setup_for "$img")
  [ -z "$setup" ] && { echo "no setup recipe for $img"; continue; }
  # The scenario goes in as a file (not stdin) so package installs cannot swallow it.
  scen=$(mktemp "${TMPDIR:-/tmp}/emudhra-scenario.XXXXXX")
  scenario > "$scen"
  docker run --rm -v "$HERE":/src:ro -v "$scen":/scenario.sh:ro -e TERM=dumb "$img" \
    sh -c "$setup; command -v bash >/dev/null || { echo 'bash is missing'; exit 3; }; bash /scenario.sh" 2>&1 | grade_run
  rc=${PIPESTATUS[0]}; [ "${PIPESTATUS[1]}" -ne 0 ] && rc=1
  rm -f "$scen"
  echo "(container exit: $rc)"
done

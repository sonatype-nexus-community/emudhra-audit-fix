#!/usr/bin/env bash
#
# emudhra-audit-fix.sh - read-only audit of developer tools against the eMudhra
# intermediate CA compromise: https://emudhra.we-have-a-problem.com/
#
# Covers curl, git, Go, Python (incl. pip), Java, Node.js, Deno, Bun, rustup, uv, pixi, mise,
# Claude Code, Electron apps, Homebrew ca-certificates, system CA bundle files
# and OS CA packages. For each tool found it runs two checks:
#   1. Live probe   - the tool itself connects to hosts that chain to the
#                     compromised intermediates. A TLS certificate error means
#                     the tool is protected; a successful connection means it
#                     trusts the compromised chain (AFFECTED). A control host
#                     guards against proxy/network failures being misread.
#   2. Version check - compares the tool version with the fixed releases
#                     listed on the page (as of 2026-10-22).
# The probe is authoritative; the version check explains and backs it up.
#
# Affected items get remediation guidance (taken from the reference page).
#
# By default the script is read-only: nothing is installed, changed or removed,
# and guidance is only printed. Small probe programs are written to a private
# temp directory, which is deleted on exit.
#
# With --fix it can also apply the fixes it knows about (system CA bundle,
# Java cacerts, Homebrew ca-certificates, macOS built-in pip). Each change is
# confirmed, verified on a copy first, backed up with a timestamp, re-verified
# after install and rolled back if it fails. --dry-run shows the plan without
# changing anything; --undo restores the backups.
#
# Portable: bash 3.2+ (stock macOS) and Linux. No jq/python needed by the
# script itself.
#
# Exit status: 0 = nothing affected, 1 = at least one tool affected/likely
# affected, 2 = usage error.

VERSION_OF_SCRIPT=0.7.0

BAD_URLS="https://dv-g3b-emudhra.we-have-a-problem.com/ https://dv-g3b-aaa-emudhra.we-have-a-problem.com/"
# The control host must NOT chain to either root the advisory says to distrust, or a correctly
# patched trust store would fail it and look broken. (example.com chains to AAA Certificate Services.)
CONTROL_URL="https://github.com/"

NO_NETWORK=0
VERBOSE=0   # 0 compact (default), 1 full detail (-v), 2 plus probe commands and raw TLS errors (-vv)
NO_GUIDE=0
FIXMODE=0
DRY=0
YES=0
UNDO=0
WORKAROUND_ONLY=0
ONLY=

usage() {
  cat <<EOF
Usage: ${0##*/} [options]

Audit of developer tools (curl, git, Go, Python, Java, Node.js, Deno, Bun, rustup, uv,
pixi, mise, Claude Code, Electron apps, Homebrew and OS CA bundles) against the eMudhra
intermediate CA compromise. By default it is read-only: it prints remediation guidance
for anything affected and changes nothing.

Audit options (the default output is a compact summary; use -v for the full report):
  --no-network      skip live TLS probes; version checks only
  --no-guidance     do not print remediation guidance
  -v, --verbose     full detail: path, version and probe result for every item, full guidance
  -vv               also print the probe commands that are run, and raw TLS errors

Fix options (these can modify the system; sudo is used where needed):
  --fix             after the audit, offer to apply fixes, asking before each change
  --dry-run         with --fix: verify and show every step but change nothing
  --yes             with --fix: do not ask before each change
  --workaround-only with --fix: skip the vendor package upgrade on Linux and go straight
                    to blocking the two roots
  --only=KIND       with --fix: apply only one kind of fix: brew, sys, java, macpip, node, uv or rustup
  --undo            restore the backups made by --fix (asks first; honours --dry-run/--yes)

  -h, --help        show this help
EOF
}

for arg in "$@"; do
  case $arg in
    --no-network)  NO_NETWORK=1 ;;
    --no-guidance) NO_GUIDE=1 ;;
    -v|--verbose)  [ "$VERBOSE" -lt 1 ] && VERBOSE=1 ;;
    -vv)           VERBOSE=2 ;;
    --fix)         FIXMODE=1 ;;
    --dry-run)     DRY=1; FIXMODE=1 ;;
    --yes)         YES=1 ;;
    --undo)        UNDO=1 ;;
    --only=*)      ONLY=${arg#--only=} ;;
    --workaround-only) WORKAROUND_ONLY=1 ;;
    -h|--help)    usage; exit 0 ;;
    *)            echo "Unknown option: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$UNDO" -eq 1 ] && [ "$FIXMODE" -eq 1 ] && [ "$DRY" -eq 0 ]; then
  echo "--undo cannot be combined with --fix" >&2; exit 2
fi
case $ONLY in ""|brew|sys|java|macpip|node|uv|rustup) ;; *) echo "--only must be one of: brew, sys, java, macpip, node, uv, rustup" >&2; exit 2 ;; esac
if [ "$YES" -eq 1 ] && [ "$FIXMODE" -eq 0 ] && [ "$UNDO" -eq 0 ]; then
  echo "--yes only makes sense with --fix or --undo" >&2; exit 2
fi
if [ "$FIXMODE" -eq 1 ] && [ "$NO_NETWORK" -eq 1 ]; then
  echo "--fix needs the live probes to verify its changes; do not combine it with --no-network" >&2; exit 2
fi

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t emudhra)
if [ -z "$TMP" ] || [ ! -d "$TMP" ]; then
  echo "Could not create a temporary directory" >&2
  exit 2
fi
trap 'rm -rf "$TMP"' EXIT

if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_DIM=$'\033[2m'; C_BLD=$'\033[1m'; C_OFF=$'\033[0m'
else
  C_RED=; C_GRN=; C_YEL=; C_DIM=; C_BLD=; C_OFF=
fi

N_BAD=0; N_OK=0; N_UNK=0
SEEN=$'\n'
FIXV=            # fixed version(s) for the tool being checked (set by check_*_version)
FIX=             # guidance lines for the item about to be reported (see fix())
GUIDE=           # accumulated guidance for affected items
ADVISE=          # accumulated guidance for items that are protected but behind
CGUIDE=          # compact (one line per item) versions of GUIDE and ADVISE
CADVISE=
FIXSYS=0; FIXPIP=0       # set by fix_* when an item's guidance points at a shared block
NEED_SYS=0; NEED_PIPMAC=0  # shared guidance blocks to print (only if an affected item needs them)
BREW_PREFIX=
PYBIN=
PROBE_RES=
NODE_SYSCA_RES=
UV_FIXED=0.13.4         # first uv release with the fix
RUSTUP_FIXED=1.29.2     # first rustup release with the fix
JAVA_PROBE_OK=0         # 1 once a Java probe class has been compiled
PLAN=$'\n'              # fixes this script can apply: kind|target lines (see plan_add)

# ---------------------------------------------------------------- helpers

log_cmd() { [ "$VERBOSE" -ge 2 ] && printf '%s  $ %s%s\n' "$C_DIM" "$*" "$C_OFF"; return 0; }

# Under --verbose, show (then clear) any raw errors a probe wrote to $TMP/err.
show_err() {
  [ "$VERBOSE" -ge 2 ] && [ -s "$TMP/err" ] && sed 's/^/  /' "$TMP/err"
  : > "$TMP/err"
  return 0
}

# run_to SECS CMD... : run a command, killing it after SECS seconds (no coreutils timeout needed).
run_to() {
  local secs=$1 pid wd rc
  shift
  "$@" &
  pid=$!
  ( sleep "$secs"; kill "$pid" 2>/dev/null ) >/dev/null 2>&1 &
  wd=$!
  wait "$pid" 2>/dev/null
  rc=$?
  kill "$wd" 2>/dev/null
  wait "$wd" 2>/dev/null
  return $rc
}

ENV_CA_VARS="SSL_CERT_FILE SSL_CERT_DIR CURL_CA_BUNDLE REQUESTS_CA_BUNDLE PIP_CERT GIT_SSL_CAINFO GIT_SSL_CAPATH NODE_EXTRA_CA_CERTS NODE_USE_SYSTEM_CA"

# env_notes VAR... : "note:" lines for any of the named environment variables that are set.
env_notes() {
  local v val out=
  for v in "$@"; do
    val=${!v}
    [ -n "$val" ] && out="${out:+$out
}    note:    $v=$val"
  done
  printf '%s' "$out"
}

audit_env() {
  local v val any=0 warn=0 out=
  for v in $ENV_CA_VARS; do
    val=${!v}
    if [ -n "$val" ]; then out="${out}  $v=$val"$'\n'; any=1; fi
  done
  for v in NODE_OPTIONS JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS; do
    val=${!v}
    case $val in
      *system-ca*|*extra-ca*|*cert*|*tls*|*trustStore*|*truststore*) out="${out}  $v=$val"$'\n'; any=1 ;;
    esac
  done
  [ -n "${GIT_SSL_NO_VERIFY:-}" ]          && { out="${out}  ${C_RED}WARNING${C_OFF} GIT_SSL_NO_VERIFY is set: git skips certificate checks, so git will report AFFECTED."$'\n'; warn=1; }
  [ "${NODE_TLS_REJECT_UNAUTHORIZED:-}" = 0 ] && { out="${out}  ${C_RED}WARNING${C_OFF} NODE_TLS_REJECT_UNAUTHORIZED=0: Node skips certificate checks, so Node will report AFFECTED."$'\n'; warn=1; }
  [ "${PYTHONHTTPSVERIFY:-}" = 0 ]         && { out="${out}  ${C_RED}WARNING${C_OFF} PYTHONHTTPSVERIFY=0 is set (ignored by the isolated probes, but affects your own Python scripts)."$'\n'; warn=1; }
  if [ "$VERBOSE" -ge 1 ]; then
    section "CA-related environment"
    if [ "$any" -eq 0 ]; then echo "  no CA-related variables set"; else printf '%s' "$out"; fi
    echo "  The probes below inherit this environment, so each result is how the tool behaves in this shell."
    echo
  elif [ "$any" -eq 1 ] || [ "$warn" -eq 1 ]; then
    # compact: only say something if the environment could change the results
    printf '%sCA-related environment (affects the results below):%s\n%s\n' "$C_BLD" "$C_OFF" "$out"
  fi
  return 0
}

# Portable realpath for a file (follows symlinks, no readlink -f needed).
resolve() {
  local p=$1 t d n=0
  while [ -L "$p" ] && [ "$n" -lt 20 ]; do
    t=$(readlink "$p")
    case $t in /*) p=$t ;; *) p=$(dirname "$p")/$t ;; esac
    n=$((n + 1))
  done
  d=$(cd -P "$(dirname "$p")" 2>/dev/null && pwd) || { echo "$p"; return; }
  echo "$d/$(basename "$p")"
}

# plan_add KIND TARGET : record a fix that --fix can apply (deduplicated).
plan_add() {
  case $PLAN in *$'\n'"$1|$2"$'\n'*) return 0 ;; esac
  PLAN="$PLAN$1|$2"$'\n'
}

# Returns 1 if key was already seen, else records it.
first_time() {
  case $SEEN in *$'\n'"$1"$'\n'*) return 1 ;; esac
  SEEN="$SEEN$1"$'\n'
  return 0
}

# ver_ge A B : succeeds if dotted-numeric A >= B (missing parts = 0).
ver_ge() {
  local IFS=. a b i x y max
  a=($1); b=($2)
  max=${#a[@]}; [ "${#b[@]}" -gt "$max" ] && max=${#b[@]}
  i=0
  while [ "$i" -lt "$max" ]; do
    x=${a[$i]:-0}; y=${b[$i]:-0}
    x=${x%%[!0-9]*}; y=${y%%[!0-9]*}
    [ -z "$x" ] && x=0
    [ -z "$y" ] && y=0
    [ "$x" -gt "$y" ] && return 0
    [ "$x" -lt "$y" ] && return 1
    i=$((i + 1))
  done
  return 0
}

# judge: reads "<result> <url>" lines (result = ok|certerr|err) and prints
# trusted | rejected | inconclusive:<why>
judge() {
  local r u ctl= trusted=0 rejected=0 other=0
  while read -r r u; do
    if [ "$u" = "$CONTROL_URL" ]; then ctl=$r; continue; fi
    case $r in
      ok)      trusted=$((trusted + 1)) ;;
      certerr) rejected=$((rejected + 1)) ;;
      *)       other=$((other + 1)) ;;
    esac
  done
  if [ -z "$ctl" ]; then echo "inconclusive:probe produced no result"; return; fi
  if [ "$ctl" = certerr ]; then echo "inconclusive:control host ($CONTROL_URL) also failed certificate checks - this tool has no usable CA bundle, or a proxy intercepts TLS"; return; fi
  if [ "$ctl" != ok ]; then echo "inconclusive:control host ($CONTROL_URL) unreachable - network or proxy problem"; return; fi
  if [ "$trusted" -gt 0 ]; then echo trusted; return; fi
  if [ "$rejected" -gt 0 ] && [ "$other" -eq 0 ]; then echo rejected; return; fi
  echo "inconclusive:test hosts unreachable or failed for a non-certificate reason"
}

# combine_probe V... : overall verdict from several probe verdicts (empty ones ignored).
# Any trusted wins; otherwise any rejected; otherwise the first non-skipped verdict.
combine_probe() {
  local v first= rej=0
  for v in "$@"; do
    case $v in
      "")       ;;
      trusted*) echo trusted; return ;;
      rejected) rej=1 ;;
      skipped*) ;;
      *)        [ -z "$first" ] && first=$v ;;
    esac
  done
  if [ "$rej" -eq 1 ]; then echo rejected; return; fi
  echo "${first:-$1}"
}

describe_probe() {
  case $1 in
    trusted)       echo "AFFECTED - connected to a host using the compromised chain" ;;
    rejected)      echo "protected - certificate rejected" ;;
    skipped*)      echo "skipped (${1#skipped:})" ;;
    inconclusive*) echo "inconclusive - ${1#inconclusive:}" ;;
    *)             echo "$1" ;;
  esac
}

describe_version() {
  case $1 in
    ok)      echo "up to date" ;;
    behind)  echo "BEHIND" ;;
    nofix)   echo "NO FIX for this release line" ;;
    na)      echo "n/a" ;;
    *)       echo "could not determine" ;;
  esac
}

# report TOOL PATH VERSION VCHECK VNOTE PROBE [EXTRA-LINES]
report() {
  local tool=$1 path=$2 ver=$3 vc=$4 vn=$5 pr=$6 extra=${7:-} status col vtxt fx
  case $pr in
    trusted)  status=AFFECTED ;;
    rejected) status=OK ;;
    *) case $vc in
         behind|nofix) status=LIKELY-AFFECTED ;;
         ok)           status=LIKELY-OK ;;
         *)            status=UNKNOWN ;;
       esac ;;
  esac
  fx=$FIX
  [ -z "$fx" ] && fx="      (no specific guidance - see https://emudhra.we-have-a-problem.com/)"$'\n'
  local first_fix
  if [ -n "$FIXC" ]; then
    first_fix=$FIXC
  else
    first_fix=$(printf '%s' "$fx" | sed -n '1s/^ *//p')
    if [ "$(printf '%s' "$fx" | grep -c .)" -gt 1 ]; then first_fix="$first_fix ... (-v for the rest)"; fi
  fi
  case $status in
    AFFECTED|LIKELY-AFFECTED)
      N_BAD=$((N_BAD + 1)); col=$C_RED
      [ "$FIXSYS" = 1 ] && { NEED_SYS=1; plan_add sys system; }
      [ "$FIXPIP" = 1 ] && { NEED_PIPMAC=1; plan_add macpip /usr/bin/python3; }
      GUIDE="${GUIDE}  - ${tool} ${ver}"$'\n'"    ${path}"$'\n'"${fx}"$'\n'
      CGUIDE="${CGUIDE}  - ${tool} ${ver}: ${first_fix}"$'\n' ;;
    OK|LIKELY-OK)
      N_OK=$((N_OK + 1)); col=$C_GRN
      if [ "$status" = OK ] && { [ "$vc" = behind ] || [ "$vc" = nofix ]; }; then
        ADVISE="${ADVISE}  - ${tool} ${ver}"$'\n'"    ${path}"$'\n'"${fx}"$'\n'
        CADVISE="${CADVISE}  - ${tool} ${ver}: ${first_fix}"$'\n'
      fi ;;
    *)
      N_UNK=$((N_UNK + 1)); col=$C_YEL ;;
  esac
  FIX=; FIXC=; FIXSYS=0; FIXPIP=0
  vtxt=$(describe_version "$vc")
  [ -n "$vn" ] && vtxt="$vtxt - $vn"
  if [ "$VERBOSE" -ge 1 ]; then
    printf '%s%s[%s]%s %s %s\n' "$C_BLD" "$col" "$status" "$C_OFF" "$tool" "$ver"
    printf '    path:    %s\n' "$path"
    printf '    version: %s\n' "$vtxt"
    printf '    probe:   %s\n' "$(describe_probe "$pr")"
    [ -n "$extra" ] && printf '%s\n' "$extra"
    echo
  else
    printf '%s%s[%s]%s %s %s' "$C_BLD" "$col" "$status" "$C_OFF" "$tool" "$ver"
    printf '  %s%s%s' "$C_DIM" "$(compact_path "$path")" "$C_OFF"
    local why
    why=$(compact_why "$status" "$pr" "$vc" "$vn")
    [ -n "$why" ] && printf '  - %s' "$why"
    echo
  fi
}

# compact_path PATH : shorten $HOME to ~ and trim very long paths.
compact_path() {
  local p=$1
  case $p in "$HOME"/*) p="~/${p#"$HOME"/}" ;; esac
  printf '%s' "$p"
}

# compact_why STATUS PROBE VC VN : the one reason worth showing next to a status.
compact_why() {
  local status=$1 pr=$2 vc=$3 vn=$4
  vn=${vn%% (page lists*}
  case $status in
    AFFECTED)
      case $vc in behind|nofix) echo "trusts the compromised chain; also behind ($vn)" ;; *) echo "trusts the compromised chain" ;; esac ;;
    OK)
      case $vc in behind|nofix) echo "rejects the chain, but older than the fixed release ($vn)" ;; *) echo "rejects the chain" ;; esac ;;
    LIKELY-AFFECTED) echo "version-only: $vn" ;;
    LIKELY-OK)       echo "version-only: $vn" ;;
    *)               case $pr in inconclusive*) echo "${pr#inconclusive:}" | cut -c1-90 ;; skipped*) echo "${pr#skipped:}" ;; esac ;;
  esac
}

section() { printf '%s== %s ==%s\n' "$C_BLD" "$1" "$C_OFF"; }

# Compact mode helpers. In the default (compact) output, tools that are not installed are
# collected into one line, and each section header is only printed if the tool was found.
MISSING=
CUR_SECTION=
# audit_start NAME : begin a tool's audit. Verbose mode prints the header immediately; compact mode defers it.
audit_start() {
  CUR_SECTION=$1
  [ "$VERBOSE" -ge 1 ] && section "$1"
  return 0
}
# audit_none [TEXT] : the tool was not found. Verbose keeps the old per-section message; compact records it.
audit_none() {
  if [ "$VERBOSE" -ge 1 ]; then
    echo "  ${1:-not found}"; echo
  else
    MISSING="${MISSING:+$MISSING, }$CUR_SECTION"
  fi
  return 0
}

# ----------------------------------------------------------- probe programs

cat > "$TMP/py_probe.py" <<'EOF'
import sys, ssl

def meta(name):
    try:
        import importlib.metadata as m
        return m.version(name)
    except Exception:
        return ""

mode = sys.argv[1]
if mode == "info":
    print("pyver=%d.%d.%d" % sys.version_info[:3])
    print("certifi=" + meta("certifi"))
    print("pip=" + meta("pip"))
    print("cafile=" + str(ssl.get_default_verify_paths().cafile))
    print("openssl=" + ssl.OPENSSL_VERSION)
else:
    import urllib.request, urllib.error
    urls = sys.argv[2:]
    if mode == "certifi":
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    elif mode == "cafile":
        ctx = ssl.create_default_context(cafile=sys.argv[2])
        urls = sys.argv[3:]
    else:
        ctx = ssl.create_default_context()
    for u in urls:
        try:
            urllib.request.urlopen(u, timeout=10, context=ctx).read(1)
            r = "ok"
        except urllib.error.HTTPError:
            r = "ok"
        except Exception as e:
            r = "certerr" if "CERTIFICATE_VERIFY_FAILED" in str(e) else "err"
            sys.stderr.write("    error: %s\n" % e)
        print(r, u)
EOF

mkdir -p "$TMP/go"
cat > "$TMP/go/probe.go" <<'EOF'
package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	c := &http.Client{Timeout: 10 * time.Second}
	for _, u := range os.Args[1:] {
		r := "ok"
		resp, err := c.Get(u)
		if err != nil {
			if strings.Contains(err.Error(), "x509:") {
				r = "certerr"
			} else {
				r = "err"
			}
		} else {
			resp.Body.Close()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "    error:", err)
		}
		fmt.Println(r, u)
	}
}
EOF

mkdir -p "$TMP/java-src" "$TMP/java-cls"
cat > "$TMP/java-src/EmudhraProbe.java" <<'EOF'
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;

public class EmudhraProbe {
    public static void main(String[] args) {
        for (String u : args) {
            String r;
            try {
                HttpsURLConnection c = (HttpsURLConnection) new URL(u).openConnection();
                c.setConnectTimeout(10000);
                c.setReadTimeout(10000);
                c.getResponseCode();
                r = "ok";
            } catch (SSLException e) {
                boolean cert = false;
                for (Throwable t = e; t != null; t = t.getCause()) {
                    if (t instanceof java.security.cert.CertificateException
                            || t instanceof java.security.cert.CertPathValidatorException
                            || String.valueOf(t.getMessage()).contains("PKIX")) {
                        cert = true;
                    }
                }
                r = cert ? "certerr" : "err";
            } catch (Exception e) {
                r = "err";
            }
            System.out.println(r + " " + u);
        }
    }
}
EOF

# ------------------------------------------------------------------- curl

# curl_probe_all CURL : prints "<result> <url>" for the control and test hosts.
# Exit codes: 35/51/58/59/60/77/82/83/90/91 are TLS/certificate failures.
curl_probe_all() {
  local u rc
  for u in $CONTROL_URL $BAD_URLS; do
    "$1" -q -sS -o /dev/null --max-time 10 "$u" >/dev/null 2>&1
    rc=$?
    case $rc in
      0)                             echo "ok $u" ;;
      35|51|58|59|60|77|82|83|90|91) echo "certerr $u" ;;
      *)                             echo "err $u" ;;
    esac
  done
}

audit_curl() {
  audit_start "curl"
  local found=0 c key vline ver tls out res env_note
  local cands
  cands=$(
    { type -ap curl 2>/dev/null
      for c in /usr/bin/curl /opt/homebrew/opt/curl/bin/curl /usr/local/opt/curl/bin/curl \
               /home/linuxbrew/.linuxbrew/opt/curl/bin/curl; do
        [ -x "$c" ] && echo "$c"
      done; } | awk '!s[$0]++'
  )
  for c in $cands; do
    [ -x "$c" ] || continue
    key="curl:$(resolve "$c")"
    first_time "$key" || continue
    found=1
    vline=$("$c" --version 2>/dev/null | head -1)
    ver=$(printf '%s\n' "$vline" | awk '{print $2}')
    tls=$(printf '%s\n' "$vline" | sed -n 's/.*libcurl\/[^ ]* (\([^)]*\)).*/\1/p')
    [ -z "$tls" ] && tls=$(printf '%s\n' "$vline" | sed -n 's/.*libcurl\/[^ ]* \([^ ]*\).*/\1/p')

    if [ "$NO_NETWORK" -eq 1 ]; then
      res="skipped:--no-network"
    else
      log_cmd "$c -q -sS --max-time 10 -o /dev/null <url>   (control + test hosts)"
      out=$(curl_probe_all "$c")
      res=$(printf '%s\n' "$out" | judge)
    fi
    env_note=$(env_notes CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR)
    [ "${res%%:*}" = trusted ] && fix_curl "$c"
    report "curl" "$c" "${ver:-?} (TLS: ${tls:-?})" na "no fixed curl version; depends on the CA bundle/OS trust store in use" "$res" "$env_note"
  done
  [ "$found" -eq 0 ] && audit_none
}

# --------------------------------------------------------------------- Go

# Sets VC / VN for a Go version like 1.26.4
check_go_version() {
  local v=$1 fix
  v=${v%%[!0-9.]*}
  if [ -z "$v" ]; then VC=unknown; VN=; return; fi
  FIXV=
  case $v in
    1.27|1.27.*) fix=1.27.3 ;;
    1.26|1.26.*) fix=1.26.10 ;;
    *)
      if ver_ge "$v" 1.28; then VC=ok; VN="newer than the fixed lines (1.26.10, 1.27.3)"
      else VC=nofix; VN="fixes only published for 1.26.10 and 1.27.3"; FIXV="1.26.10 or 1.27.3"; fi
      return ;;
  esac
  FIXV=$fix
  if ver_ge "$v" "$fix"; then VC=ok; VN="fixed in $fix"; else VC=behind; VN="fixed in $fix"; fi
}

audit_go() {
  audit_start "Go"
  local found=0 g key gv v res out d
  local cands
  cands=$(
    { type -ap go 2>/dev/null
      for d in /usr/local/go/bin/go /opt/homebrew/opt/go/libexec/bin/go /usr/local/opt/go/libexec/bin/go \
               "$HOME"/sdk/go*/bin/go "$HOME"/go/pkg/mod/golang.org/toolchain@*/bin/go \
               "$HOME"/.asdf/installs/golang/*/go/bin/go "$HOME"/.local/share/mise/installs/go/*/bin/go; do
        [ -x "$d" ] && echo "$d"
      done; } | awk '!s[$0]++'
  )
  for g in $cands; do
    [ -x "$g" ] || continue
    key="go:$(resolve "$g")"
    first_time "$key" || continue
    found=1
    gv=$(GOTOOLCHAIN=local "$g" version 2>/dev/null | awk '{print $3}')
    v=${gv#go}
    check_go_version "$v"
    if [ "$NO_NETWORK" -eq 1 ]; then
      res="skipped:--no-network"
    else
      log_cmd "(cd <tmp> && GOTOOLCHAIN=local $g run probe.go <urls>)"
      out=$(cd "$TMP/go" && GOTOOLCHAIN=local GOFLAGS= GOWORK=off "$g" run probe.go $CONTROL_URL $BAD_URLS 2>"$TMP/err")
      show_err
      res=$(printf '%s\n' "$out" | judge)
    fi
    fix_go "$g" "$res"
    report "Go" "$g" "${gv:-?}" "$VC" "$VN" "$res"
  done
  [ "$found" -eq 0 ] && audit_none
}

# ----------------------------------------------------------------- Python

python_candidates() {
  local IFS=: d p base
  for d in $PATH /opt/homebrew/bin /usr/local/bin "$HOME"/.pyenv/versions/*/bin \
           /Library/Frameworks/Python.framework/Versions/*/bin \
           "$HOME"/.asdf/installs/python/*/bin "$HOME"/.local/share/mise/installs/python/*/bin; do
    [ -d "$d" ] || continue
    for p in "$d"/python*; do
      base=${p##*/}
      case $base in
        python|python[0-9]|python[0-9].[0-9]|python[0-9].[0-9][0-9]) [ -x "$p" ] && echo "$p" ;;
      esac
    done
  done
}

# pip_probe_all PYTHON : pip's own TLS behaviour. Asks each host's /simple/ index for a package
# that does not exist; any HTTP answer (even 404) means the TLS handshake was accepted.
pip_probe_all() {
  local u rc out
  for u in $CONTROL_URL $BAD_URLS; do
    rm -rf "$TMP/pipdl"
    run_to 40 "$1" -I -m pip download --no-deps --no-input --disable-pip-version-check \
      --retries 0 --timeout 10 -d "$TMP/pipdl" --index-url "${u}simple/" emudhra-probe-does-not-exist \
      >"$TMP/pipout" 2>&1 </dev/null
    rc=$?
    if grep -qi -E 'CERTIFICATE_VERIFY_FAILED|certificate verify failed|SSLCertVerificationError|problem confirming the ssl certificate|SSLError' "$TMP/pipout"; then
      out=certerr
    elif [ "$rc" -ge 128 ] || grep -qi -E 'NewConnectionError|Name or service not known|nodename nor servname|Temporary failure|ConnectTimeout|ReadTimeout|ProxyError|Connection refused|timed out|No module named' "$TMP/pipout"; then
      out=err
    else
      out=ok
    fi
    if [ "$out" != ok ]; then
      { grep -i -m1 -E 'CERTIFICATE_VERIFY_FAILED|certificate verify failed|SSLError|ssl certificate|NewConnection|timed out|ProxyError|No module' "$TMP/pipout" || tail -1 "$TMP/pipout"; } |
        cut -c1-220 | sed 's/^/    error: /' >> "$TMP/err"
    fi
    echo "$out $u"
  done
}

audit_python() {
  audit_start "Python"
  local found=0 p key info pv cf pip cafile ossl res1 res2 res3 res vc vn out extra envn
  local cands
  cands=$(python_candidates | awk '!s[$0]++')
  for p in $cands; do
    # macOS /usr/bin/python3 is a stub that prompts to install the Command Line Tools.
    if [ "$p" = /usr/bin/python3 ] && [ "$(uname)" = Darwin ] && ! xcode-select -p >/dev/null 2>&1; then
      continue
    fi
    key="python:$(resolve "$p")"
    first_time "$key" || continue
    found=1
    info=$("$p" -I "$TMP/py_probe.py" info 2>/dev/null)
    pv=$(printf '%s\n' "$info" | sed -n 's/^pyver=//p')
    if [ -z "$pv" ]; then
      report "Python" "$p" "?" unknown "" "inconclusive:interpreter could not run the probe (Python 3.8+ needed)"
      continue
    fi
    [ -z "$PYBIN" ] && PYBIN=$p
    cf=$(printf '%s\n' "$info" | sed -n 's/^certifi=//p')
    pip=$(printf '%s\n' "$info" | sed -n 's/^pip=//p')
    cafile=$(printf '%s\n' "$info" | sed -n 's/^cafile=//p')
    ossl=$(printf '%s\n' "$info" | sed -n 's/^openssl=//p')

    # Version check: certifi >= 2026.10.19, pip >= 26.2.2 (CPython itself has no listed fix;
    # it uses the OS/OpenSSL trust store, which the probe covers).
    vc=na; vn=
    if [ -n "$cf" ]; then
      if ver_ge "$cf" 2026.10.19; then vn="certifi $cf ok"; vc=ok; else vn="certifi $cf < 2026.10.19"; vc=behind; fi
    fi
    if [ -n "$pip" ]; then
      if ver_ge "$pip" 26.2.2; then
        vn="${vn:+$vn; }pip $pip ok"; [ "$vc" = na ] && vc=ok
      else
        vn="${vn:+$vn; }pip $pip < 26.2.2"; vc=behind
      fi
    fi

    if [ "$NO_NETWORK" -eq 1 ]; then
      res="skipped:--no-network"; res1=$res; res2=; res3=
    else
      log_cmd "$p -I <tmp>/py_probe.py default <urls>"
      out=$("$p" -I "$TMP/py_probe.py" default $CONTROL_URL $BAD_URLS 2>"$TMP/err")
      show_err
      res1=$(printf '%s\n' "$out" | judge)
      res2=
      if [ -n "$cf" ]; then
        log_cmd "$p -I <tmp>/py_probe.py certifi <urls>"
        out=$("$p" -I "$TMP/py_probe.py" certifi $CONTROL_URL $BAD_URLS 2>"$TMP/err")
        show_err
        res2=$(printf '%s\n' "$out" | judge)
      fi
      if "$p" -I -m pip --version >/dev/null 2>&1 </dev/null; then
        log_cmd "$p -I -m pip download --no-deps --index-url <host>/simple/ emudhra-probe-does-not-exist"
        out=$(pip_probe_all "$p")
        show_err
        res3=$(printf '%s\n' "$out" | judge)
      else
        res3="skipped:pip is not installed for this interpreter"
      fi
      res=$(combine_probe "$res1" "$res2" "$res3")
    fi
    extra="    detail:  default trust store: $(describe_probe "$res1")"
    [ -n "$res2" ] && extra="$extra
             certifi bundle:      $(describe_probe "$res2")"
    [ -n "$res3" ] && extra="$extra
             pip download:        $(describe_probe "$res3")"
    extra="$extra
             OpenSSL cafile:      ${cafile:-none}  (${ossl:-?})"
    envn=$(env_notes SSL_CERT_FILE SSL_CERT_DIR REQUESTS_CA_BUNDLE PIP_CERT)
    [ -n "$envn" ] && extra="$extra
$envn"
    fix_python "$p" "$cafile" "$res1" "$res2" "$vc" "$res3"
    report "Python" "$p" "$pv" "$vc" "$vn" "$res" "$extra"
  done
  [ "$found" -eq 0 ] && audit_none
}

# ------------------------------------------------------------------- Java

# Sets VC / VN for a java.version string (e.g. 11.0.32, 1.8.0_504, 21.0.12+1)
check_java_version() {
  local v=$1 major fix upd
  case $v in
    1.8.0_*)
      upd=${v#1.8.0_}; upd=${upd%%[!0-9]*}
      if [ -n "$upd" ] && [ "$upd" -ge 511 ]; then VC=ok; else VC=behind; fi
      VN="fixed in 8u511"; FIXV=8u511
      return ;;
  esac
  FIXV=
  major=${v%%[!0-9]*}
  v=${v%%[!0-9.]*}
  case $major in
    11) fix=11.0.33 ;;
    17) fix=17.0.21 ;;
    21) fix=21.0.13 ;;
    25) fix=25.0.5 ;;
    27) fix=27.0.1 ;;
    "") VC=unknown; VN=; return ;;
    *)
      if [ "$major" -gt 27 ]; then VC=ok; VN="newer than the fixed lines"
      else VC=nofix; VN="fixes only published for 8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1"
        FIXV="a fixed release of a supported line (8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1)"; fi
      return ;;
  esac
  FIXV=$fix
  # The page lists e.g. 11.0.33.0.2; compare on the first three components.
  if ver_ge "$v" "$fix"; then VC=ok; else VC=behind; fi
  VN="fixed in $fix (page lists $fix.0.2)"
}

java_candidates() {
  local p d
  # Testing aid: EMUDHRA_JAVA_HOMES (space-separated) replaces normal discovery.
  if [ -n "${EMUDHRA_JAVA_HOMES:-}" ]; then
    for d in $EMUDHRA_JAVA_HOMES; do echo "$d"; done
    return
  fi
  [ -n "${JAVA_HOME:-}" ] && echo "$JAVA_HOME"
  p=$(command -v java 2>/dev/null)
  [ -n "$p" ] && dirname "$(dirname "$(resolve "$p")")"
  [ -x /usr/libexec/java_home ] && /usr/libexec/java_home -V 2>&1 | sed -n 's/.*[[:space:]]\(\/.*\)$/\1/p'
  for d in /Library/Java/JavaVirtualMachines/*/Contents/Home \
           "$HOME"/Library/Java/JavaVirtualMachines/*/Contents/Home \
           /usr/lib/jvm/* /usr/java/* /opt/java/* /opt/jdk* \
           "$HOME"/.sdkman/candidates/java/* "$HOME"/.asdf/installs/java/* \
           "$HOME"/.local/share/mise/installs/java/* "$HOME"/.jdks/* \
           /opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home \
           /usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home \
           /home/linuxbrew/.linuxbrew/opt/openjdk*/libexec; do
    [ -d "$d" ] && echo "$d"
  done
}

audit_java() {
  audit_start "Java (JRE/JDK)"
  local homes="" h hp key found=0 jv vendor res out j
  for h in $(java_candidates | awk '!s[$0]++'); do
    [ -x "$h/bin/java" ] || continue
    hp=$(cd -P "$h" 2>/dev/null && pwd) || continue
    first_time "java:$hp" || continue
    homes="$homes$hp"$'\n'
  done

  # Compile the probe once with any javac (targeting Java 8 so every JRE can run it).
  local compiled=0 jc
  if [ "$NO_NETWORK" -eq 0 ]; then
    for h in $homes; do
      jc="$h/bin/javac"
      [ -x "$jc" ] || continue
      if "$jc" --release 8 -d "$TMP/java-cls" "$TMP/java-src/EmudhraProbe.java" >/dev/null 2>&1 ||
         "$jc" -source 8 -target 8 -d "$TMP/java-cls" "$TMP/java-src/EmudhraProbe.java" >/dev/null 2>&1; then
        compiled=1; JAVA_PROBE_OK=1; log_cmd "$jc --release 8 -d <tmp> EmudhraProbe.java"; break
      fi
    done
  fi

  for h in $homes; do
    j="$h/bin/java"
    jv=$("$j" -version 2>&1 | sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -1)
    if [ -z "$jv" ]; then continue; fi
    found=1
    vendor=
    [ -r "$h/release" ] && vendor=$(sed -n 's/^IMPLEMENTOR="\(.*\)"/\1/p' "$h/release" | head -1)
    check_java_version "$jv"
    if [ "$NO_NETWORK" -eq 1 ]; then
      res="skipped:--no-network"
    elif [ "$compiled" -eq 0 ]; then
      res="skipped:no javac found to build the probe - version check only"
    else
      log_cmd "$j -cp <tmp> EmudhraProbe <urls>"
      out=$("$j" -cp "$TMP/java-cls" EmudhraProbe $CONTROL_URL $BAD_URLS 2>/dev/null)
      res=$(printf '%s\n' "$out" | judge)
    fi
    fix_java "$h" "$res"
    report "Java" "$h" "$jv${vendor:+ ($vendor)}" "$VC" "$VN" "$res"
  done
  [ "$found" -eq 0 ] && audit_none
}

# ------------------------------------------------- guidance helpers (print only)

# fix LINE : add a guidance line for the item about to be reported.
fix() { FIX="${FIX}      $1"$'\n'; }

# fixc TEXT : the single line shown for this item in the compact (default) output.
# Falls back to the first fix() line if a fix_* function does not set one.
FIXC=
fixc() { [ -z "$FIXC" ] && FIXC=$1; return 0; }

# where_from PATH : how a tool was probably installed, to tailor upgrade advice.
where_from() {
  case $1 in
    */.nvm/*|*/nvm/versions/node/*) echo nvm ;;
    */.volta/*)    echo volta ;;
    */fnm/*)       echo fnm ;;
    */.asdf/*)     echo asdf ;;
    */mise/*)      echo mise ;;
    */.sdkman/*)   echo sdkman ;;
    */.pyenv/*)    echo pyenv ;;
    */.cargo/*)    echo cargo ;;
    */Cellar/*|/opt/homebrew/*|/usr/local/opt/*|*/.linuxbrew/*) echo brew ;;
    /usr/local/go/*) echo golang ;;
    /Applications/*|*/Applications/*) echo app ;;
    *)             echo other ;;
  esac
}

# vcmp CURRENT FIXED : sets VC/VN/FIXV for tools with a single fixed version.
vcmp() {
  FIXV=$2
  if [ -z "$1" ]; then VC=unknown; VN=; return; fi
  if ver_ge "$1" "$2"; then VC=ok; else VC=behind; fi
  VN="fixed in $2"
}

fix_curl() {
  case $(where_from "$1") in
    brew) fixc "brew upgrade curl ca-certificates"; fix "brew update && brew upgrade curl ca-certificates" ;;
    *)
      fixc "patch the system CA bundle (or use Homebrew's curl)"
      if [ "$1" = /usr/bin/curl ] && [ "$(uname)" = Darwin ]; then
        fix "Apple's curl reads /etc/ssl/cert.pem and does not check revocation."
        fix "Apply the macOS bundle workaround (System trust store, below), or install Homebrew's curl"
        fix "and upgrade ca-certificates: brew install curl && brew upgrade ca-certificates"
      else
        fix "Update the OS ca-certificates package, or the CA bundle this curl uses (curl CA bundle >= 2026-10-20)."
      fi
      FIXSYS=1 ;;
  esac
}

fix_go() {
  [ "${2%%:*}" = trusted ] && { fix "This Go build trusts the compromised chain via the OS trust store: see System trust store below."; FIXSYS=1; }
  { [ "$VC" = behind ] || [ "$VC" = nofix ]; } || return 0
  fixc "upgrade Go to $FIXV or later (https://go.dev/dl/)"
  case $(where_from "$1") in
    brew)   fix "Upgrade Go to $FIXV or later: brew upgrade go" ;;
    mise)   fix "Upgrade Go to $FIXV or later: mise use -g go@${FIXV%% *}" ;;
    asdf)   fix "Upgrade Go to $FIXV or later: asdf install golang ${FIXV%% *}" ;;
    golang) fix "Upgrade Go to $FIXV or later: download from https://go.dev/dl/ and replace /usr/local/go" ;;
    *)      fix "Upgrade Go to $FIXV or later (https://go.dev/dl/). Projects can also pin it with 'toolchain' in go.mod." ;;
  esac
}

fix_python() {
  local p=$1 cafile=$2 r1=$3 r2=$4 vc=$5 r3=$6
  # compact line: most useful single action, in priority order
  if [ "${r1%%:*}" = trusted ]; then
    case $cafile in
      */etc/ca-certificates/*|*/etc/openssl*|*/Cellar/*) fixc "brew upgrade ca-certificates (this Python uses Homebrew's bundle)" ;;
      ""|None) ;;
      *) fixc "patch the system CA bundle ($cafile)" ;;
    esac
  fi
  [ "${r2%%:*}" = trusted ] && fixc "pip install --upgrade 'certifi>=2026.10.19'"
  [ "${r3%%:*}" = trusted ] && fixc "upgrade pip to 26.2.2 or later"
  [ "$vc" = behind ] && fixc "$p -m pip install --upgrade 'pip>=26.2.2' 'certifi>=2026.10.19'"
  if [ "${r1%%:*}" = trusted ]; then
    case $cafile in
      */etc/ca-certificates/*|*/etc/openssl*|*/Cellar/*)
        fix "Uses Homebrew's CA bundle: brew update && brew upgrade ca-certificates" ;;
      ""|None)
        fix "No default CA file is configured for this Python." ;;
      *)
        fix "Reads the OS CA bundle ($cafile): see System trust store below."; FIXSYS=1 ;;
    esac
  fi
  if [ "${r2%%:*}" = trusted ]; then
    fix "The certifi bundle trusts the compromised chain: python3 -m pip install --upgrade 'certifi>=2026.10.19'"
    fix "(use a virtualenv or pipx if the environment is externally managed)"
  fi
  if [ "${r3%%:*}" = trusted ]; then
    fix "pip itself accepts the compromised chain (it carries its own CA bundle): upgrade it to 26.2.2 or later."
    fix "(PIP_CERT=/path/to/patched-bundle.pem is a stop-gap.)"
  fi
  if [ "$vc" = behind ]; then
    fix "Upgrade pip and certifi: $p -m pip install --upgrade 'pip>=26.2.2' 'certifi>=2026.10.19'"
  fi
  if [ "$p" = /usr/bin/python3 ] && [ "$(uname)" = Darwin ]; then
    if [ "${r1%%:*}" = trusted ] || [ "${r3%%:*}" = trusted ] || [ "$vc" = behind ]; then
      fix "Apple's built-in pip: see Built-in pip (macOS) below."; FIXPIP=1
    fi
  fi
}

AWK_JAVA_ALIASES='/^Alias name:/{a=substr($0,13)} /^Owner:/ && /CN=(AAA Certificate Services|emSign ECC Root CA - G3)/{print a}'

# java_cacerts JAVA_HOME : path of the JDK's default trust store, if present.
java_cacerts() {
  if [ -f "$1/lib/security/cacerts" ]; then echo "$1/lib/security/cacerts"
  elif [ -f "$1/jre/lib/security/cacerts" ]; then echo "$1/jre/lib/security/cacerts"; fi
}

# java_affected_aliases KEYTOOL CACERTS : read-only; aliases whose subject is one of the two roots
# the advisory says to distrust. Matching on subject (not alias) because aliases differ by vendor.
java_affected_aliases() {
  "$1" -J-Duser.language=en -list -v -keystore "$2" -storepass changeit 2>/dev/null </dev/null | awk "$AWK_JAVA_ALIASES"
}

# java_upgrade_hint HOW : where to look for a fixed JDK, for the compact guidance line.
java_upgrade_hint() {
  case $1 in
    sdkman) echo "sdk list java" ;;
    brew)   echo "brew upgrade openjdk" ;;
    *)      echo "your JDK vendor" ;;
  esac
}

fix_java() {
  local h=$1 res=$2 how cac kt n
  how=$(where_from "$h")
  fixc "upgrade to Java $FIXV or later ($(java_upgrade_hint "$how"))"
  case $how in
    sdkman) fix "sdk list java   # pick a build at or above $FIXV, then:"
            fix "sdk install java <identifier> && sdk default java <identifier>"
            fix "sdk uninstall java $(basename "$h")   # once nothing depends on it" ;;
    brew)   fix "brew update && brew upgrade openjdk   # or: brew upgrade --cask temurin" ;;
    *)
      case $h in
        /Library/Java/*|*/Library/Java/*) fix "Install the vendor's latest update for this line ($FIXV or later) and remove the old JDK." ;;
        /usr/lib/jvm/*|/usr/java/*)       fix "Upgrade the distro's JDK/JRE package (apt/dnf/zypper) to $FIXV or later." ;;
        *)                                fix "Install $FIXV or later from your JDK vendor and point JAVA_HOME at it." ;;
      esac ;;
  esac
  fix "Java uses its own cacerts/distrust list, so OS-level workarounds do not help; update the JDK."
  cac=$(java_cacerts "$h")
  kt=$h/bin/keytool
  if [ -n "$cac" ] && [ -x "$kt" ]; then
    n=$(java_affected_aliases "$kt" "$cac" | grep -c .)
    if [ "$n" -gt 0 ]; then
      [ "${res%%:*}" = trusted ] && plan_add java "$h"
      fix "Stop-gap if no fixed build is available yet (this JDK's cacerts holds $n of the roots to distrust;"
      fix "the script has not tested that removing them stops the probe connecting):"
      fix "  R=\"$cac\"      # prefix commands with sudo if you cannot write to it"
      fix "  cp -p \"\$R\" \"\$R.pre-emudhra\""
      fix "  \"$kt\" -J-Duser.language=en -list -v -keystore \"\$R\" -storepass changeit | awk '$AWK_JAVA_ALIASES' |"
      fix "    while IFS= read -r a; do \"$kt\" -delete -alias \"\$a\" -keystore \"\$R\" -storepass changeit; done"
      fix "  Side effects: Java will reject sites chained to those roots (some Sectigo-issued certificates), and a"
      fix "  JDK upgrade restores them. Undo with: cp -p \"\$R.pre-emudhra\" \"\$R\""
    elif [ "${res%%:*}" = trusted ]; then
      fix "The default cacerts has none of the roots to distrust (or its password is not 'changeit'); check for a"
      fix "custom truststore: -Djavax.net.ssl.trustStore, JAVA_TOOL_OPTIONS or JDK_JAVA_OPTIONS."
    fi
  fi
}

# --------------------------------------------------------------- more probes

cat > "$TMP/node_probe.js" <<'EOF'
const https = require('https');
const urls = process.argv.slice(2);
let i = 0;
function next() {
  if (i >= urls.length) return;
  const u = urls[i++];
  const req = https.get(u, { timeout: 10000 }, function (res) {
    res.resume();
    console.log('ok', u);
    next();
  });
  req.on('timeout', function () { req.destroy(new Error('timeout')); });
  req.on('error', function (e) {
    const c = String(e.code || '');
    const cert = /CERT|UNABLE_TO_VERIFY|UNABLE_TO_GET_ISSUER|SELF_SIGNED|DEPTH_ZERO/.test(c);
    console.error('    error: ' + e.message);
    console.log(cert ? 'certerr' : 'err', u);
    next();
  });
}
next();
EOF

cat > "$TMP/deno_probe.js" <<'EOF'
for (const u of Deno.args) {
  try {
    const r = await fetch(u);
    await r.body?.cancel();
    console.log("ok", u);
  } catch (e) {
    const m = String(e);
    console.error("    error: " + m);
    console.log(/certificate|UnknownIssuer|Revoked|invalid peer/i.test(m) ? "certerr" : "err", u);
  }
}
EOF

cat > "$TMP/bun_probe.js" <<'EOF'
const urls = process.argv.slice(2);
for (const u of urls) {
  try {
    const r = await fetch(u);
    await r.arrayBuffer();
    console.log("ok", u);
  } catch (e) {
    const m = String(e) + " " + (e && e.code ? e.code : "");
    console.error("    error: " + m);
    console.log(/CERT|certificate|UNABLE_TO|SELF_SIGNED/i.test(m) ? "certerr" : "err", u);
  }
}
EOF

# runtime_probe BIN ARGS... : run a probe command against control + test hosts.
runtime_probe() {
  if [ "$NO_NETWORK" -eq 1 ]; then PROBE_RES="skipped:--no-network"; return; fi
  local out
  log_cmd "$* <urls>"
  out=$("$@" $CONTROL_URL $BAD_URLS 2>"$TMP/err" </dev/null)
  show_err
  PROBE_RES=$(printf '%s\n' "$out" | judge)
}

# probe_cafile FILE : test a PEM bundle using whichever Python the audit found.
probe_cafile() {
  if [ "$NO_NETWORK" -eq 1 ]; then echo "skipped:--no-network"; return; fi
  if [ -z "$PYBIN" ]; then echo "skipped:no Python available to test this bundle - version check only"; return; fi
  local out
  log_cmd "$PYBIN -I <tmp>/py_probe.py cafile $1 <urls>"
  out=$("$PYBIN" -I "$TMP/py_probe.py" cafile "$1" $CONTROL_URL $BAD_URLS 2>"$TMP/err" </dev/null)
  show_err
  printf '%s\n' "$out" | judge
}

# ------------------------------------------------------------------- Node.js

check_node_version() {
  local v=${1#v} major
  FIXV=
  major=${v%%.*}
  case $major in
    22) FIXV=22.23.4 ;;
    24) FIXV=24.22.1 ;;
    26) FIXV=26.12.1 ;;
    "") VC=unknown; VN=; return ;;
    *)
      if [ "$major" -gt 26 ]; then VC=ok; VN="newer than the fixed lines"
      else VC=nofix; VN="fixes only published for 22.23.4, 24.22.1, 26.12.1"; FIXV="22.23.4, 24.22.1 or 26.12.1"; fi
      return ;;
  esac
  vcmp "$v" "$FIXV"
}

node_candidates() {
  local d
  # Testing aid: EMUDHRA_NODE_BINS names a directory of version folders (like nvm's versions/node) and
  # replaces normal discovery.
  if [ -n "${EMUDHRA_NODE_BINS:-}" ]; then
    for d in "$EMUDHRA_NODE_BINS"/*/bin/node; do [ -x "$d" ] && echo "$d"; done
    return
  fi
  command -v node 2>/dev/null
  # nvm lives in $NVM_DIR when that is set, otherwise ~/.nvm
  for d in "${NVM_DIR:-$HOME/.nvm}"/versions/node/*/bin/node "$HOME"/.volta/tools/image/node/*/bin/node \
           "$HOME"/.local/share/fnm/node-versions/*/installation/bin/node \
           "$HOME"/Library/Application\ Support/fnm/node-versions/*/installation/bin/node \
           "$HOME"/.asdf/installs/nodejs/*/bin/node "$HOME"/.local/share/mise/installs/node/*/bin/node \
           /opt/homebrew/opt/node*/bin/node /usr/local/opt/node*/bin/node /usr/local/bin/node /usr/bin/node; do
    [ -x "$d" ] && echo "$d"
  done
}

# node_upgrade_hint HOW : the install command for the version manager in use, for the compact line.
node_upgrade_hint() {
  case $1 in
    nvm)   echo "nvm install $FIXV" ;;
    volta) echo "volta install node@$FIXV" ;;
    fnm)   echo "fnm install $FIXV" ;;
    mise)  echo "mise use -g node@$FIXV" ;;
    asdf)  echo "asdf install nodejs $FIXV" ;;
    brew)  echo "brew upgrade node" ;;
    *)     echo "https://nodejs.org" ;;
  esac
}

fix_node() {
  local n=$1 how
  how=$(where_from "$n")
  fixc "upgrade Node.js to $FIXV or later ($(node_upgrade_hint "$how"))"
  case $how in
    nvm)   fix "nvm install $FIXV && nvm alias default $FIXV   # then: nvm uninstall $(basename "$(dirname "$(dirname "$n")")")" ;;
    volta) fix "volta install node@$FIXV" ;;
    fnm)   fix "fnm install $FIXV && fnm default $FIXV" ;;
    mise)  fix "mise use -g node@$FIXV" ;;
    asdf)  fix "asdf install nodejs $FIXV && asdf global nodejs $FIXV" ;;
    brew)  fix "brew update && brew upgrade node" ;;
    *)     fix "Install Node.js $FIXV or later (https://nodejs.org/en/download or your package manager)." ;;
  esac
  fix "Node.js uses its own bundled CA list by default, so editing OS bundles does not normally change it"
  fix "(unless NODE_EXTRA_CA_CERTS or --use-system-ca is in play): upgrade the runtime."
  case ${NODE_SYSCA_RES%%:*} in
    rejected)
      fix "Stop-gap: run with --use-system-ca (or NODE_USE_SYSTEM_CA=1) so Node uses the OS trust store."
      fix "Tested here: with that flag Node rejects the chain, because this OS store already blocks it. That only"
      fix "holds while the OS store stays patched, so still upgrade the runtime." ;;
    trusted)
      fix "Tested here: --use-system-ca does not help; Node still accepts the chain with it (it may not apply the"
      fix "OS revocation block). Upgrading the runtime is the fix." ;;
    skipped)
      fix "This Node has no --use-system-ca, so upgrading is the only fix." ;;
  esac
  fix "(Fixed releases: 22.23.4, 24.22.1, 26.12.1.)"
}

audit_node() {
  audit_start "Node.js"
  local found=0 n key v nres extra
  while IFS= read -r n; do
    [ -n "$n" ] && [ -x "$n" ] || continue
    key="node:$(resolve "$n")"
    first_time "$key" || continue
    found=1
    v=$("$n" --version 2>/dev/null </dev/null)
    check_node_version "$v"
    runtime_probe "$n" "$TMP/node_probe.js"
    nres=$PROBE_RES
    NODE_SYSCA_RES=
    if [ "${nres%%:*}" = trusted ]; then
      if "$n" --use-system-ca -e 0 >/dev/null 2>&1 </dev/null; then
        runtime_probe "$n" --use-system-ca "$TMP/node_probe.js"
        NODE_SYSCA_RES=$PROBE_RES
      else
        NODE_SYSCA_RES="skipped:no --use-system-ca"
      fi
    fi
    extra=$(env_notes NODE_EXTRA_CA_CERTS NODE_USE_SYSTEM_CA)
    [ -n "$NODE_SYSCA_RES" ] && extra="${extra:+$extra
}    detail:  with --use-system-ca: $(describe_probe "$NODE_SYSCA_RES")"
    if [ "${nres%%:*}" = trusted ] || [ "$VC" = behind ] || [ "$VC" = nofix ]; then
      fix_node "$n"
      # --fix can upgrade Node when it came from nvm and the major line has a published fix
      # One plan entry per major line, not per binary: a single run installs the fixed release once and then
      # offers every older version of that line for removal. Planning each old binary separately would repeat
      # the whole upgrade (and its prompts) once per version.
      if [ "$(where_from "$n")" = nvm ] && [ "$VC" = behind ]; then plan_node_major "$n"; fi
    fi
    report "Node.js" "$n" "${v:-?}" "$VC" "$VN" "$nres" "$extra"
  done <<EOF
$(node_candidates | awk '!s[$0]++')
EOF
  [ "$found" -eq 0 ] && audit_none
  return 0
}

# --------------------------------------------------------- Deno / Bun (probe)

audit_deno() {
  audit_start "Deno"
  local d v found=0
  while IFS= read -r d; do
    [ -n "$d" ] && [ -x "$d" ] || continue
    first_time "deno:$(resolve "$d")" || continue
    found=1
    v=$("$d" --version 2>/dev/null </dev/null | awk 'NR==1{print $2}')
    vcmp "$v" 2.9.8
    runtime_probe "$d" run --no-prompt --allow-net "$TMP/deno_probe.js"
    { [ "${PROBE_RES%%:*}" = trusted ] || [ "$VC" = behind ]; } && fix "Upgrade Deno to 2.9.8 or later: deno upgrade   (or brew upgrade deno)"
    report "Deno" "$d" "${v:-?}" "$VC" "$VN" "$PROBE_RES"
  done <<EOF
$({ command -v deno 2>/dev/null; ls "$HOME"/.deno/bin/deno /opt/homebrew/bin/deno /usr/local/bin/deno 2>/dev/null; } | awk '!s[$0]++')
EOF
  [ "$found" -eq 0 ] && audit_none
  return 0
}

audit_bun() {
  audit_start "Bun"
  local b v found=0
  while IFS= read -r b; do
    [ -n "$b" ] && [ -x "$b" ] || continue
    first_time "bun:$(resolve "$b")" || continue
    found=1
    v=$("$b" --version 2>/dev/null </dev/null)
    runtime_probe "$b" run "$TMP/bun_probe.js"
    [ "${PROBE_RES%%:*}" = trusted ] && {
      fix "The page lists no fixed Bun release yet (pending). Watch https://emudhra.we-have-a-problem.com/"
      fix "and upgrade as soon as one ships: bun upgrade. Until then avoid Bun for sensitive outbound TLS."
    }
    report "Bun" "$b" "${v:-?}" na "no fixed release yet (listed as pending)" "$PROBE_RES"
  done <<EOF
$({ command -v bun 2>/dev/null; ls "$HOME"/.bun/bin/bun /opt/homebrew/bin/bun /usr/local/bin/bun 2>/dev/null; } | awk '!s[$0]++')
EOF
  [ "$found" -eq 0 ] && audit_none
  return 0
}

# ------------------------------------------- version-only tools (rustup etc.)

# audit_simple LABEL BIN-NAME FIXED UPGRADE-COMMAND [EXTRA-CANDIDATE...]
audit_simple() {
  local label=$1 name=$2 fixed=$3 upg=$4 b v found=0 extra="$5"
  audit_start "$label"
  while IFS= read -r b; do
    [ -n "$b" ] && [ -x "$b" ] || continue
    first_time "$name:$(resolve "$b")" || continue
    found=1
    v=$(version_of "$name" "$b")
    vcmp "$v" "$fixed"
    if [ "$VC" = behind ] && [ "$name" = uv ]; then
      upg=$(uv_upgrade_cmd "$(uv_install_method "$b")")
      plan_add uv "$b"
    fi
    if [ "$VC" = behind ] && [ "$name" = rustup ]; then
      upg=$(rustup_upgrade_cmd "$(rustup_install_method "$b")")
      plan_add rustup "$b"
    fi
    if [ "$VC" = behind ]; then
      fixc "$upg"
      fix "Upgrade $label to $fixed or later: $upg"
      [ "$name" = rustup ] && fix "Also check Rust projects: Cargo.lock should resolve rustls-webpki >= 0.103.16 and webpki-roots >= 1.0.10 (cargo update -p rustls-webpki -p webpki-roots). Upgrading rustup does not do this."
    fi
    report "$label" "$b" "${v:-?}" "$VC" "$VN" "skipped:no safe way to probe this tool's own TLS - version check only"
  done <<EOF
$({ command -v "$name" 2>/dev/null; for b in $extra; do [ -x "$b" ] && echo "$b"; done; } | awk '!s[$0]++')
EOF
  [ "$found" -eq 0 ] && audit_none
  return 0
}

# uv_install_method BIN : standalone | brew | pipx | pip | cargo | mise | asdf | unknown. `uv self update` only works
# for the standalone installer, which leaves a receipt (uv-receipt.json) naming the directory it installed into.
uv_install_method() {
  local b=$1 r d receipt
  r=$(resolve "$b"); d=$(dirname "$b")
  case $b$r in
    */mise/*) echo mise; return ;;
    */.asdf/*) echo asdf; return ;;
    */pipx/venvs/*|*/pipx/shims/*) echo pipx; return ;;
    */Cellar/*|/opt/homebrew/*|/usr/local/opt/*|*/.linuxbrew/*) echo brew; return ;;
  esac
  # pip puts uv in <env>/bin with the package beside it in <env>/lib/python*/site-packages
  if ls -d "$(dirname "$d")"/lib/python*/site-packages/uv >/dev/null 2>&1; then echo pip; return; fi
  receipt="${XDG_CONFIG_HOME:-$HOME/.config}/uv/uv-receipt.json"
  if [ -r "$receipt" ] && grep -q -F "\"$d\"" "$receipt" 2>/dev/null; then echo standalone; return; fi
  case $b in "$HOME"/.cargo/bin/*) echo cargo; return ;; esac
  echo unknown
}

# uv_upgrade_cmd METHOD : the right upgrade command for how uv was installed.
uv_upgrade_cmd() {
  case $1 in
    standalone) echo "uv self update" ;;
    brew)  echo "brew upgrade uv" ;;
    pipx)  echo "pipx upgrade uv" ;;
    pip)   echo "pip install --upgrade uv   (in the environment that owns it)" ;;
    cargo) echo "cargo install --locked --force uv" ;;
    mise)  echo "mise use -g uv@latest   (mise manages this uv)" ;;
    asdf)  echo "asdf install uv latest && asdf global uv latest" ;;
    *)     echo "uv self update   (standalone install), or your package manager: brew upgrade uv / pipx upgrade uv" ;;
  esac
}

# rustup_install_method BIN : official | brew | system | unknown. `rustup self update` only works for a rustup put
# in place by the official rustup-init, which lives in $CARGO_HOME/bin (default ~/.cargo/bin).
rustup_install_method() {
  local b=$1 r ch
  r=$(resolve "$b"); ch=${CARGO_HOME:-$HOME/.cargo}
  case $b$r in
    */Cellar/*|/opt/homebrew/*|/usr/local/opt/*|*/.linuxbrew/*) echo brew; return ;;
    /usr/bin/*|/bin/*|/usr/sbin/*|/usr/local/bin/*|/snap/*) echo system; return ;;
  esac
  case $b in "$ch"/bin/*) echo official; return ;; esac
  echo unknown
}

# rustup_upgrade_cmd METHOD : the right upgrade command for how rustup was installed.
rustup_upgrade_cmd() {
  case $1 in
    official) echo "rustup self update" ;;
    brew)     echo "brew upgrade rustup" ;;
    system)   echo "your package manager (apt/dnf/pacman/apk upgrade rustup)" ;;
    *)        echo "rustup self update   (official install), or your package manager: brew upgrade rustup" ;;
  esac
}

# version_of NAME BIN : print a bare dotted version for the tool.
version_of() {
  case $1 in
    mise)  "$2" --version 2>/dev/null </dev/null | awk 'NR==1{print $1}' ;;
    claude) "$2" --version 2>/dev/null </dev/null | awk 'NR==1{print $1}' ;;
    *)     "$2" --version 2>/dev/null </dev/null | awk 'NR==1{print $2}' ;;
  esac
}

# --------------------------------------------------- Homebrew ca-certificates

audit_brew() {
  audit_start "Homebrew ca-certificates"
  local b prefix link active norm bundle res
  b=$(command -v brew 2>/dev/null)
  if [ -z "$b" ]; then audit_none "Homebrew not found"; return 0; fi
  prefix=$(dirname "$(dirname "$(resolve "$b")")")
  BREW_PREFIX=$prefix
  link="$prefix/opt/ca-certificates"
  if [ ! -L "$link" ] && [ ! -d "$link" ]; then audit_none "ca-certificates formula not installed"; return 0; fi
  active=$(basename "$(readlink "$link" 2>/dev/null || echo "$link")")
  norm=$(printf '%s' "$active" | tr '_-' '..')
  vcmp "$norm" 2026.09.25.1
  VN="fixed in 2026-09-25_1"
  bundle="$prefix/etc/ca-certificates/cert.pem"
  if [ -f "$bundle" ]; then res=$(probe_cafile "$bundle"); else res="skipped:bundle $bundle not found"; fi
  if [ "${res%%:*}" = trusted ] || [ "$VC" = behind ]; then
    plan_add brew "$prefix"
    fixc "brew upgrade ca-certificates"
    fix "brew update && brew upgrade ca-certificates"
    fix "(Homebrew's Python, curl, openssl and others read this bundle. Old versions linger in the Cellar;"
    fix " 'brew cleanup ca-certificates' removes them.)"
  fi
  report "Homebrew ca-certificates" "$link" "$active" "$VC" "$VN" "$res"
  return 0
}

# ------------------------------------------------------------ system CA bundles

audit_sysbundle() {
  audit_start "System CA bundle files"
  local f key found=0 res brewb=
  [ -n "$BREW_PREFIX" ] && brewb=$(resolve "$BREW_PREFIX/etc/ca-certificates/cert.pem")
  for f in /etc/ssl/cert.pem /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
           /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/ca-bundle.pem \
           /usr/local/share/certs/ca-root-nss.crt; do
    [ -f "$f" ] || continue
    key="bundle:$(resolve "$f")"
    [ -n "$brewb" ] && [ "$(resolve "$f")" = "$brewb" ] && continue
    first_time "$key" || continue
    found=1
    res=$(probe_cafile "$f")
    [ "${res%%:*}" = trusted ] && { fixc "patch this bundle (system trust store recipe with -v)"; fix "This bundle still contains the roots the compromised chain leads to: see System trust store below."; FIXSYS=1; }
    report "CA bundle" "$f" "file" na "no version; tested directly" "$res"
  done
  [ "$found" -eq 0 ] && audit_none "none found"
  [ "$VERBOSE" -ge 1 ] && [ "$(uname)" = Darwin ] && echo "  Note: macOS's own trust store (Keychain) carries Apple's block since 19 Oct; tools that use it are protected."$'\n'
  return 0
}

# ---------------------------------------------------------------- OS packages

audit_ospkg() {
  audit_start "OS CA packages"
  local id= vid= ver= fixed= mgr= vc=unknown vn= upg=
  if [ -r /etc/os-release ]; then
    id=$(. /etc/os-release; echo "$ID"); vid=$(. /etc/os-release; echo "$VERSION_ID")
  fi
  if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W ca-certificates >/dev/null 2>&1; then
    mgr=dpkg; ver=$(dpkg-query -W -f='${Version}' ca-certificates 2>/dev/null)
    upg="sudo apt-get update && sudo apt-get install --only-upgrade ca-certificates"
    case $id in
      ubuntu) case $vid in 22.04|24.04|26.04|26.10) fixed="20260816ubuntu0.${vid}.1" ;; esac ;;
      debian) case $vid in 12) fixed="20250419~deb12u2" ;; 13) fixed="20250419+deb13u1" ;; *) fixed="20260816+nmu1" ;; esac ;;
    esac
    if [ -n "$fixed" ]; then
      if dpkg --compare-versions "$ver" ge "$fixed"; then vc=ok; else vc=behind; fi
      vn="fixed in $fixed"
    fi
  elif command -v apk >/dev/null 2>&1 && apk info -e ca-certificates >/dev/null 2>&1; then
    mgr=apk; ver=$(apk list -I ca-certificates 2>/dev/null | awk '$1 ~ /^ca-certificates-[0-9]/{sub(/^ca-certificates-/, "", $1); print $1; exit}')
    upg="apk update && apk upgrade ca-certificates"; fixed=20261020-r0; vn="fixed in $fixed"
    case ${ver%%-*} in
      ""|*[!0-9]*) vc=unknown ;;
      *)           if [ "${ver%%-*}" -ge 20261020 ]; then vc=ok; else vc=behind; fi ;;
    esac
  elif command -v pacman >/dev/null 2>&1 && pacman -Q ca-certificates-mozilla >/dev/null 2>&1; then
    mgr=pacman; ver=$(pacman -Q ca-certificates-mozilla 2>/dev/null | awk '{print $2}')
    upg="sudo pacman -Syu ca-certificates-mozilla"; fixed=3.131.1-1; vn="fixed in $fixed"
    if ver_ge "${ver%%-*}" 3.131.1; then vc=ok; else vc=behind; fi
  elif command -v rpm >/dev/null 2>&1 && rpm -q ca-certificates >/dev/null 2>&1; then
    mgr=rpm; ver=$(rpm -q --qf '%{VERSION}' ca-certificates 2>/dev/null)
    upg="sudo dnf upgrade ca-certificates"
    if [ "$id" = fedora ]; then
      fixed=2026.2.92_v9.0.319; vn="fixed in $fixed"
      # Fedora versions look like 2026.2.92_v9.0.319: compare the date-like part, then the _v build part.
      if ver_ge "${ver%%_v*}" "${fixed%%_v*}" && { [ "${ver%%_v*}" != "${fixed%%_v*}" ] || ver_ge "${ver#*_v}" "${fixed#*_v}"; }; then vc=ok; else vc=behind; fi
    else
      vn="the page lists no fixed package for this distribution"
    fi
  fi
  if [ -z "$mgr" ]; then
    audit_none "no supported package manager / ca-certificates package found (not applicable here)"
    return 0
  fi
  if [ "$vc" = behind ]; then
    fixc "$upg"
    fix "$upg"
    fix "If your distribution has not shipped the fix yet, use the workaround in System trust store (below)."
    FIXSYS=1
  fi
  report "ca-certificates ($mgr)" "$mgr" "${ver:-?}" "$vc" "$vn" "skipped:package check only; see the CA bundle results above"
  return 0
}

# --------------------------------------------------------------- Electron apps

check_electron_version() {
  local v=$1 major=${1%%.*}
  FIXV=
  case $major in
    42) FIXV=42.11.16 ;;
    43) FIXV=43.8.1 ;;
    44) FIXV=44.9.1 ;;
    "") VC=unknown; VN=; return ;;
    *)
      if [ "$major" -gt 44 ]; then VC=ok; VN="newer than the fixed lines"
      else VC=nofix; VN="fixes only published for 42.11.16, 43.8.1, 44.9.1"; FIXV="42.11.16, 43.8.1 or 44.9.1"; fi
      return ;;
  esac
  vcmp "$v" "$FIXV"
}

audit_electron() {
  audit_start "Electron apps"
  if [ "$(uname)" != Darwin ]; then
    audit_none "(macOS apps only for now - not checked on this platform)"; return 0
  fi
  local f app v found=0
  for f in /Applications/*.app/Contents/Frameworks/"Electron Framework.framework"/Resources/Info.plist \
           "$HOME"/Applications/*.app/Contents/Frameworks/"Electron Framework.framework"/Resources/Info.plist; do
    [ -f "$f" ] || continue
    found=1
    app=${f%/Contents/Frameworks/*}
    v=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$f" 2>/dev/null)
    check_electron_version "$v"
    if [ "$VC" = behind ] || [ "$VC" = nofix ]; then
      fixc "update the app to a build on Electron $FIXV or newer (in-app update, else ask the vendor)"
      fix "Update the app to a release built on Electron ${FIXV} (or newer) (check for an in-app update;"
      fix "if none exists yet, ask the vendor). You cannot patch the embedded runtime yourself."
    fi
    report "Electron app: $(basename "$app" .app)" "$app" "Electron ${v:-?}" "$VC" "$VN" "skipped:cannot probe an app's embedded runtime - version check only"
  done
  [ "$found" -eq 0 ] && audit_none "no Electron apps found"
  return 0
}

# ------------------------------------------------------------------- git

# git_probe_all GIT : prints "<result> <url>" for the control and test hosts. git ls-remote
# against a non-repository: a TLS failure mentions the certificate; any HTTP-level answer
# ("not found", auth needed) means the handshake was accepted.
git_probe_all() {
  local u rc out
  export GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=true
  cd "$TMP" || return
  for u in $CONTROL_URL $BAD_URLS; do
    run_to 25 "$1" -c http.lowSpeedLimit=1 -c http.lowSpeedTime=10 ls-remote "$u" \
      >/dev/null 2>"$TMP/gitout" </dev/null
    rc=$?
    if grep -qi 'certificate' "$TMP/gitout"; then out=certerr
    elif [ "$rc" -eq 0 ]; then out=ok
    elif grep -qi -E 'returned error|not found|not valid|is this a git repository|not a git repository|does not appear to be a git|authentication failed|could not read (username|password)' "$TMP/gitout"; then out=ok
    else out=err
    fi
    [ "$out" != ok ] && sed 's/^/    error: /' "$TMP/gitout" | head -3 >> "$TMP/err"
    echo "$out $u"
  done
}

fix_git() {
  [ "${2%%:*}" = trusted ] || return 0
  case $(where_from "$1") in
    brew) fixc "brew upgrade git ca-certificates"; fix "brew update && brew upgrade git ca-certificates" ;;
    *)
      fixc "patch the system CA bundle (or use Homebrew's git)"
      if [ "$1" = /usr/bin/git ] && [ "$(uname)" = Darwin ]; then
        fix "Apple's git reads /etc/ssl/cert.pem and does not check revocation: see System trust store below,"
        fix "or use Homebrew's git: brew install git && brew upgrade ca-certificates"
      else
        fix "git uses the OS/curl CA bundle (http.sslCAInfo or GIT_SSL_CAINFO if set): update ca-certificates,"
        fix "or see System trust store below."
      fi
      FIXSYS=1 ;;
  esac
}

audit_git() {
  audit_start "git"
  local found=0 g v res out cfg extra
  while IFS= read -r g; do
    [ -n "$g" ] && [ -x "$g" ] || continue
    # macOS /usr/bin/git is a stub that prompts to install the Command Line Tools.
    if [ "$g" = /usr/bin/git ] && [ "$(uname)" = Darwin ] && ! xcode-select -p >/dev/null 2>&1; then continue; fi
    first_time "git:$(resolve "$g")" || continue
    found=1
    v=$("$g" --version 2>/dev/null </dev/null | awk '{print $3}')
    if [ "$NO_NETWORK" -eq 1 ]; then
      res="skipped:--no-network"
    else
      log_cmd "$g ls-remote <url>   (control + test hosts)"
      out=$(git_probe_all "$g")
      show_err
      res=$(printf '%s\n' "$out" | judge)
    fi
    extra=$(env_notes GIT_SSL_CAINFO GIT_SSL_CAPATH SSL_CERT_FILE)
    cfg=$(cd "$TMP" && "$g" config --get http.sslCAInfo 2>/dev/null </dev/null)
    [ -n "$cfg" ] && extra="${extra:+$extra
}    note:    http.sslCAInfo=$cfg"
    cfg=$(cd "$TMP" && "$g" config --get http.sslVerify 2>/dev/null </dev/null)
    [ "$cfg" = false ] && extra="${extra:+$extra
}    note:    http.sslVerify=false - git skips certificate checks"
    fix_git "$g" "$res"
    report "git" "$g" "${v:-?}" na "no fixed git version; depends on the CA bundle in use" "$res" "$extra"
  done <<EOF
$({ command -v git 2>/dev/null; ls /opt/homebrew/bin/git /usr/local/bin/git /usr/bin/git 2>/dev/null; } | awk '!s[$0]++')
EOF
  [ "$found" -eq 0 ] && audit_none
  return 0
}

# --------------------------------------------------------- guidance (printing)

print_sys_guidance() {
  local id= like= all
  if [ -r /etc/os-release ]; then
    id=$(. /etc/os-release; echo "$ID"); like=$(. /etc/os-release; echo "$ID_LIKE")
  fi
  all="$id $like $(uname -s)"
  echo "  System trust store (for tools that read the OS CA bundle)"
  echo "    Preferred: install your OS vendor's fixed CA package/update. If none is available yet, the page's"
  echo "    workaround distrusts the two roots the compromised intermediates chain to ('AAA Certificate"
  echo "    Services' by Comodo, and 'emSign ECC Root CA - G3'). That can break legitimate sites which chain"
  echo "    to those roots, so keep the backup, test, and re-run this audit afterwards."
  echo
  case $all in
    *Darwin*)
      cat <<'EOF'
    macOS - /etc/ssl/cert.pem (read by the built-in curl, git, python3, perl, ruby, openssl):
      sudo cp -p /etc/ssl/cert.pem /etc/ssl/cert.pem.bak &&
      sudo awk '/^(###|===) /{skip=0}
        /^=== .*\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/{skip=1}
        !skip' /etc/ssl/cert.pem.bak | sudo tee /etc/ssl/cert.pem > /dev/null
      (An OS update may replace this file. Others report that macOS updates do not refresh it, so re-run
       the audit after updating rather than assuming either way.)
EOF
      ;;
    *alpine*)
      cat <<'EOF'
    Alpine:
      apk add ca-certificates &&
      sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' /etc/ca-certificates.conf && update-ca-certificates
EOF
      ;;
    *debian*|*ubuntu*|*devuan*)
      cat <<'EOF'
    Debian / Ubuntu (run as root):
      sed -i \
        -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \
        -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' \
        /etc/ca-certificates.conf && update-ca-certificates
EOF
      ;;
    *fedora*|*rhel*|*centos*|*rocky*|*almalinux*|*amzn*)
      cat <<'EOF'
    Fedora / RHEL / CentOS / Rocky / Alma / Amazon Linux 2023 (run as root):
      d=/etc/pki/ca-trust/source/blocklist; [ -d $d ] || d=/etc/pki/ca-trust/source/blacklist
      trust extract --overwrite --format=pem-bundle \
        --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' \
        $d/Comodo_AAA_Services_root.pem &&
      trust extract --overwrite --format=pem-bundle \
        --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \
        $d/emSign_ECC_Root_CA_-_G3.pem &&
      update-ca-trust
EOF
      ;;
    *suse*|*sles*)
      cat <<'EOF'
    openSUSE / SLES (run as root):
      d=/etc/pki/trust/blocklist; [ -d $d ] || d=/etc/pki/trust/blacklist
      trust extract --format=pem-bundle \
        --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' \
        $d/Comodo_AAA_Services_root.pem &&
      trust extract --format=pem-bundle \
        --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \
        $d/emSign_ECC_Root_CA_-_G3.pem &&
      update-ca-certificates
EOF
      ;;
    *arch*)
      cat <<'EOF'
    Arch Linux (run as root):
      trust extract --format=pem-bundle \
        --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \
        /etc/ca-certificates/trust-source/blocklist/emSign_ECC_Root_CA_-_G3.pem &&
      update-ca-trust
EOF
      ;;
    *nixos*)
      cat <<'EOF'
    NixOS (configuration.nix):
      security.pki.caCertificateBlacklist = [ "Comodo AAA Services root" "emSign ECC Root CA - G3" ];
EOF
      ;;
    *FreeBSD*)
      cat <<'EOF'
    FreeBSD 14+ (run as root):
      cp /etc/ssl/certs/14bc7599.0 /usr/share/certs/untrusted/14bc7599.pem
      cp /etc/ssl/certs/ee64a828.0 /usr/share/certs/untrusted/ee64a828.pem
      certctl rehash
EOF
      ;;
    *NetBSD*)
      cat <<'EOF'
    NetBSD 10+ (run as root):
      certctl untrust /usr/share/certs/mozilla/all/emSign_ECC_Root_CA_-_G3.pem &&
      certctl untrust /usr/share/certs/mozilla/all/Comodo_AAA_Services_root.pem
EOF
      ;;
    *MINGW*|*MSYS*|*CYGWIN*)
      echo "    Windows: use Block-EmudhraCompromisedCA.ps1 from the page (elevated PowerShell)."
      echo "    The page does not recommend this for enterprise-managed devices."
      ;;
    *)
      echo "    No recipe for this platform here - see https://emudhra.we-have-a-problem.com/ ."
      ;;
  esac
  echo
}

print_pip_guidance() {
  echo "  Built-in pip (macOS)"
  echo "    Apple's pip does its own certificate handling; the page's fix points it at the system bundle."
  echo "    Do this after the System trust store workaround above:"
  cat <<'EOF'
      F="$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')/sitecustomize.py" &&
      echo 'import os; os.environ.setdefault("PIP_CERT", "/etc/ssl/cert.pem")' | sudo tee -a "$F" > /dev/null &&
      sudo chmod 644 "$F"
EOF
  echo
  echo "    Alternatively avoid Apple's python3/pip: use Homebrew Python or a virtualenv with pip >= 26.2.2."
  echo
}

print_guidance_compact() {
  if [ -n "$CGUIDE" ]; then
    printf '%s%sFix first%s (nothing has been run; -v shows full commands)\n' "$C_BLD" "$C_RED" "$C_OFF"
    printf '%s' "$CGUIDE"
    if [ "$NEED_SYS" = 1 ]; then
      echo "  - System CA bundle: upgrade your OS CA package, or distrust the two roots (recipe for this platform with -v)"
    fi
    echo
  fi
  if [ -n "$CADVISE" ]; then
    printf '%s%sProtected, but older than the fixed release%s\n' "$C_BLD" "$C_YEL" "$C_OFF"
    printf '%s' "$CADVISE"
    echo
  fi
  if [ "$FIXMODE" -eq 0 ] && [ "$PLAN" != $'\n' ]; then
    echo "Apply fixes: ${0##*/} --fix --dry-run   (shows every step, changes nothing), then --fix"
    echo
  fi
}

print_guidance() {
  [ "$NO_GUIDE" -eq 1 ] && return 0
  [ -z "$GUIDE" ] && [ -z "$ADVISE" ] && return 0
  if [ "$VERBOSE" -lt 1 ]; then
    print_guidance_compact
    return 0
  fi
  section "Remediation guidance"
  if [ "$FIXMODE" -eq 1 ]; then
    echo "  This is guidance only; nothing below has been run yet. Commands that edit system trust"
  else
    echo "  This is guidance only; nothing below has been run. Commands that edit system trust"
  fi
  echo "  files need sudo - read them first. Upgrading is better than distrusting roots where it is possible."
  echo
  if [ -n "$GUIDE" ]; then
    printf '%s%sAffected - fix these first%s\n' "$C_BLD" "$C_RED" "$C_OFF"
    printf '%s' "$GUIDE"
    [ "$NEED_SYS" = 1 ] && print_sys_guidance
    [ "$NEED_PIPMAC" = 1 ] && print_pip_guidance
  fi
  if [ -n "$ADVISE" ]; then
    printf '%s%sProtected today, but older than the fixed release - upgrade when convenient%s\n' "$C_BLD" "$C_YEL" "$C_OFF"
    printf '%s' "$ADVISE"
  fi
  if [ "$FIXMODE" -eq 0 ] && [ "$PLAN" != $'\n' ]; then
    echo "  This script can apply some of these for you (system CA bundle, Java cacerts, Homebrew, macOS pip):"
    echo "    ${0##*/} --fix --dry-run    # verify and show every step, change nothing"
    echo "    ${0##*/} --fix              # apply, asking before each change"
    echo
  fi
  echo "  After changing anything, re-run this script to confirm."
  echo
}

# ------------------------------------------------------------------ fixing (--fix / --undo)
#
# Everything below only runs with --fix or --undo. Principles:
#   * ask before every change (unless --yes); --dry-run changes nothing
#   * build the new file/store on a COPY and test it before it replaces anything
#   * keep a timestamped backup next to the original; --undo restores the newest one
#   * re-run the probes afterwards and roll back if the result is not an improvement
#   * never delete anything but the two roots named on the advisory page

BACKUP_TAG=pre-emudhra
STAMP=$(date +%Y%m%d%H%M%S)
ROOTS_RE='(AAA Certificate Services|emSign ECC Root CA - G3)'
SANITY_URLS="https://github.com/ https://www.google.com/ https://pypi.org/ https://repo.maven.apache.org/maven2/ https://registry.npmjs.org/ https://proxy.golang.org/"
FIXED_N=0; FAILED_N=0; SKIPPED_N=0
SUDO=
FIX_NOTES=

# fx_say / fx_do / fx_warn : consistent output for fix actions.
fx_say()  { printf '  %s\n' "$*"; }
fx_warn() { printf '  %s! %s%s\n' "$C_YEL" "$*" "$C_OFF"; }
fx_ok()   { printf '  %s✓ %s%s\n' "$C_GRN" "$*" "$C_OFF"; }
fx_bad()  { printf '  %s✗ %s%s\n' "$C_RED" "$*" "$C_OFF"; }
fx_cmd()  { printf '  %s  $ %s%s\n' "$C_DIM" "$*" "$C_OFF"; }

# confirm PROMPT : y/N. --yes answers yes. Otherwise it asks on the controlling terminal (/dev/tty), not stdin,
# because the fix loops read their plan from a here-document, which replaces stdin. No terminal means no.
confirm() {
  [ "$YES" -eq 1 ] && return 0
  local a=
  if ! { : </dev/tty; } 2>/dev/null; then
    fx_warn "no terminal to ask on - skipping (use --yes to run unattended)"
    return 1
  fi
  printf '  %s [y/N] ' "$1" >/dev/tty
  read -r a </dev/tty
  case $a in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# confirm_agree WARNING-TEXT : for destructive steps. Prints the warning, then requires the user to type exactly
# "I AGREE" on the controlling terminal. Unlike confirm(), --yes NEVER answers this, "y"/"yes"/"i agree" are all
# refused, end-of-input is refused, and with no terminal the answer is no.
confirm_agree() {
  local a=
  if ! { : </dev/tty; } 2>/dev/null; then
    fx_warn "no terminal to ask on - not removing anything (--yes does not answer this prompt)"
    return 1
  fi
  printf '%s\n' "$1" >/dev/tty
  printf '  Type I AGREE to continue, anything else cancels: ' >/dev/tty
  # IFS= and no word splitting: plain `read -r` would strip leading/trailing spaces, so " I AGREE" would pass.
  IFS= read -r a </dev/tty || return 1
  [ "$a" = "I AGREE" ]
}

# need_sudo PATH : sets SUDO to "sudo" if PATH (or its directory) is not writable by us. to "sudo" if PATH (or its directory) is not writable by us.
need_sudo() {
  local t=$1
  [ -e "$t" ] || t=$(dirname "$t")
  if [ -w "$t" ]; then SUDO=; else SUDO=sudo; fi
  if [ "$SUDO" = sudo ] && [ "$(id -u)" -eq 0 ]; then SUDO=; fi
  if [ "$SUDO" = sudo ] && ! command -v sudo >/dev/null 2>&1; then
    fx_bad "need root to write $1 but sudo is not available - run this script as root"
    return 1
  fi
  return 0
}

# as_root CMD... : run through $SUDO when needed (never in dry-run).
as_root() {
  fx_cmd "${SUDO:+$SUDO }$*"
  [ "$DRY" -eq 1 ] && return 0
  $SUDO "$@"
}

# strip_roots IN OUT : copy a PEM bundle without the two roots, leaving everything else verbatim.
# Works per certificate: a block is the text since the previous END CERTIFICATE line, through its own
# END CERTIFICATE line. That covers every common layout - Apple's "=== /C=../CN=.." headers with a
# text dump, curl's "Name / =====" titles, and Mozilla-style "# comment" headers. A block is dropped
# if any of its text (other than an Issuer: line) names one of the two roots.
strip_roots() {
  awk -v re="$ROOTS_RE" '
    { buf = buf $0 "\n"; if ($0 !~ /Issuer/ && $0 ~ re) drop = 1 }
    /^-----END CERTIFICATE-----/ { if (!drop) printf "%s", buf; buf = ""; drop = 0 }
    END { printf "%s", buf }
  ' "$1" > "$2"
}

# count_certs FILE
count_certs() { local c; c=$(grep -c 'BEGIN CERTIFICATE' "$1" 2>/dev/null); echo "${c:-0}"; }

# bundle_roots_present FILE : prints how many of the two roots a PEM bundle still contains (via openssl).
bundle_roots_present() {
  local n=0 tmpd c
  tmpd=$(mktemp -d "$TMP/pem.XXXXXX") || return 1
  awk -v d="$tmpd" '/-----BEGIN CERTIFICATE-----/{i++; f=sprintf("%s/c%04d.pem", d, i)} f{print > f} /-----END CERTIFICATE-----/{close(f); f=""}' "$1"
  for c in "$tmpd"/c*.pem; do
    [ -f "$c" ] || continue
    if openssl x509 -in "$c" -noout -subject 2>/dev/null | grep -Eq "$ROOTS_RE"; then n=$((n + 1)); fi
  done
  rm -rf "$tmpd"
  echo "$n"
}

# sanity_check_bundle FILE : does a bundle still validate the normal sites? Uses the Python probe
# against SANITY_URLS (with FILE as the only trust anchors) and the compromised hosts.
# Prints "sane" or "broken:<url>"; prints "unchecked:<why>" if it cannot be tested.
sanity_check_bundle() {
  local f=$1 out r u ok=0 bad
  [ -n "$PYBIN" ] || { echo "unchecked:no Python available"; return; }
  out=$("$PYBIN" -I "$TMP/py_probe.py" cafile "$f" $SANITY_URLS 2>/dev/null </dev/null)
  while read -r r u; do
    case $r in ok) ok=$((ok + 1)) ;; certerr) bad="${bad:+$bad }$u" ;; esac
  done <<EOF
$out
EOF
  if [ -n "$bad" ]; then echo "broken:$bad"; return; fi
  if [ "$ok" -eq 0 ]; then echo "unchecked:could not reach the sanity-check sites"; return; fi
  echo sane
}

# verdict_for_bundle FILE : trusted | rejected | inconclusive:... for the compromised hosts.
verdict_for_bundle() { probe_cafile "$1"; }

# newest_backup FILE : most recent FILE.pre-emudhra-* (empty if none)
newest_backup() { ls -1t "$1".$BACKUP_TAG-* 2>/dev/null | head -1; }

# ---- shared: patch a PEM bundle in place (macOS /etc/ssl/cert.pem and similar single-file stores)
fix_pem_bundle() {
  local f=$1 new="$TMP/patched-bundle.pem" before after bak st v
  fx_say "${C_BLD}$f${C_OFF}  (system CA bundle: read by the built-in curl, git, python3, perl, openssl)"
  if [ ! -f "$f" ]; then fx_warn "not found"; SKIPPED_N=$((SKIPPED_N + 1)); return; fi
  before=$(count_certs "$f")
  strip_roots "$f" "$new"
  after=$(count_certs "$new")
  if [ "$after" -ge "$before" ]; then
    fx_ok "already clean - neither root is present ($before certificates)"; SKIPPED_N=$((SKIPPED_N + 1)); return
  fi
  if [ $((before - after)) -gt 2 ]; then
    fx_bad "refusing: stripping would remove $((before - after)) certificates; expected at most 2"
    FAILED_N=$((FAILED_N + 1)); return
  fi
  fx_say "would remove $((before - after)) of $before certificates (the two roots only)"
  v=$(verdict_for_bundle "$new")
  case ${v%%:*} in
    rejected)    fx_ok "test on a copy: the patched bundle rejects the compromised chain" ;;
    trusted)     fx_bad "test on a copy: the patched bundle STILL accepts the compromised chain - not applying"
                 FAILED_N=$((FAILED_N + 1)); return ;;
    *)           fx_bad "could not test the patched copy (${v#*:}) - not applying a change I cannot verify"
                 FAILED_N=$((FAILED_N + 1)); return ;;
  esac
  st=$(sanity_check_bundle "$new")
  case ${st%%:*} in
    sane)      fx_ok "test on a copy: github.com, google.com, pypi.org, Maven Central, npm and the Go proxy still validate" ;;
    broken)    fx_bad "the patched bundle would break: ${st#broken:} - not applying"
               fx_say "(those sites chain to a root this fix removes; use the vendor package update instead)"
               FAILED_N=$((FAILED_N + 1)); return ;;
    *)         fx_bad "sanity check could not run (${st#*:}) - not applying a change I cannot verify"
               FAILED_N=$((FAILED_N + 1)); return ;;
  esac
  fx_warn "side effect: any site whose certificate chains to either root will stop validating in tools that use this bundle"
  if [ "$DRY" -eq 1 ]; then
    fx_say "[dry-run] would back up to $f.$BACKUP_TAG-$STAMP and install the patched bundle"
    need_sudo "$f" >/dev/null 2>&1 || true
    fx_cmd "${SUDO:+$SUDO }cp -p $f $f.$BACKUP_TAG-$STAMP"
    fx_cmd "${SUDO:+$SUDO }cp $new $f   # keeps owner/mode of the original"
    return
  fi
  confirm "Remove the two roots from $f?" || { fx_say "skipped"; SKIPPED_N=$((SKIPPED_N + 1)); return; }
  need_sudo "$f" || { FAILED_N=$((FAILED_N + 1)); return; }
  bak="$f.$BACKUP_TAG-$STAMP"
  as_root cp -p "$f" "$bak" || { fx_bad "backup failed - nothing changed"; FAILED_N=$((FAILED_N + 1)); return; }
  # write through the original inode's permissions: cp over the file keeps owner and mode
  as_root cp "$new" "$f" || { fx_bad "install failed - restoring"; as_root cp -p "$bak" "$f"; FAILED_N=$((FAILED_N + 1)); return; }
  v=$(verdict_for_bundle "$f")
  case ${v%%:*} in
    rejected) fx_ok "verified: $f now rejects the compromised chain"
              FIXED_N=$((FIXED_N + 1))
              FIX_NOTES="${FIX_NOTES}  - $f: backup at $bak"$'\n' ;;
    *)        fx_bad "verification failed (${v}) - rolling back"
              as_root cp -p "$bak" "$f"
              FAILED_N=$((FAILED_N + 1)) ;;
  esac
}

# ---- Debian / Ubuntu / Alpine : mark the roots as disabled in ca-certificates.conf
fix_debian_like() {
  local conf=/etc/ca-certificates.conf new="$TMP/ca-certificates.conf" bak changed
  fx_say "${C_BLD}$conf${C_OFF}  (Debian/Ubuntu/Alpine CA configuration)"
  [ -f "$conf" ] || { fx_warn "not found"; SKIPPED_N=$((SKIPPED_N + 1)); return; }
  if ! command -v update-ca-certificates >/dev/null 2>&1; then
    fx_warn "update-ca-certificates not found - cannot rebuild the bundle"; SKIPPED_N=$((SKIPPED_N + 1)); return
  fi
  sed -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' "$conf" > "$new"
  if cmp -s "$conf" "$new"; then
    fx_ok "already clean - both roots are already disabled (or not listed)"; SKIPPED_N=$((SKIPPED_N + 1)); return
  fi
  # List the entries being disabled without depending on diff's output format (BusyBox differs).
  fx_say "would disable: $(grep -E '^mozilla/(emSign_ECC_Root_CA_-_G3|Comodo_AAA_Services_root)\.crt' "$conf" | tr '\n' ' ')"
  if [ "$DRY" -eq 1 ]; then
    fx_say "[dry-run] would back up to $conf.$BACKUP_TAG-$STAMP, install the edited file and run update-ca-certificates"
    need_sudo "$conf" >/dev/null 2>&1 || true
    fx_cmd "${SUDO:+$SUDO }cp -p $conf $conf.$BACKUP_TAG-$STAMP"
    fx_cmd "${SUDO:+$SUDO }cp $new $conf && ${SUDO:+$SUDO }update-ca-certificates"
    return
  fi
  confirm "Disable the two roots in $conf and rebuild the bundle?" || { fx_say "skipped"; SKIPPED_N=$((SKIPPED_N + 1)); return; }
  need_sudo "$conf" || { FAILED_N=$((FAILED_N + 1)); return; }
  bak="$conf.$BACKUP_TAG-$STAMP"
  as_root cp -p "$conf" "$bak" || { fx_bad "backup failed - nothing changed"; FAILED_N=$((FAILED_N + 1)); return; }
  as_root cp "$new" "$conf" && as_root update-ca-certificates >/dev/null
  changed=$(for b in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem; do [ -f "$b" ] && { probe_cafile "$b"; break; }; done)
  case ${changed%%:*} in
    rejected) fx_ok "verified: the rebuilt system bundle rejects the compromised chain"
              FIXED_N=$((FIXED_N + 1)); FIX_NOTES="${FIX_NOTES}  - $conf: backup at $bak (restore with --undo)"$'\n' ;;
    *)        fx_bad "verification failed (${changed:-no result}) - rolling back"
              as_root cp -p "$bak" "$conf" && as_root update-ca-certificates >/dev/null
              FAILED_N=$((FAILED_N + 1)) ;;
  esac
}

# remove_blocklist_files DIR : delete the three files this script creates in a p11-kit blocklist directory.
# Refuses unless DIR is a non-empty absolute path to an existing directory, so an unset variable can never
# turn this into `rm -f /emSign_...` at the filesystem root.
remove_blocklist_files() {
  local d=$1
  case $d in
    /?*) ;;
    *) fx_bad "refusing to remove files: directory is empty or not absolute ('$d')"; return 1 ;;
  esac
  [ -d "$d" ] || { fx_bad "refusing to remove files: $d is not a directory"; return 1; }
  as_root rm -f "$d/emSign_ECC_Root_CA_-_G3.pem" "$d/Comodo_AAA_Services_root.pem" "$d/.emudhra-audit-created"
}

# ---- Fedora/RHEL/SUSE/Arch : add the roots to the p11-kit blocklist
fix_p11_blocklist() {
  local d bundle
  fx_say "${C_BLD}p11-kit blocklist${C_OFF}  (Fedora/RHEL/SUSE/Arch)"
  command -v trust >/dev/null 2>&1 || { fx_warn "'trust' command not found"; SKIPPED_N=$((SKIPPED_N + 1)); return; }
  if [ -d /etc/pki/ca-trust/source ]; then d=/etc/pki/ca-trust/source/blocklist; [ -d $d ] || d=/etc/pki/ca-trust/source/blacklist
  elif [ -d /etc/pki/trust ]; then d=/etc/pki/trust/blocklist; [ -d $d ] || d=/etc/pki/trust/blacklist
  elif [ -d /etc/ca-certificates/trust-source ]; then d=/etc/ca-certificates/trust-source/blocklist
  else fx_warn "no known trust-source directory"; SKIPPED_N=$((SKIPPED_N + 1)); return; fi
  if [ -f "$d/emSign_ECC_Root_CA_-_G3.pem" ]; then fx_ok "already clean - blocklist entry exists in $d"; SKIPPED_N=$((SKIPPED_N + 1)); return; fi
  fx_say "would add blocklist entries to $d (new files; nothing existing is modified)"
  if [ "$DRY" -eq 1 ]; then
    need_sudo "$d" >/dev/null 2>&1 || true
    fx_cmd "${SUDO:+$SUDO }trust extract --format=pem-bundle --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' $d/emSign_ECC_Root_CA_-_G3.pem"
    fx_cmd "${SUDO:+$SUDO }trust extract --format=pem-bundle --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' $d/Comodo_AAA_Services_root.pem"
    fx_cmd "${SUDO:+$SUDO }update-ca-trust   # or update-ca-certificates on SUSE"
    return
  fi
  confirm "Add the two roots to the trust blocklist in $d?" || { fx_say "skipped"; SKIPPED_N=$((SKIPPED_N + 1)); return; }
  need_sudo "$d" || { FAILED_N=$((FAILED_N + 1)); return; }
  as_root mkdir -p "$d"
  as_root trust extract --overwrite --format=pem-bundle --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' "$d/emSign_ECC_Root_CA_-_G3.pem"
  as_root trust extract --overwrite --format=pem-bundle --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' "$d/Comodo_AAA_Services_root.pem"
  printf 'created by emudhra-audit-fix.sh %s\n' "$STAMP" | $SUDO tee "$d/.emudhra-audit-created" >/dev/null
  if command -v update-ca-trust >/dev/null 2>&1; then as_root update-ca-trust; else as_root update-ca-certificates; fi
  for bundle in /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/ssl/certs/ca-certificates.crt; do
    [ -f "$bundle" ] && break
  done
  v=$(probe_cafile "$bundle")
  case ${v%%:*} in
    rejected) fx_ok "verified: the rebuilt bundle rejects the compromised chain"
              FIXED_N=$((FIXED_N + 1)); FIX_NOTES="${FIX_NOTES}  - blocklist files in $d (restore with --undo)"$'\n' ;;
    *)        fx_bad "verification failed (${v:-no result}) - removing the blocklist entries"
              remove_blocklist_files "$d"
              if command -v update-ca-trust >/dev/null 2>&1; then as_root update-ca-trust; else as_root update-ca-certificates; fi
              FAILED_N=$((FAILED_N + 1)) ;;
  esac
}

# ---- what the system fix should do on this platform
fix_system() {
  local id= like= all
  [ -r /etc/os-release ] && { id=$(. /etc/os-release; echo "$ID"); like=$(. /etc/os-release; echo "$ID_LIKE"); }
  all="$id $like $(uname -s)"
  echo
  fx_say "${C_BLD}System trust store${C_OFF}"
  if [ "$WORKAROUND_ONLY" -eq 0 ]; then
    case $all in
      *debian*|*ubuntu*|*alpine*|*devuan*) fx_say "Preferred: the vendor's fixed package (apt-get install --only-upgrade ca-certificates / apk upgrade ca-certificates)." ;;
      *fedora*|*rhel*|*centos*|*rocky*|*almalinux*|*amzn*) fx_say "Preferred: the vendor's fixed package (dnf upgrade ca-certificates)." ;;
    esac
  fi
  case $all in
    *Darwin*)                                    fix_pem_bundle /etc/ssl/cert.pem ;;
    *debian*|*ubuntu*|*alpine*|*devuan*)         fix_debian_like ;;
    *fedora*|*rhel*|*centos*|*rocky*|*almalinux*|*amzn*|*suse*|*sles*|*arch*) fix_p11_blocklist ;;
    *)  fx_warn "no automated fix for this platform ($all) - follow the printed guidance"; SKIPPED_N=$((SKIPPED_N + 1)) ;;
  esac
}

# ---- Java cacerts
# java_alias_subject KEYTOOL CACERTS ALIAS : the certificate's CN, for display only.
java_alias_subject() {
  "$1" -J-Duser.language=en -list -v -keystore "$2" -storepass changeit -alias "$3" 2>/dev/null </dev/null |
    sed -n 's/^Owner:.*CN=\([^,]*\).*/\1/p' | head -1
}

fix_java_store() {
  local h=$1 cac kt n aliases a work bak v pre
  fx_say ""
  fx_say "${C_BLD}Java cacerts${C_OFF}  $h"
  cac=$(java_cacerts "$h"); kt=$h/bin/keytool
  if [ -z "$cac" ] || [ ! -x "$kt" ]; then fx_warn "no cacerts or keytool - skipped"; SKIPPED_N=$((SKIPPED_N + 1)); return; fi
  aliases=$(java_affected_aliases "$kt" "$cac")
  n=$(printf '%s\n' "$aliases" | grep -c .)
  if [ "$n" -eq 0 ]; then fx_ok "none of the roots are in $cac"; SKIPPED_N=$((SKIPPED_N + 1)); return; fi
  fx_say "this is a stop-gap: upgrading to a fixed JDK is better, and restores these roots"
  fx_say "would delete $n entr$([ "$n" -eq 1 ] && echo y || echo ies) from the JDK trust store ($cac):"
  printf '%s\n' "$aliases" | while IFS= read -r a; do
    [ -n "$a" ] && printf '      %s   (%s)\n' "$a" "$(java_alias_subject "$kt" "$cac" "$a")"
  done
  work="$TMP/cacerts.$$"
  cp "$cac" "$work"
  printf '%s\n' "$aliases" | while IFS= read -r a; do
    [ -n "$a" ] && "$kt" -delete -alias "$a" -keystore "$work" -storepass changeit >/dev/null 2>&1
  done
  pre=$("$kt" -list -keystore "$cac" -storepass changeit 2>/dev/null | grep -c trustedCertEntry)
  if [ "$(java_affected_aliases "$kt" "$work" | grep -c .)" -ne 0 ]; then
    fx_bad "test on a copy: the roots are still present after deletion - not applying"; FAILED_N=$((FAILED_N + 1)); return
  fi
  if [ $((pre - $("$kt" -list -keystore "$work" -storepass changeit 2>/dev/null | grep -c trustedCertEntry))) -ne "$n" ]; then
    fx_bad "test on a copy: removed a different number of entries than planned - not applying"; FAILED_N=$((FAILED_N + 1)); return
  fi
  v=$(java_probe_with_store "$h" "$work")
  case ${v%%:*} in
    rejected) fx_ok "test on a copy: this JDK rejects the compromised chain with the patched store" ;;
    trusted)  fx_bad "test on a copy: the JDK STILL accepts the chain with the patched store - not applying"
              fx_say "(the chain may be accepted through a different root; the fixed JDK build is the real answer)"
              FAILED_N=$((FAILED_N + 1)); return ;;
    *)        fx_warn "could not test the patched copy (${v#*:})" ;;
  esac
  if [ "$DRY" -eq 1 ]; then
    need_sudo "$cac" >/dev/null 2>&1 || true
    fx_say "[dry-run] would back up to $cac.$BACKUP_TAG-$STAMP and install the patched store"
    fx_cmd "${SUDO:+$SUDO }cp -p $cac $cac.$BACKUP_TAG-$STAMP"
    fx_cmd "${SUDO:+$SUDO }cp $work $cac"
    return
  fi
  confirm "Remove these $n entries from $cac?" || { fx_say "skipped"; SKIPPED_N=$((SKIPPED_N + 1)); return; }
  need_sudo "$cac" || { FAILED_N=$((FAILED_N + 1)); return; }
  bak="$cac.$BACKUP_TAG-$STAMP"
  as_root cp -p "$cac" "$bak" || { fx_bad "backup failed - nothing changed"; FAILED_N=$((FAILED_N + 1)); return; }
  as_root cp "$work" "$cac" || { as_root cp -p "$bak" "$cac"; FAILED_N=$((FAILED_N + 1)); return; }
  v=$(java_probe_with_store "$h" "")
  case ${v%%:*} in
    rejected) fx_ok "verified: this JDK now rejects the compromised chain"
              FIXED_N=$((FIXED_N + 1)); FIX_NOTES="${FIX_NOTES}  - $cac: backup at $bak (a JDK upgrade also restores the roots)"$'\n' ;;
    *)        fx_bad "verification failed (${v}) - rolling back"; as_root cp -p "$bak" "$cac"; FAILED_N=$((FAILED_N + 1)) ;;
  esac
  rm -f "$work"
}

# java_probe_with_store JAVA_HOME STORE : run the compiled probe, optionally against a different truststore.
java_probe_with_store() {
  local h=$1 store=$2 out opts=
  [ "$JAVA_PROBE_OK" -eq 1 ] || { echo "inconclusive:no javac available to build the probe"; return; }
  [ -n "$store" ] && opts="-Djavax.net.ssl.trustStore=$store -Djavax.net.ssl.trustStorePassword=changeit"
  out=$("$h/bin/java" $opts -cp "$TMP/java-cls" EmudhraProbe $CONTROL_URL $BAD_URLS 2>/dev/null </dev/null)
  printf '%s\n' "$out" | judge
}

# ---- Homebrew
fix_brew_store() {
  local prefix=$1 b="$1/bin/brew" before after v
  echo
  fx_say "${C_BLD}Homebrew ca-certificates${C_OFF}"
  [ -x "$b" ] || b=$(command -v brew)
  before=$(basename "$(readlink "$prefix/opt/ca-certificates" 2>/dev/null)")
  fx_say "installed: $before; fixed in 2026-09-25_1 (this is an upgrade, not a trust-store edit)"
  if [ "$DRY" -eq 1 ]; then
    fx_cmd "$b update && $b upgrade ca-certificates"
    return
  fi
  confirm "Run 'brew update && brew upgrade ca-certificates'?" || { fx_say "skipped"; SKIPPED_N=$((SKIPPED_N + 1)); return; }
  fx_cmd "$b update"; "$b" update >/dev/null 2>&1 </dev/null || fx_warn "brew update reported a problem; continuing"
  fx_cmd "$b upgrade ca-certificates"; "$b" upgrade ca-certificates </dev/null 2>&1 | sed 's/^/      /' | tail -5
  after=$(basename "$(readlink "$prefix/opt/ca-certificates" 2>/dev/null)")
  v=$(probe_cafile "$prefix/etc/ca-certificates/cert.pem")
  case ${v%%:*} in
    rejected) fx_ok "verified: Homebrew's bundle ($after) now rejects the compromised chain"
              FIXED_N=$((FIXED_N + 1)); FIX_NOTES="${FIX_NOTES}  - Homebrew ca-certificates: $before -> $after (brew cleanup removes the old version)"$'\n' ;;
    *)        fx_bad "after upgrade, Homebrew's bundle still does not reject the chain (${v:-no result}); installed: $after"
              FAILED_N=$((FAILED_N + 1)) ;;
  esac
}

# ---- macOS built-in pip (sitecustomize.py sets PIP_CERT)
fix_macos_pip() {
  local py=/usr/bin/python3 f d line bak
  echo
  fx_say "${C_BLD}macOS built-in pip${C_OFF}  (/usr/bin/python3)"
  [ -x "$py" ] || { fx_warn "not found"; SKIPPED_N=$((SKIPPED_N + 1)); return; }
  d=$("$py" -c 'import sysconfig; print(sysconfig.get_path("stdlib"))' 2>/dev/null </dev/null)
  [ -n "$d" ] && [ -d "$d" ] || { fx_warn "could not locate the stdlib directory"; SKIPPED_N=$((SKIPPED_N + 1)); return; }
  f="$d/sitecustomize.py"
  line='import os; os.environ.setdefault("PIP_CERT", "/etc/ssl/cert.pem")'
  if [ -f "$f" ] && grep -qF "$line" "$f"; then fx_ok "already configured in $f"; SKIPPED_N=$((SKIPPED_N + 1)); return; fi
  fx_say "this points Apple's pip at /etc/ssl/cert.pem, so it only helps once that file is patched"
  case $d in
    */Xcode.app/*)         fx_warn "this directory is inside Xcode: updating Xcode will overwrite this change. A virtualenv or Homebrew Python avoids that." ;;
    */CommandLineTools/*)  fx_warn "this directory is inside the Command Line Tools: updating them will overwrite this change. A virtualenv or Homebrew Python avoids that." ;;
  esac
  fx_say "would append one line to $f (new file if absent)"
  if [ "$DRY" -eq 1 ]; then
    need_sudo "$d" >/dev/null 2>&1 || true
    [ -f "$f" ] && fx_cmd "${SUDO:+$SUDO }cp -p $f $f.$BACKUP_TAG-$STAMP"
    fx_cmd "echo '$line' | ${SUDO:+$SUDO }tee -a $f"
    return
  fi
  confirm "Add that line to $f?" || { fx_say "skipped"; SKIPPED_N=$((SKIPPED_N + 1)); return; }
  need_sudo "$d" || { FAILED_N=$((FAILED_N + 1)); return; }
  bak=
  if [ -f "$f" ]; then bak="$f.$BACKUP_TAG-$STAMP"; as_root cp -p "$f" "$bak" || { FAILED_N=$((FAILED_N + 1)); return; }; fi
  fx_cmd "echo '...' | ${SUDO:+$SUDO }tee -a $f"
  printf '%s\n' "$line" | $SUDO tee -a "$f" >/dev/null && $SUDO chmod 644 "$f"
  if "$py" -I -c 'import sys' >/dev/null 2>&1 </dev/null; then
    fx_ok "applied; $py still starts. Re-run the audit to see pip's result."
    FIXED_N=$((FIXED_N + 1)); FIX_NOTES="${FIX_NOTES}  - $f: ${bak:+backup at $bak, }created or appended (delete the line to undo)"$'\n'
  else
    fx_bad "$py no longer starts - rolling back"
    if [ -n "$bak" ]; then as_root cp -p "$bak" "$f"; elif [ -n "$f" ] && [ "$(basename "$f")" = sitecustomize.py ]; then as_root rm -f "$f"; fi
    FAILED_N=$((FAILED_N + 1))
  fi
}

# ---- Node.js via nvm
# nvm is a shell function, not a binary, so every call goes through nvm_run, which sources nvm.sh in a
# subshell (NVM_DIR if set, else ~/.nvm). Nothing in the user's shell or config is touched.
nvm_dir() { printf '%s' "${NVM_DIR:-$HOME/.nvm}"; }
nvm_run() {   # nvm ARGS... : run `nvm ARGS` in a clean subshell; output on stdout/stderr, status returned
  local d
  d=$(nvm_dir)
  [ -s "$d/nvm.sh" ] || return 127
  ( export NVM_DIR="$d"; . "$d/nvm.sh" >/dev/null 2>&1; nvm "$@" ) </dev/null
}

# plan_node_major NODE_BIN : schedule one nvm upgrade per major line, targeting the newest installed binary of
# that major (the closest to the fixed release, so --reinstall-packages-from copies the most relevant packages).
plan_node_major() {
  local n=$1 v major best entry
  v=$("$n" --version 2>/dev/null </dev/null); v=${v#v}; major=${v%%.*}
  # already planned for this major? keep the newer of the two
  while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    best=$("$entry" --version 2>/dev/null </dev/null); best=${best#v}
    if [ "${best%%.*}" = "$major" ]; then
      if ver_ge "$v" "$best" && [ "$v" != "$best" ]; then
        # replace the older entry with this newer one (PLAN is newline-separated "kind|target" lines)
        PLAN=$(printf '%s\n' "$PLAN" | grep -v -F -x "node|$entry")$'\n'
        plan_add node "$n"
      fi
      return 0
    fi
  done <<EOF3
$(printf '%s\n' "$PLAN" | grep '^node|' | cut -d'|' -f2-)
EOF3
  plan_add node "$n"
}

# nvm_run_seq CMD1... -- CMD2... : run two nvm commands in order in ONE subshell, so state set by the first (for
# example `nvm deactivate` clearing the active version from PATH) is seen by the second. Stops at the first failure
# of the second command only; the first is best-effort because deactivating when nothing is active is harmless.
nvm_run_seq() {
  local d first=() second=() seen=0 a
  d=$(nvm_dir)
  [ -s "$d/nvm.sh" ] || return 127
  for a in "$@"; do
    if [ "$a" = "--" ]; then seen=1; continue; fi
    if [ "$seen" -eq 0 ]; then first+=("$a"); else second+=("$a"); fi
  done
  ( export NVM_DIR="$d"; . "$d/nvm.sh" >/dev/null 2>&1; nvm "${first[@]}" >/dev/null 2>&1; nvm "${second[@]}" ) </dev/null
}

# node_fixed_for NODE_BIN : the fixed version for this Node's major line, or empty if none is published.
node_fixed_for() {
  local v major
  v=$("$1" --version 2>/dev/null </dev/null); v=${v#v}; major=${v%%.*}
  case $major in
    22) echo 22.23.4 ;;
    24) echo 24.22.1 ;;
    26) echo 26.12.1 ;;
  esac
}

fix_node_nvm() {
  local n=$1 oldv fixed newbin cur_default nres avail
  echo
  fx_say "${C_BLD}Node.js (nvm)${C_OFF}  $n"
  oldv=$("$n" --version 2>/dev/null </dev/null)
  fixed=$(node_fixed_for "$n")
  if [ -z "$fixed" ]; then
    fx_warn "no fixed Node.js release is published for $oldv's major line (fixed: 22.23.4, 24.22.1, 26.12.1) - not guessing a different major"
    SKIPPED_N=$((SKIPPED_N + 1)); return
  fi
  if [ ! -s "$(nvm_dir)/nvm.sh" ]; then
    fx_warn "$(nvm_dir)/nvm.sh not found - cannot drive nvm (set NVM_DIR if nvm lives elsewhere)"
    SKIPPED_N=$((SKIPPED_N + 1)); return
  fi
  newbin="$(nvm_dir)/versions/node/v$fixed/bin/node"
  fx_say "installed: $oldv   fixed in: v$fixed (same major line; this is an upgrade, not a trust-store edit)"

  # Is the fixed release actually published? Ask nvm rather than assuming.
  if [ -x "$newbin" ]; then
    fx_say "v$fixed is already installed"
  else
    avail=$(nvm_run version-remote "${fixed%%.*}" 2>/dev/null | tail -1)
    avail=${avail#v}
    if [ -z "$avail" ] || [ "$avail" = N/A ] || ! ver_ge "$avail" "$fixed"; then
      fx_warn "nvm reports ${avail:-nothing} as the newest ${fixed%%.*}.x; the fixed release $fixed is not available yet - not changing anything"
      SKIPPED_N=$((SKIPPED_N + 1)); return
    fi
  fi

  if [ "$DRY" -eq 1 ]; then
    [ -x "$newbin" ] || fx_cmd "nvm install v$fixed --reinstall-packages-from=$oldv"
    fx_cmd "# then, only if $oldv is your current default: nvm alias default v$fixed   (asked separately)"
    fx_say "[dry-run] afterwards, each older v${fixed%%.*}.x that is not your default or aliased would be offered for removal"
    fx_say "[dry-run] behind a type-I-AGREE prompt that --yes cannot answer (nvm uninstall $oldv); nothing is removed now"
    return
  fi

  if [ ! -x "$newbin" ]; then
    confirm "Install Node.js v$fixed with nvm (global npm packages are copied from $oldv)?" || { fx_say "skipped"; SKIPPED_N=$((SKIPPED_N + 1)); return; }
    fx_cmd "nvm install v$fixed --reinstall-packages-from=$oldv"
    nvm_run install "v$fixed" --reinstall-packages-from="$oldv" 2>&1 | sed 's/^/      /' | tail -6
    if [ ! -x "$newbin" ]; then
      fx_bad "nvm did not install v$fixed (offline, mirror down or interrupted) - nothing was changed"
      FAILED_N=$((FAILED_N + 1)); return
    fi
  else
    confirm "Use the already-installed v$fixed?" || { fx_say "skipped"; SKIPPED_N=$((SKIPPED_N + 1)); return; }
  fi

  # Verify the NEW binary itself: it must reject the compromised chain.
  nres=$(node_probe_bin "$newbin")
  case ${nres%%:*} in
    rejected) fx_ok "verified: $newbin rejects the compromised chain" ;;
    *)        fx_bad "v$fixed is installed but does not reject the chain (${nres:-no result}) - leaving your default alone"
              FAILED_N=$((FAILED_N + 1)); return ;;
  esac

  # The default alias is a separate decision: other projects may rely on the current default.
  cur_default=$(nvm_run version default 2>/dev/null | tail -1)
  if [ "$cur_default" = "$oldv" ]; then
    if confirm "$oldv is your nvm default. Make v$fixed the default (nvm alias default v$fixed)?"; then
      fx_cmd "nvm alias default v$fixed"
      nvm_run alias default "v$fixed" >/dev/null 2>&1 && fx_ok "default is now v$fixed" || fx_warn "could not set the default alias"
      FIX_NOTES="${FIX_NOTES}  - nvm default alias: $oldv -> v$fixed (undo: nvm alias default $oldv)"$'\n'
    else
      fx_say "default left as $oldv; new shells will keep using it until you change it"
    fi
  else
    fx_say "your nvm default is ${cur_default:-unset}, not $oldv - not changing it"
  fi
  FIXED_N=$((FIXED_N + 1))
  FIX_NOTES="${FIX_NOTES}  - Node.js: installed v$fixed beside $oldv"$'\n'

  # Last, and only after a verified upgrade: offer to remove the old, affected version(s). Each is a separate,
  # strongly worded prompt that --yes can never answer.
  offer_node_removal "$fixed"
}

# nvm_aliases_for VERSION : names of every nvm alias that resolves to VERSION (e.g. v24.16.0), one per line.
# Asks nvm itself, because aliases chain (default -> lts/* -> lts/krypton -> v24.16.0).
nvm_aliases_for() {
  nvm_run alias 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' |
    awk -v v="$1" '{ name=$1; if (index($0, "(-> " v ")") || index($0, "(-> " v " ")) print name }'
}

# nvm_removable_versions FIXED : old versions of the same major that are safe to OFFER for removal, as
# "<version>|<reason>" lines. reason is empty when removal may be offered, otherwise why it is being kept.
nvm_removable_versions() {
  local fixed=$1 major dir d v def reasons
  major=${fixed%%.*}
  dir="$(nvm_dir)/versions/node"
  def=$(nvm_run version default 2>/dev/null | tail -1)
  for d in "$dir"/v"$major".*; do
    [ -d "$d" ] || continue
    v=${d##*/}; v=${v#v}
    ver_ge "$v" "$fixed" && continue            # the fixed version, or newer: never offered
    reasons=
    [ "v$v" = "$def" ] && reasons="it is your nvm default"
    al=$(nvm_aliases_for "v$v" | tr '\n' ' ')
    [ -n "${al// /}" ] && reasons="${reasons:+$reasons; }aliases point at it: $al"
    echo "$v|$reasons"
  done
}

# offer_node_removal FIXED : after a verified upgrade, offer to remove older same-major versions, one at a time,
# each behind the I AGREE gate. Never runs under --dry-run, never with --yes alone.
offer_node_removal() {
  local fixed=$1 line v reason n=0 removed=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    v=${line%%|*}; reason=${line#*|}
    n=$((n + 1))
    if [ -n "$reason" ]; then
      fx_say "keeping v$v: $reason"
      continue
    fi
    if confirm_agree "
  ${C_YEL}WARNING: this permanently deletes Node.js v$v from nvm.${C_OFF}

  Before you continue, be aware that:
    - it is the version with the compromised-chain problem, so removing it is the safest end state, BUT
    - any project that pins it (an .nvmrc, .node-version, engines field, a CI script or a shell alias) will
      stop working until it is pointed at v$fixed or newer;
    - global npm packages installed only under v$v are deleted with it (the upgrade copied them to v$fixed);
    - running processes and shells currently using v$v keep running, but new shells will not find it;
    - this cannot be undone except by reinstalling it: nvm install v$v   (a reinstall brings the problem back).

  Command that will run: nvm uninstall v$v"; then
      fx_cmd "nvm deactivate && nvm uninstall v$v"
      # nvm refuses to uninstall the version that is "currently active", and a script started from a shell that
      # already had v$v active inherits that. `nvm deactivate` only changes PATH inside this subshell, so it cannot
      # affect the user's own shell. Keep nvm's output so a failure can say why.
      nvm_out=$(nvm_run_seq deactivate -- uninstall "v$v" 2>&1)
      if [ ! -d "$(nvm_dir)/versions/node/v$v" ]; then
        fx_ok "removed v$v"
        removed=$((removed + 1))
        FIX_NOTES="${FIX_NOTES}  - Node.js: removed v$v (reinstall with: nvm install v$v)"$'\n'
      else
        fx_bad "nvm could not remove v$v; it is still installed. nvm said:"
        printf '%s\n' "$nvm_out" | sed 's/^/        /' | head -6
        fx_say "To finish it yourself, open a NEW shell (one that does not have v$v active) and run: nvm uninstall v$v"
      fi
    else
      fx_say "kept v$v (nothing typed, or not exactly I AGREE)"
    fi
  done <<EOF2
$(nvm_removable_versions "$fixed")
EOF2
  [ "$n" -eq 0 ] && fx_say "no older v${fixed%%.*}.x versions are installed, so there is nothing to remove"
  return 0
}

# node_probe_bin NODE_BIN : TLS verdict (trusted | rejected | inconclusive:...) for one Node binary.
node_probe_bin() {
  local out
  [ "$NO_NETWORK" -eq 1 ] && { echo "skipped:--no-network"; return; }
  out=$("$1" "$TMP/node_probe.js" $CONTROL_URL $BAD_URLS 2>/dev/null </dev/null)
  printf '%s\n' "$out" | judge
}

# ---- uv (standalone installer only)
# fix_uv UV_BIN : `uv self update` for a standalone install; for any other install method print the right command
# and change nothing. The binary is copied first and put back if the update leaves uv broken or still behind.
fix_uv() {
  local b=$1 how cmd oldv newv bak
  how=$(uv_install_method "$b"); cmd=$(uv_upgrade_cmd "$how")
  oldv=$(version_of uv "$b")
  fx_say "${C_BLD}uv${C_OFF}  $b  ($oldv, install method: $how)"
  if [ "$how" != standalone ]; then
    fx_warn "this uv was not installed by the standalone installer, so 'uv self update' is not used. Run: $cmd"
    SKIPPED_N=$((SKIPPED_N + 1)); return
  fi
  if [ "$DRY" -eq 1 ]; then
    fx_cmd "$b self update"
    fx_say "[dry-run] would then re-read 'uv --version' and compare it with $UV_FIXED; nothing is changed now"
    return
  fi
  confirm "Upgrade uv with '$b self update'?" || { fx_say "skipped"; SKIPPED_N=$((SKIPPED_N + 1)); return; }
  bak="$TMP/uv.bak"
  cp -p "$b" "$bak" || { fx_bad "could not back up $b - nothing was changed"; FAILED_N=$((FAILED_N + 1)); return; }
  fx_cmd "$b self update"
  "$b" self update </dev/null 2>&1 | sed 's/^/      /' | tail -6
  newv=$(version_of uv "$b")
  if [ -z "$newv" ]; then
    fx_bad "uv no longer reports a version - restoring the previous binary"
    cp -p "$bak" "$b"; FAILED_N=$((FAILED_N + 1)); return
  fi
  if ver_ge "$newv" "$UV_FIXED"; then
    fx_ok "uv --version now reports $newv (fixed in $UV_FIXED). This is a version check, not a TLS probe."
    FIXED_N=$((FIXED_N + 1))
    FIX_NOTES="${FIX_NOTES}  - uv: $oldv -> $newv"$'\n'
  else
    fx_bad "uv reports $newv, still behind $UV_FIXED (the update may not have happened) - the binary still works"
    FAILED_N=$((FAILED_N + 1))
  fi
  fx_say "Note: this upgrades uv only. Python versions and tools that uv manages (uv python / uv tool) are not upgraded."
}

# ---- rustup (official rustup-init install only)
# fix_rustup RUSTUP_BIN : `rustup self update` for an official install; for any other install method print the right
# command and change nothing. The binary is copied first and put back if rustup stops responding.
fix_rustup() {
  local b=$1 how cmd oldv newv bak
  how=$(rustup_install_method "$b"); cmd=$(rustup_upgrade_cmd "$how")
  oldv=$(version_of rustup "$b")
  fx_say "${C_BLD}rustup${C_OFF}  $b  ($oldv, install method: $how)"
  if [ "$how" != official ]; then
    fx_warn "this rustup was not installed by rustup-init, so 'rustup self update' is not used. Run: $cmd"
    SKIPPED_N=$((SKIPPED_N + 1)); return
  fi
  if [ "$DRY" -eq 1 ]; then
    fx_cmd "$b self update"
    fx_say "[dry-run] would then re-read 'rustup --version' and compare it with $RUSTUP_FIXED; nothing is changed now"
    return
  fi
  confirm "Upgrade rustup with '$b self update'?" || { fx_say "skipped"; SKIPPED_N=$((SKIPPED_N + 1)); return; }
  bak="$TMP/rustup.bak"
  cp -p "$b" "$bak" || { fx_bad "could not back up $b - nothing was changed"; FAILED_N=$((FAILED_N + 1)); return; }
  fx_cmd "$b self update"
  "$b" self update </dev/null 2>&1 | sed 's/^/      /' | tail -6
  newv=$(version_of rustup "$b")
  if [ -z "$newv" ]; then
    fx_bad "rustup no longer reports a version - restoring the previous binary. If it is still broken, reinstall with rustup-init (https://rustup.rs)"
    cp -p "$bak" "$b"; FAILED_N=$((FAILED_N + 1)); return
  fi
  if ver_ge "$newv" "$RUSTUP_FIXED"; then
    fx_ok "rustup --version now reports $newv (fixed in $RUSTUP_FIXED). This is a version check, not a TLS probe."
    FIXED_N=$((FIXED_N + 1))
    FIX_NOTES="${FIX_NOTES}  - rustup: $oldv -> $newv"$'\n'
  else
    fx_bad "rustup reports $newv, still behind $RUSTUP_FIXED (the update may not have happened) - the binary still works"
    FAILED_N=$((FAILED_N + 1))
  fi
  fx_say "Note: this upgrades rustup only. Rust toolchains are not updated (rustup update), and Rust projects still need"
  fx_say "rustls-webpki >= 0.103.16 and webpki-roots >= 1.0.10 in Cargo.lock (cargo update -p rustls-webpki -p webpki-roots)."
}

# ---- orchestration
run_fixes() {
  local line kind target ran=0
  section "Fix"
  if [ "$PLAN" = $'\n' ]; then
    echo "  Nothing to fix: no affected item has an automated fix."; echo; return 0
  fi
  if [ "$DRY" -eq 1 ]; then
    echo "  DRY RUN - nothing will be changed. Each step below is verified on a copy where possible."
  else
    echo "  Each change asks first, is tested on a copy, is backed up, verified after, and rolled back if it fails."
  fi
  if [ "$(uname)" = Darwin ] && profiles status -type enrollment 2>/dev/null </dev/null | grep -qi 'enrolled via DEP: *Yes\|MDM enrollment: *Yes'; then
    fx_warn "this Mac appears to be enrolled in MDM ($(profiles status -type enrollment 2>/dev/null </dev/null | tr '\n' ' ' | cut -c1-110)): IT may overwrite these changes, or want to make them centrally"
  fi
  # order: package/upgrade fixes first, then the system store, then the stop-gaps that depend on it
  # Iterate with `for` over newline-split lines, NOT `while read <<EOF`: a here-document would replace stdin
  # for everything run inside the loop (brew, keytool, prompts), which is how confirm() once lost its terminal.
  local oldifs=$IFS
  IFS=$'\n'
  for kind in brew sys java macpip node uv rustup; do
    for line in $PLAN; do
      IFS=$oldifs
      case $line in "$kind|"*) ;; *) IFS=$'\n'; continue ;; esac
      target=${line#*|}
      if [ -n "$ONLY" ] && [ "$ONLY" != "$kind" ]; then IFS=$'\n'; continue; fi
      ran=1
      case $kind in
        brew)   fix_brew_store "$target" ;;
        sys)    fix_system ;;
        java)   fix_java_store "$target" ;;
        macpip) fix_macos_pip ;;
        node)   fix_node_nvm "$target" ;;
        uv)     fix_uv "$target" ;;
        rustup) fix_rustup "$target" ;;
      esac
      IFS=$'\n'
    done
  done
  IFS=$oldifs
  echo
  [ "$ran" -eq 0 ] && echo "  Nothing matched${ONLY:+ --only $ONLY}."
  printf '  %sChanged: %s   Failed or refused: %s   Skipped: %s%s\n' "$C_BLD" "$FIXED_N" "$FAILED_N" "$SKIPPED_N" "$C_OFF"
  if [ -n "$FIX_NOTES" ]; then
    echo "  Backups and undo notes:"
    printf '%s' "$FIX_NOTES"
    echo "  Restore system files and JDK stores with: ${0##*/} --undo"
  fi
  if [ "$DRY" -eq 0 ] && [ "$FIXED_N" -gt 0 ]; then
    echo "  Re-run the audit to confirm. OS updates may overwrite edited system files."
  fi
  echo
}

# ---- undo
run_undo() {
  local f b any=0 cands h d
  section "Undo"
  cands=$(
    for f in /etc/ssl/cert.pem /etc/ca-certificates.conf /etc/pki/tls/certs/ca-bundle.crt; do
      [ -n "$(newest_backup "$f")" ] && echo "$f"
    done
    # every JDK the audit would find, so backups are found wherever the JDK lives
    for h in $(java_candidates | awk '!s[$0]++'); do
      f=$(java_cacerts "$h")
      [ -n "$f" ] && [ -n "$(newest_backup "$f")" ] && echo "$f"
    done
    if [ "$(uname)" = Darwin ] && [ -x /usr/bin/python3 ]; then
      d=$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))' 2>/dev/null </dev/null)
      [ -n "$d" ] && [ -n "$(newest_backup "$d/sitecustomize.py")" ] && echo "$d/sitecustomize.py"
    fi
  )
  # p11-kit blocklist entries this script created (identified by its marker file)
  for d in /etc/pki/ca-trust/source/blocklist /etc/pki/ca-trust/source/blacklist /etc/pki/trust/blocklist \
           /etc/pki/trust/blacklist /etc/ca-certificates/trust-source/blocklist; do
    [ -f "$d/.emudhra-audit-created" ] || continue
    any=1
    fx_say "${C_BLD}$d${C_OFF}"
    fx_say "remove the blocklist entries this script added (emSign_ECC_Root_CA_-_G3.pem, Comodo_AAA_Services_root.pem)"
    if [ "$DRY" -eq 1 ]; then fx_say "[dry-run] would remove them and rebuild the bundle"; continue; fi
    confirm "Remove them and rebuild the trust bundle?" || { fx_say "skipped"; continue; }
    need_sudo "$d" || continue
    remove_blocklist_files "$d" || { fx_bad "could not remove them"; continue; }
    if command -v update-ca-trust >/dev/null 2>&1; then as_root update-ca-trust; else as_root update-ca-certificates >/dev/null; fi
    fx_ok "removed and rebuilt"
  done
  for f in $(printf '%s\n' "$cands" | awk '!s[$0]++'); do
    b=$(newest_backup "$f")
    [ -z "$b" ] && continue
    any=1
    fx_say "${C_BLD}$f${C_OFF}"
    fx_say "restore from $b"
    if [ "$DRY" -eq 1 ]; then fx_say "[dry-run] would restore it"; continue; fi
    confirm "Restore $f from that backup?" || { fx_say "skipped"; continue; }
    need_sudo "$f" || continue
    if as_root cp -p "$b" "$f"; then fx_ok "restored"; else fx_bad "restore failed"; continue; fi
    case $f in
      /etc/ca-certificates.conf) command -v update-ca-certificates >/dev/null 2>&1 && as_root update-ca-certificates >/dev/null ;;
    esac
  done
  [ "$any" -eq 0 ] && echo "  No ${BACKUP_TAG} backups found in the usual places."
  echo "  Homebrew upgrades are not covered by --undo (see the notes printed by --fix)."
  echo
}

# ------------------------------------------------------------------- main

if [ "$VERBOSE" -ge 1 ]; then
  printf '%seMudhra intermediate CA compromise - developer tool audit%s (v%s, read-only)\n' "$C_BLD" "$C_OFF" "$VERSION_OF_SCRIPT"
  printf 'Host: %s   Date: %s\n' "$(uname -srm)" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
  printf 'Reference: https://emudhra.we-have-a-problem.com/\n'
  if [ "$NO_NETWORK" -eq 1 ]; then
    echo "Mode: version checks only (--no-network)"
  else
    echo "Probe hosts: $BAD_URLS (control: $CONTROL_URL)"
  fi
  echo
else
  printf '%seMudhra CA compromise audit%s v%s - %s - %s%s\n' "$C_BLD" "$C_OFF" "$VERSION_OF_SCRIPT" "$(uname -sm)" "$(date '+%Y-%m-%d')" \
    "$([ "$NO_NETWORK" -eq 1 ] && echo ' - version checks only')"
  echo
fi

if [ "$UNDO" -eq 1 ]; then
  run_undo
  exit 0
fi

# Testing aid: EMUDHRA_AUDIT_ONLY=node (or curl, git, go, python, java, ...) runs just that one audit, so tests of a
# single fix do not wait for every other tool to be probed over the network. Unset, everything runs.
want() { [ -z "${EMUDHRA_AUDIT_ONLY:-}" ] || [ "$EMUDHRA_AUDIT_ONLY" = "$1" ]; }

audit_env
want curl   && audit_curl
want git    && audit_git
want go     && audit_go
want python && audit_python
want java   && audit_java
want node   && audit_node
want deno   && audit_deno
want bun    && audit_bun
want rustup && audit_simple "rustup" rustup 1.29.2 "rustup self update   (or: brew upgrade rustup)" "${CARGO_HOME:-$HOME/.cargo}/bin/rustup"
want uv     && audit_simple "uv" uv 0.13.4 "uv self update   (or: brew upgrade uv / pipx upgrade uv)" "$HOME/.local/bin/uv $HOME/.cargo/bin/uv"
want pixi   && audit_simple "pixi" pixi 0.82.1 "pixi self-update   (or: brew upgrade pixi)" "$HOME/.pixi/bin/pixi"
want mise   && audit_simple "mise" mise 2026.10.17 "mise self-update   (or: brew upgrade mise)" "$HOME/.local/bin/mise"
want claude && audit_simple "Claude Code" claude 2.1.303 "claude update" "$HOME/.local/bin/claude $HOME/.claude/local/claude"
want brew   && audit_brew
want sys    && audit_sysbundle
want ospkg  && audit_ospkg
want electron && audit_electron

if [ "$VERBOSE" -ge 1 ]; then
  section "Summary"
  printf '  affected / likely affected: %s\n  ok / likely ok:             %s\n  unknown:                    %s\n' "$N_BAD" "$N_OK" "$N_UNK"
  echo
  echo "Notes: 'AFFECTED'/'OK' come from a live probe. 'LIKELY-*' are version-only."
  echo "Not covered yet: Rust crates in your projects (rustls-webpki, webpki-roots), Perl Mozilla::CA, Composer,"
  echo "Elixir/Erlang, containers and per-project virtualenvs/node_modules."
  echo
else
  [ -n "$MISSING" ] && printf '%sNot installed / not applicable:%s %s\n\n' "$C_DIM" "$C_OFF" "$MISSING"
  printf '%sSummary:%s %s%s affected%s, %s%s ok%s, %s%s unknown%s   (-v for the full report)\n' "$C_BLD" "$C_OFF" \
    "$C_RED" "$N_BAD" "$C_OFF" "$C_GRN" "$N_OK" "$C_OFF" "$C_YEL" "$N_UNK" "$C_OFF"
  echo
fi

print_guidance

if [ "$FIXMODE" -eq 1 ]; then
  run_fixes
fi

[ "$N_BAD" -gt 0 ] && exit 1
exit 0

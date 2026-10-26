#!/usr/bin/env bash
#
# Tests the root-stripping logic used by `../emudhra-audit-fix.sh --fix` against a CA bundle.
# Read-only on the input; writes only to a private temp directory.
#
# Usage: tests/test_strip_roots.sh [BUNDLE]     (default: /etc/ssl/cert.pem)

BUNDLE=${1:-/etc/ssl/cert.pem}
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/../../emudhra-audit-fix.sh"

T=$(mktemp -d) || exit 2
trap 'rm -rf "$T"' EXIT

# Load only the helper functions under test, not the whole script.
ROOTS_RE='(AAA Certificate Services|emSign ECC Root CA - G3)'
eval "$(sed -n '/^strip_roots() {/,/^}/p;/^count_certs() {/p' "$SCRIPT")"

fails=0
check() {  # DESCRIPTION CONDITION-EXIT-CODE
  if [ "$2" -eq 0 ]; then echo "  ok   $1"; else echo "  FAIL $1"; fails=$((fails + 1)); fi
}
yes_if() { if "$@"; then echo 0; else echo 1; fi; }

# split BUNDLE PREFIX : one file per certificate, named PREFIX-NNNN.pem
split_certs() {
  awk -v d="$T" -v p="$2" '/-----BEGIN CERTIFICATE-----/{i++; f=sprintf("%s/%s-%04d.pem", d, p, i)} f{print > f} /-----END CERTIFICATE-----/{close(f); f=""}' "$1"
}
fingerprints() { for c in "$@"; do openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null; done | sort; }
is_root() { openssl x509 -in "$1" -noout -subject 2>/dev/null | grep -q -E 'AAA Certificate Services|emSign ECC Root CA - G3'; }

[ -r "$BUNDLE" ] || { echo "cannot read $BUNDLE"; exit 2; }
echo "bundle: $BUNDLE"

strip_roots "$BUNDLE" "$T/new.pem"
before=$(count_certs "$BUNDLE"); after=$(count_certs "$T/new.pem")
echo "  certificates: $before -> $after"

split_certs "$BUNDLE" orig
split_certs "$T/new.pem" kept
roots_in_orig=0
for c in "$T"/orig-*.pem; do is_root "$c" && roots_in_orig=$((roots_in_orig + 1)); done

check "removed exactly the root certificates present ($roots_in_orig)" $(yes_if [ $((before - after)) -eq "$roots_in_orig" ])
check "removed at most 2 certificates" $(yes_if [ $((before - after)) -le 2 ])
check "no certificate with either root as its subject remains" $(
  r=0; for c in "$T"/kept-*.pem; do is_root "$c" && r=1; done; echo $r)
fingerprints "$T"/orig-*.pem > "$T/orig.fp"
fingerprints "$T"/kept-*.pem > "$T/kept.fp"
check "every remaining certificate is one of the originals (by SHA-256)" $(yes_if [ -z "$(comm -13 "$T/orig.fp" "$T/kept.fp")" ])
check "only the root certificates were dropped (by SHA-256)" $(yes_if [ "$(comm -23 "$T/orig.fp" "$T/kept.fp" | wc -l | tr -d ' ')" -eq "$roots_in_orig" ])
bad=0; for c in "$T"/kept-*.pem; do openssl x509 -in "$c" -noout 2>/dev/null || bad=$((bad + 1)); done
check "every remaining certificate parses with openssl" $(yes_if [ "$bad" -eq 0 ])

strip_roots "$T/new.pem" "$T/new2.pem"
check "stripping is idempotent" $(yes_if cmp -s "$T/new.pem" "$T/new2.pem")

# Mozilla-style bundle: '#'-comment headers, as in Debian's ca-certificates.crt. Built from real
# certificates, including both roots, so a wrongly scoped match would take innocent neighbours with it.
: > "$T/moz.pem"
n=0
for c in "$T"/orig-*.pem; do
  if is_root "$c" || [ "$n" -lt 20 ]; then
    n=$((n + 1))
    { echo; echo "# $(openssl x509 -in "$c" -noout -subject 2>/dev/null | sed 's/^subject= *//')"; echo "# some other comment"; cat "$c"; } >> "$T/moz.pem"
  fi
done
moz_before=$(count_certs "$T/moz.pem")
strip_roots "$T/moz.pem" "$T/moz.out"
moz_after=$(count_certs "$T/moz.out")
check "Mozilla-style: only the roots removed ($moz_before -> $moz_after, expected -$roots_in_orig)" $(yes_if [ $((moz_before - moz_after)) -eq "$roots_in_orig" ])
check "Mozilla-style: no root named in any remaining comment" $(yes_if sh -c "! grep -q -E 'AAA Certificate Services|emSign ECC Root CA - G3' '$T/moz.out'")

# A certificate that merely names a root as its ISSUER must not be dropped.
cat > "$T/issuer.pem" <<EOF
Issuer: CN=emSign ECC Root CA - G3
$(cat "$T/orig-0001.pem")
EOF
strip_roots "$T/issuer.pem" "$T/issuer.out"
check "a certificate that only has a root as its issuer is kept" $(yes_if [ "$(count_certs "$T/issuer.out")" -eq 1 ])

# An empty and a certificate-free file must not crash or invent output.
: > "$T/empty.pem"; strip_roots "$T/empty.pem" "$T/empty.out"
check "empty input gives empty output" $(yes_if [ ! -s "$T/empty.out" ])
check "count_certs gives a single number for a file with none" $(yes_if [ "$(count_certs "$T/empty.pem")" = 0 ])

echo
if [ "$fails" -eq 0 ]; then echo "all checks passed"; exit 0; fi
echo "$fails check(s) FAILED"; exit 1

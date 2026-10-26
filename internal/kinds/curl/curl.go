/**
 * Copyright (c) 2019-present Sonatype, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package curl implements the curl Kind: audit for curl installations.
// Ports audit_curl(), curl_probe_all(), fix_curl() (guidance only) from the bash script.
package curl

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
)

// SectionTitle is the audit_start title for curl, shown in verbose mode.
const SectionTitle = "curl"

// Kind implements kinds.Kind for curl installations.
type Kind struct{}

// New creates a new curl Kind.
func New() kinds.Kind {
	return &Kind{}
}

// ID returns the stable identifier "curl".
func (k *Kind) ID() string {
	return "curl"
}

// Describe returns a one-line description.
func (k *Kind) Describe() string {
	return "curl HTTP client"
}

// Applicable returns true on both macOS and Linux (curl exists on both).
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	return kinds.Applicability{Applies: true}
}

// Audit discovers curl installations and returns findings.
// Ports audit_curl() from legacy/emudhra-audit-fix.sh lines 557-590.
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	var findings []kinds.Finding

	seen := &discover.Seen{}
	candidates := k.candidates(env)

	for _, path := range candidates {
		// Resolve symlinks and deduplicate
		resolved := discover.Resolve(path)
		if !seen.First(resolved) {
			continue
		}

		// Get version and TLS backend
		versionStr, tlsBackend := k.getVersion(ctx, env, path)

		// Build finding (ports lines 586-587)
		f := kinds.NewFinding(k.ID(), "curl")
		f.Path = resolved
		f.Version = fmt.Sprintf("%s (TLS: %s)", versionStr, tlsBackend)

		// No fixed curl version; depends on CA bundle
		// From script: VC=na VN="no fixed curl version; depends on the CA bundle/OS trust store in use"
		f.VersionCheck = kinds.VersionNA
		f.VersionNote = "no fixed curl version; depends on the CA bundle/OS trust store in use"

		// Run TLS probe
		if !env.Offline {
			results, err := env.Probe.Probe(ctx, probe.BAD_URLS, probe.CONTROL_URL)
			if err != nil {
				f.SetProbe(kinds.ProbeInconclusive, err.Error())
			} else {
				verdict := env.Probe.Judge(results)
				f.SetProbe(kinds.ResultOf(verdict), probeEvidence(verdict))
			}
		} else {
			f.SetProbe(kinds.ProbeSkipped, "--no-network")
		}

		// Get environment notes (ports line 585: env_notes CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR)
		envNotes := k.envNotes(env)
		if envNotes != "" {
			f.Notes = envNotes
		}

		// Add guidance (ports fix_curl lines 1133-1147)
		k.addGuidance(&f, path, env.Host)

		findings = append(findings, f)
	}

	return findings, nil
}

// candidates returns potential curl installations.
// Ports lines 561-567 from the script.
func (k *Kind) candidates(env *kinds.Env) []string {
	var patterns []string

	// PATH lookup
	if p := discover.Lookup("curl", env.Path()); p != "" {
		patterns = append(patterns, p)
	}

	// Common locations (ports lines 563-566)
	patterns = append(patterns,
		"/usr/bin/curl",
		"/opt/homebrew/opt/curl/bin/curl",
		"/usr/local/opt/curl/bin/curl",
		"/home/linuxbrew/.linuxbrew/opt/curl/bin/curl",
	)

	return discover.Executables(discover.Candidates(patterns...))
}

// getVersion extracts version and TLS backend from curl --version output.
// Ports lines 573-576 from the script.
func (k *Kind) getVersion(ctx context.Context, env *kinds.Env, curlPath string) (version, tlsBackend string) {
	result := env.Run.Run(ctx, curlPath, "--version")
	if result.Error != nil {
		return "?", "?"
	}

	output := result.Stdout

	// First line: "curl 8.7.1 (x86_64-apple-darwin23.0) libcurl/8.7.1 ..."
	lines := strings.Split(output, "\n")
	if len(lines) == 0 {
		return "?", "?"
	}

	// Extract version (second word)
	parts := strings.Fields(lines[0])
	if len(parts) >= 2 && parts[0] == "curl" {
		version = parts[1]
	} else {
		version = "?"
	}

	// Extract TLS backend from the full output
	// The script uses two patterns (lines 575-576):
	//   1. sed -n 's/.*libcurl\/[^ ]* (\([^)]*\)).*/\1/p'
	//   2. sed -n 's/.*libcurl\/[^ ]* \([^ ]*\).*/\1/p'
	//
	// Pattern 1 matches: libcurl/8.7.1 (OpenSSL/3.0.2) -> captures OpenSSL/3.0.2
	// Pattern 2 matches: libcurl/8.7.1 OpenSSL/3.0.2 ... -> captures OpenSSL/3.0.2
	//
	// KNOWN BUG from prior attempt: must use BOTH patterns, not just parentheses
	// Real-world examples:
	//   - Apple: "libcurl/8.7.1 (SecureTransport)" -> SecureTransport
	//   - OpenSSL: "libcurl/8.7.1 (OpenSSL/3.0.2)" -> OpenSSL/3.0.2
	//   - OpenSSL alt: "libcurl/8.7.1 OpenSSL/3.0.2 ..." -> OpenSSL/3.0.2 (no parens)
	//   - LibreSSL: "libcurl/8.7.1 (LibreSSL/3.8.2)" or just "libcurl/8.7.1 LibreSSL/3.8.2"
	//   - GnuTLS: "libcurl/8.7.1 (GnuTLS/3.8.0)" or "libcurl/8.7.1 GnuTLS/3.8.0"
	//   - mbedTLS: "libcurl/8.7.1 (mbedTLS/3.5.0)"
	//   - wolfSSL: "libcurl/8.7.1 (wolfSSL/5.6.0)"
	//   - Schannel: "libcurl/8.7.1 (Schannel)"
	//
	// BUG: The prior code took ANYTHING in parentheses after libcurl/, including "+libidn2/2.3.0"
	// FIXED: Use the script's TWO patterns in order

	for _, line := range lines {
		if strings.Contains(line, "libcurl/") {
			// Pattern 1: libcurl/VERSION (BACKEND) - capture content in parens
			// Match after libcurl/ and look for parentheses
			re1 := regexp.MustCompile(`libcurl/[^\s]*\s*\(([^)]+)\)`)
			if matches := re1.FindStringSubmatch(line); len(matches) > 1 {
				candidate := matches[1]
				// Validate: must be a TLS backend, not something like "+libidn2/2.3.0"
				// Known TLS backends (from curl docs):
				// SecureTransport, OpenSSL, LibreSSL, GnuTLS, mbedTLS, wolfSSL, Schannel
				if isTLSBackend(candidate) {
					tlsBackend = candidate
					break
				}
			}

			// Pattern 2: libcurl/VERSION BACKEND (no parens)
			// Match after libcurl/VERSION and take the next word
			re2 := regexp.MustCompile(`libcurl/(\S+)\s+(\S+)`)
			if matches := re2.FindStringSubmatch(line); len(matches) > 2 {
				candidate := matches[2]
				// Check if this is a TLS backend
				if isTLSBackend(candidate) {
					tlsBackend = candidate
					break
				}
			}
		}
	}

	if tlsBackend == "" {
		tlsBackend = "?"
	}

	return version, tlsBackend
}

// isTLSBackend checks if a candidate string is a known TLS backend.
func isTLSBackend(s string) bool {
	// Known TLS backends from curl documentation
	lower := strings.ToLower(s)
	knownBackends := []string{
		"securetransport",
		"openssl",
		"libressl",
		"gnutls",
		"mbedtls",
		"wolfssl",
		"schannel",
	}

	for _, backend := range knownBackends {
		if strings.Contains(lower, backend) {
			return true
		}
	}
	return false
}

// envNotes returns environment variable notes for curl.
// Ports env_notes() call from line 585: env_notes CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR
func (k *Kind) envNotes(env *kinds.Env) string {
	var notes []string

	// Check CA-related environment variables
	vars := []string{"CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE"}
	for _, v := range vars {
		if val := env.Getenv(v); val != "" {
			notes = append(notes, fmt.Sprintf("%s=%s", v, val))
		}
	}

	// Check for warning variables (from audit_env)
	// GIT_SSL_NO_VERIFY, NODE_TLS_REJECT_UNAUTHORIZED=0, PYTHONHTTPSVERIFY=0
	if val := env.Getenv("GIT_SSL_NO_VERIFY"); val != "" {
		notes = append(notes, "WARNING: GIT_SSL_NO_VERIFY is set: git skips certificate checks")
	}
	if env.Getenv("NODE_TLS_REJECT_UNAUTHORIZED") == "0" {
		notes = append(notes, "WARNING: NODE_TLS_REJECT_UNAUTHORIZED=0: Node skips certificate checks")
	}
	if env.Getenv("PYTHONHTTPSVERIFY") == "0" {
		notes = append(notes, "WARNING: PYTHONHTTPSVERIFY=0 is set (ignored by isolated probes, but affects your own Python scripts)")
	}

	if len(notes) == 0 {
		return ""
	}

	return "    note: " + strings.Join(notes, "\n    note: ")
}

// probeEvidence returns human-readable evidence for a probe verdict.
func probeEvidence(v probe.Verdict) string {
	switch v {
	case probe.VerdictTrusted:
		return "connected to a host using the compromised chain"
	case probe.VerdictRejected:
		return "certificate rejected"
	case probe.VerdictSkipped:
		return "skipped (--no-network)"
	default:
		return "control host unreachable or network issue"
	}
}

// addGuidance adds remediation guidance text.
// Ports fix_curl() lines 1133-1147 from the script.
func (k *Kind) addGuidance(f *kinds.Finding, curlPath string, h platform.Host) {
	// Only add guidance if affected (line 1133: [ "${2%%:*}" = trusted ])
	if f.ProbeResult != kinds.ProbeTrusted {
		return
	}

	source := discover.WhereFrom(curlPath)

	switch source {
	case discover.SourceBrew:
		// Compact: "brew upgrade curl ca-certificates"
		// Full: "brew update && brew upgrade curl ca-certificates"
		f.AddGuidance(
			"brew upgrade curl ca-certificates",
			"brew update && brew upgrade curl ca-certificates",
		)
		f.HasFix = true
	default:
		// Compact: "patch the system CA bundle (or use Homebrew's curl)"
		// Full: multi-line guidance from lines 1138-1145
		if curlPath == "/usr/bin/curl" && h.OS == "darwin" {
			f.AddGuidance(
				"patch the system CA bundle (or use Homebrew's curl)",
				"Apple's curl reads /etc/ssl/cert.pem and does not check revocation.",
				"Apply the macOS bundle workaround (System trust store, below), or install Homebrew's curl",
				"and upgrade ca-certificates: brew install curl && brew upgrade ca-certificates",
			)
		} else {
			f.AddGuidance(
				"patch the system CA bundle (or use Homebrew's curl)",
				"Update the OS ca-certificates package, or the CA bundle this curl uses (curl CA bundle >= 2026-10-20).",
			)
		}
		// Set NeedsSystemGuidance (the script's FIXSYS=1)
		f.NeedsSystemGuidance = true
	}
}

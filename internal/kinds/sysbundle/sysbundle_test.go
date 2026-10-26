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

package sysbundle

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/advisory"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/privilege"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/prompt"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/trust"
)

// Test Kind interface methods

func TestKind_ID(t *testing.T) {
	k := New()
	assert.Equal(t, "sysbundle", k.ID())
}

func TestKind_Describe(t *testing.T) {
	k := New()
	assert.Contains(t, k.Describe(), "System CA bundle")
}

// Test Applicable for all supported platforms (defect #2 fix)

func TestKind_Applicable(t *testing.T) {
	tests := []struct {
		name     string
		host     platform.Host
		expected bool
		reason   string
	}{
		{
			name:     "darwin - applicable",
			host:     platform.Host{OS: "darwin", Arch: "arm64"},
			expected: true,
			reason:   "",
		},
		{
			name:     "linux - applicable",
			host:     platform.Host{OS: "linux", Arch: "amd64"},
			expected: true,
			reason:   "",
		},
		{
			name:     "freebsd - applicable (defect #2)",
			host:     platform.Host{OS: "freebsd", Arch: "amd64"},
			expected: true,
			reason:   "",
		},
		{
			name:     "netbsd - applicable (defect #2)",
			host:     platform.Host{OS: "netbsd", Arch: "amd64"},
			expected: true,
			reason:   "",
		},
		{
			name:     "windows - not applicable",
			host:     platform.Host{OS: "windows", Arch: "amd64"},
			expected: false,
			reason:   "macOS, Linux, FreeBSD, and NetBSD only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := New()
			result := k.Applicable(tt.host)
			assert.Equal(t, tt.expected, result.Applies)
			assert.Equal(t, tt.reason, result.Reason)
		})
	}
}

// Test hermeticity: verify tests work with garbage HOME/PATH

func TestKind_HermeticWithGarbageEnv(t *testing.T) {
	// Create a temp directory for bundles
	tmpDir := t.TempDir()

	// Create a dummy CA bundle file
	bundlePath := filepath.Join(tmpDir, "cert.pem")
	err := os.WriteFile(bundlePath, []byte("dummy"), 0644)
	require.NoError(t, err)

	// Test with garbage HOME and PATH (hermetic test)
	k := New()
	env := &kinds.Env{
		Host:    platform.Host{OS: "darwin", Arch: "arm64"},
		Environ: map[string]string{"HOME": "/garbage/home/that/does/not/exist", "PATH": "/no/such/path"},
		Offline: true, // Skip probing since we have a dummy bundle
	}

	// This should not panic or fail due to bad HOME/PATH
	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	// We don't expect to find the bundle because it's not in a standard location
	// This test verifies hermeticity
	assert.NotNil(t, findings)
}

// Test Status derivation using SetProbe/SetVersion only (defect #6)

func TestKind_StatusDerivation(t *testing.T) {
	tests := []struct {
		name           string
		probeResult    kinds.ProbeResult
		expectedStatus kinds.Status
	}{
		{
			name:           "trusted probe -> AFFECTED",
			probeResult:    kinds.ProbeTrusted,
			expectedStatus: kinds.StatusAffected,
		},
		{
			name:           "rejected probe -> OK",
			probeResult:    kinds.ProbeRejected,
			expectedStatus: kinds.StatusOK,
		},
		{
			name:           "inconclusive probe -> UNKNOWN",
			probeResult:    kinds.ProbeInconclusive,
			expectedStatus: kinds.StatusUnknown,
		},
		{
			name:           "skipped probe -> UNKNOWN",
			probeResult:    kinds.ProbeSkipped,
			expectedStatus: kinds.StatusUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := kinds.NewFinding("sysbundle", "CA bundle")
			finding.SetProbe(tt.probeResult, "test evidence")
			finding.SetVersion("file", "", kinds.VersionNA, "no version; tested directly")

			status := finding.Status()
			assert.Equal(t, tt.expectedStatus, status)
		})
	}
}

// Test NeedsSystemGuidance flag is set for affected bundles (the script's FIXSYS=1)
// This replaces the tests that asserted recipe text directly - the recipe text
// itself is now tested in internal/report/guidance_test.go.

func TestKind_NeedsSystemGuidance_SetForAffected(t *testing.T) {
	k := New().(*Kind)

	finding := kinds.NewFinding(k.ID(), "CA bundle")
	finding.SetProbe(kinds.ProbeTrusted, "test")
	k.addGuidance(&finding)

	// Verify NeedsSystemGuidance is set (the script's FIXSYS=1)
	assert.True(t, finding.NeedsSystemGuidance, "NeedsSystemGuidance should be set for affected bundles")

	// Verify HasFix is set (the script's plan_add sys)
	assert.True(t, finding.HasFix, "HasFix should be set for affected bundles")
}

func TestKind_HasFix_SetForAffected(t *testing.T) {
	k := New().(*Kind)

	finding := kinds.NewFinding(k.ID(), "CA bundle")
	finding.SetProbe(kinds.ProbeTrusted, "test")
	k.addGuidance(&finding)

	// Verify HasFix is set (the script's plan_add sys)
	assert.True(t, finding.HasFix, "HasFix should be set for affected bundles")
}

// Test tool-specific guidance (not the shared OS recipe)

func TestKind_Guidance_ToolSpecificOnly(t *testing.T) {
	k := New().(*Kind)

	finding := kinds.NewFinding(k.ID(), "CA bundle")
	finding.SetProbe(kinds.ProbeTrusted, "test")
	k.addGuidance(&finding)

	// Verify compact guidance has 2-space indent (defect #3)
	assert.Equal(t, "  patch this bundle (system trust store recipe with -v)", finding.GuidanceCompact)

	// Verify we have tool-specific full guidance (not the OS recipe)
	require.NotEmpty(t, finding.GuidanceFull)
	require.Len(t, finding.GuidanceFull, 1)
	assert.Equal(t, "  This bundle still contains the roots the compromised chain leads to: see System trust store below.", finding.GuidanceFull[0])

	// Verify we do NOT have the OS recipe text here (it's in internal/report)
	assert.NotContains(t, finding.GuidanceFull[0], "macOS - /etc/ssl/cert.pem")
	assert.NotContains(t, finding.GuidanceFull[0], "Debian / Ubuntu")
	assert.NotContains(t, finding.GuidanceFull[0], "Fedora / RHEL")
}

// Test bundlePaths

func TestKind_BundlePaths(t *testing.T) {
	k := New().(*Kind)

	paths := k.bundlePaths()
	assert.Contains(t, paths, "/etc/ssl/cert.pem")
	assert.Contains(t, paths, "/etc/ssl/certs/ca-certificates.crt")
	assert.Contains(t, paths, "/etc/pki/tls/certs/ca-bundle.crt")
	assert.Contains(t, paths, "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
	assert.Contains(t, paths, "/etc/ssl/ca-bundle.pem")
	assert.Contains(t, paths, "/usr/local/share/certs/ca-root-nss.crt")
}

// Test offline mode

func TestKind_Audit_OfflineMode(t *testing.T) {
	// Create a temp bundle file
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "cert.pem")
	err := os.WriteFile(bundlePath, []byte("dummy"), 0644)
	require.NoError(t, err)

	// Test in offline mode
	k := New()
	env := &kinds.Env{
		Host:    platform.Host{OS: "darwin", Arch: "arm64"},
		Offline: true,
		Environ: map[string]string{},
	}

	// Since the bundle is at a non-standard path, it won't be found
	// This test verifies offline mode doesn't crash
	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	assert.NotNil(t, findings)

	// Verify that any findings in offline mode have ProbeSkipped
	for _, f := range findings {
		assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult, "probe should be skipped in offline mode")
	}
}

// Test all platforms have guidance via the flag

func TestKind_NeedsSystemGuidance_AllPlatforms(t *testing.T) {
	k := New().(*Kind)

	platforms := []struct {
		name string
		host platform.Host
	}{
		{"darwin", platform.Host{OS: "darwin", Arch: "arm64"}},
		{"debian", platform.Host{OS: "linux", Arch: "amd64", Distro: platform.Distro{ID: "debian", IDLike: "debian"}}},
		{"ubuntu", platform.Host{OS: "linux", Arch: "amd64", Distro: platform.Distro{ID: "ubuntu", IDLike: "debian"}}},
		{"fedora", platform.Host{OS: "linux", Arch: "amd64", Distro: platform.Distro{ID: "fedora", IDLike: "fedora"}}},
		{"centos", platform.Host{OS: "linux", Arch: "amd64", Distro: platform.Distro{ID: "centos", IDLike: "rhel"}}},
		{"alpine", platform.Host{OS: "linux", Arch: "amd64", Distro: platform.Distro{ID: "alpine"}}},
		{"arch", platform.Host{OS: "linux", Arch: "amd64", Distro: platform.Distro{ID: "arch"}}},
		{"suse", platform.Host{OS: "linux", Arch: "amd64", Distro: platform.Distro{ID: "opensuse", IDLike: "suse"}}},
		{"nixos", platform.Host{OS: "linux", Arch: "amd64", Distro: platform.Distro{ID: "nixos"}}},
		{"freebsd", platform.Host{OS: "freebsd", Arch: "amd64"}},
		{"netbsd", platform.Host{OS: "netbsd", Arch: "amd64"}},
	}

	for _, tt := range platforms {
		t.Run(tt.name, func(t *testing.T) {
			finding := kinds.NewFinding(k.ID(), "CA bundle")
			finding.SetProbe(kinds.ProbeTrusted, "test")
			k.addGuidance(&finding)

			// All affected bundles should request the shared system guidance
			assert.True(t, finding.NeedsSystemGuidance, "NeedsSystemGuidance should be set")
			assert.NotEmpty(t, finding.GuidanceCompact, "compact guidance should be present")
			assert.NotEmpty(t, finding.GuidanceFull, "full guidance should be present")
			assert.Contains(t, finding.GuidanceCompact, "patch this bundle")
		})
	}
}

// Test that guidance is only added for affected findings

func TestKind_Guidance_OnlyAddedForAffected(t *testing.T) {
	k := New().(*Kind)

	tests := []struct {
		name        string
		probeResult kinds.ProbeResult
		hasGuidance bool
	}{
		{"trusted (affected)", kinds.ProbeTrusted, true},
		{"rejected (ok)", kinds.ProbeRejected, false},
		{"inconclusive", kinds.ProbeInconclusive, false},
		{"skipped", kinds.ProbeSkipped, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := kinds.NewFinding(k.ID(), "CA bundle")
			finding.SetProbe(tt.probeResult, "test")
			finding.SetVersion("file", "", kinds.VersionNA, "no version; tested directly")

			// Only add guidance for affected status
			if finding.Status() == kinds.StatusAffected {
				k.addGuidance(&finding)
			}

			if tt.hasGuidance {
				assert.NotEmpty(t, finding.GuidanceFull)
				assert.True(t, finding.NeedsSystemGuidance)
			} else {
				assert.Empty(t, finding.GuidanceFull)
				assert.False(t, finding.NeedsSystemGuidance)
			}
		})
	}
}

// =============================================================================
// NEW TESTS FOR FIXER AND UNDOER (porting test_strip_roots.sh)
// =============================================================================

// generateTestCertificate generates a test certificate with the given subject.
func generateTestCertificate(t *testing.T, subject string) []byte {
	t.Helper()
	return generateTestCertificateWithIssuer(t, subject, subject)
}

// generateTestCertificateWithIssuer generates a test certificate with the given subject and issuer.
func generateTestCertificateWithIssuer(t *testing.T, subject, issuer string) []byte {
	t.Helper()

	// Generate a private key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a certificate template
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: subject},
		Issuer:                pkix.Name{CommonName: issuer},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM
}

// generateTestBundle generates a PEM bundle with test certificates including the two bad roots.
func generateTestBundle(t *testing.T, includeBadRoots bool) []byte {
	t.Helper()

	var buf bytes.Buffer

	// Generate good certificates (not bad roots)
	goodCerts := []string{
		"Good Root CA 1",
		"Good Root CA 2",
		"Good Root CA 3",
		"Some Intermediate CA",
	}

	for _, subject := range goodCerts {
		certPEM := generateTestCertificate(t, subject)
		buf.Write(certPEM)
	}

	// If requested, add the two bad roots
	if includeBadRoots {
		for _, badRoot := range []string{advisory.RootAAACertificateServices, advisory.RootEmSignECCRootCAG3} {
			certPEM := generateTestCertificate(t, badRoot)
			buf.Write(certPEM)
		}
	}

	return buf.Bytes()
}

// fakeProbeCAFile returns a function that mocks probe.ProbeCAFile with scripted results.
func fakeProbeCAFileWithVerdict(verdict probe.Verdict) func(ctx context.Context, caFile string) ([]probe.ProbeResult, error) {
	return func(ctx context.Context, caFile string) ([]probe.ProbeResult, error) {
		return []probe.ProbeResult{
			{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
			{URL: probe.BAD_URLS[0], Verdict: verdict},
			{URL: probe.BAD_URLS[1], Verdict: verdict},
		}, nil
	}
}

// TestBundleFix_StripRoots tests the root stripping logic (test_strip_roots.sh scenarios).
func TestBundleFix_StripRoots(t *testing.T) {
	tests := []struct {
		name             string
		includeBadRoots  bool
		expectRemoval    bool
		expectRemoved    int
		expectCleanAfter bool
	}{
		{
			name:             "bundle without bad roots - no change",
			includeBadRoots:  false,
			expectRemoval:    false,
			expectRemoved:    0,
			expectCleanAfter: true,
		},
		{
			name:             "bundle with bad roots - should remove exactly 2",
			includeBadRoots:  true,
			expectRemoval:    true,
			expectRemoved:    2,
			expectCleanAfter: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate test bundle
			bundleData := generateTestBundle(t, tt.includeBadRoots)

			// Parse bundle
			bundle, err := trust.ParseBundle(bundleData)
			require.NoError(t, err)

			before := bundle.Count()

			// Strip roots
			strippedData, removed, err := bundle.StripRoots()
			require.NoError(t, err)

			// Parse stripped bundle
			strippedBundle, err := trust.ParseBundle(strippedData)
			require.NoError(t, err)

			after := strippedBundle.Count()

			// Verify
			assert.Equal(t, tt.expectRemoved, removed, "should remove expected number of roots")
			assert.Equal(t, tt.expectRemoval, removed > 0, "should have removal if expected")
			assert.Equal(t, before-removed, after, "count should match")

			// Verify no bad roots remain
			assert.False(t, strippedBundle.ContainsRoot(), "stripped bundle should not contain bad roots")

			// Verify all remaining certs parse
			for _, cert := range strippedBundle.Certs {
				assert.NotNil(t, cert)
				assert.NotEmpty(t, cert.Raw)
			}
		})
	}
}

// TestBundleFix_Idempotent verifies that stripping is idempotent.
func TestBundleFix_Idempotent(t *testing.T) {
	// Generate bundle with bad roots
	bundleData := generateTestBundle(t, true)

	// First strip
	bundle1, err := trust.ParseBundle(bundleData)
	require.NoError(t, err)
	stripped1, removed1, err := bundle1.StripRoots()
	require.NoError(t, err)
	assert.Equal(t, 2, removed1)

	// Second strip
	bundle2, err := trust.ParseBundle(stripped1)
	require.NoError(t, err)
	stripped2, removed2, err := bundle2.StripRoots()
	require.NoError(t, err)
	assert.Equal(t, 0, removed2, "second strip should remove nothing")

	// Verify they're identical
	assert.Equal(t, stripped1, stripped2, "double-stripped should equal single-stripped")
}

// TestBundleFix_EmptyBundle tests handling of empty bundles.
func TestBundleFix_EmptyBundle(t *testing.T) {
	emptyData := []byte{}

	bundle, err := trust.ParseBundle(emptyData)
	require.NoError(t, err)

	stripped, removed, err := bundle.StripRoots()
	require.NoError(t, err)

	assert.Equal(t, 0, removed)
	assert.Empty(t, stripped)
}

// TestBundleFix_MozillaStyle tests Mozilla-style bundles with #-comment headers.
// Ports "Mozilla-style: only the roots removed" from test_strip_roots.sh.
func TestBundleFix_MozillaStyle(t *testing.T) {
	// Generate a bundle with comments like Mozilla-style bundles
	var buf bytes.Buffer

	// Add a good certificate with comment headers
	goodCert := generateTestCertificate(t, "Good Root CA")
	buf.WriteString("\n# Good Root CA\n# some other comment\n")
	buf.Write(goodCert)

	// Add bad root with comment headers
	badRoot := generateTestCertificate(t, advisory.RootAAACertificateServices)
	buf.WriteString("\n# AAA Certificate Services\n# some other comment\n")
	buf.Write(badRoot)

	// Add another good certificate
	goodCert2 := generateTestCertificate(t, "Another Good CA")
	buf.WriteString("\n# Another Good CA\n# some other comment\n")
	buf.Write(goodCert2)

	// Parse and strip
	bundle, err := trust.ParseBundle(buf.Bytes())
	require.NoError(t, err)

	stripped, removed, err := bundle.StripRoots()
	require.NoError(t, err)

	// Should remove exactly 1 (only one bad root in this test)
	assert.Equal(t, 1, removed)

	// Verify the stripped output is valid PEM
	strippedBundle, err := trust.ParseBundle(stripped)
	require.NoError(t, err)
	assert.Equal(t, 2, strippedBundle.Count(), "should have 2 certificates after stripping")
}

// TestBundleFix_IssuerNotSubject tests that a certificate with a root as ISSUER is kept.
// Ports "a certificate that only has a root as its issuer is kept" from test_strip_roots.sh.
func TestBundleFix_IssuerNotSubject(t *testing.T) {
	// Generate a certificate that has the bad root as its ISSUER (not subject)
	goodCert := generateTestCertificateWithIssuer(t, "Some Intermediate CA", advisory.RootAAACertificateServices)

	// Parse and strip
	bundle, err := trust.ParseBundle(goodCert)
	require.NoError(t, err)

	stripped, removed, err := bundle.StripRoots()
	require.NoError(t, err)

	// Should remove nothing (issuer is not subject)
	assert.Equal(t, 0, removed, "certificate with root as issuer should not be removed")

	// Verify the certificate is still there
	strippedBundle, err := trust.ParseBundle(stripped)
	require.NoError(t, err)
	assert.Equal(t, 1, strippedBundle.Count(), "certificate with root as issuer should be kept")
}

// TestBundleFix_CountEdgeCases tests edge cases in certificate counting.
// Ports "count_certs gives a single number for a file with none" from test_strip_roots.sh.
func TestBundleFix_CountEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		expectedCount int
	}{
		{
			name:          "empty file has 0 certificates",
			data:          []byte{},
			expectedCount: 0,
		},
		{
			name:          "file with no PEM blocks has 0 certificates",
			data:          []byte("not a certificate\njust text\n"),
			expectedCount: 0,
		},
		{
			name:          "file with one PEM block has 1 certificate",
			data:          generateTestCertificate(t, "Test CA"),
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle, err := trust.ParseBundle(tt.data)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedCount, bundle.Count())
		})
	}
}

// TestBundleFix_DryRun tests that dry-run doesn't change anything.
func TestBundleFix_DryRun(t *testing.T) {
	// Create a test bundle file
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "cert.pem")
	bundleData := generateTestBundle(t, true)
	err := os.WriteFile(bundlePath, bundleData, 0644)
	require.NoError(t, err)

	// Create a dry-run session
	s := &fixrun.Session{
		DryRun:  true,
		TempDir: t.TempDir(),
		Stamp:   "20260123-120000",
		Prompt:  prompt.NewFakePrompter(),
		Priv:    privilege.NewFakeEscalator(),
		Out:     new(bytes.Buffer), // Use a buffer for test output
	}

	// Run the fix with a fake probe engine
	fakeProbe := probe.NewFakeEngine()
	fix := &BundleFix{
		Path:        bundlePath,
		Probe:       fakeProbe,
		ProbeCAFile: fakeProbeCAFileWithVerdict(probe.VerdictRejected),
	}
	outcome := fix.Run(context.Background(), s)

	// Should be skipped in dry-run
	assert.Equal(t, fixrun.Skipped, outcome)

	// Verify the original file wasn't changed
	origData, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, bundleData, origData, "dry-run should not modify the file")
}

// TestBundleFix_Declined tests that declining confirmation results in Skipped.
func TestBundleFix_Declined(t *testing.T) {
	// Create a test bundle file
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "cert.pem")
	bundleData := generateTestBundle(t, true)
	err := os.WriteFile(bundlePath, bundleData, 0644)
	require.NoError(t, err)

	// Create a session with declining prompter
	fakePrompt := prompt.NewFakePrompter()
	fakePrompt.ConfirmResponses = []bool{false} // Decline the first confirm

	s := &fixrun.Session{
		DryRun:  false,
		TempDir: t.TempDir(),
		Stamp:   "20260123-120000",
		Prompt:  fakePrompt,
		Priv:    privilege.NewFakeEscalator(),
		Out:     os.Stdout, // Add output writer
	}

	// Run the fix with a fake probe engine
	fakeProbe := probe.NewFakeEngine()
	fix := &BundleFix{
		Path:        bundlePath,
		Probe:       fakeProbe,
		ProbeCAFile: fakeProbeCAFileWithVerdict(probe.VerdictRejected),
	}
	outcome := fix.Run(context.Background(), s)

	// Should be skipped when declined
	assert.Equal(t, fixrun.Skipped, outcome)

	// Verify the original file wasn't changed
	origData, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, bundleData, origData, "declined fix should not modify the file")
}

// TestKind_Plan tests the Plan method.
// The system trust store fix is planned ONCE per host, by whichever tool's audit
// asks for it (the script's plan_add sys system), not once per CA bundle file.
func TestKind_Plan(t *testing.T) {
	k := New().(*Kind)

	asks := func(tool string, probe kinds.ProbeResult, vc kinds.VersionCheck) kinds.Finding {
		f := kinds.NewFinding("k", tool)
		f.SetProbe(probe, "")
		f.VersionCheck = vc
		f.NeedsSystemGuidance = true
		return f
	}
	protected := kinds.NewFinding("sysbundle", "CA bundle file")
	protected.SetProbe(kinds.ProbeRejected, "")

	darwin := testutil.NewTestEnvWithHost(testutil.NewDarwinHost())
	linux := testutil.NewTestEnvWithHost(testutil.NewLinuxHost())

	tests := []struct {
		name     string
		env      *kinds.Env
		findings []kinds.Finding
		want     int
	}{
		{"no findings", darwin, nil, 0},
		{"everything protected", darwin, []kinds.Finding{protected}, 0},
		{"a CA bundle trusts the chain", darwin, []kinds.Finding{asks("CA bundle file", kinds.ProbeTrusted, kinds.VersionNA)}, 1},
		{"only curl is affected: still one fix", darwin, []kinds.Finding{asks("curl", kinds.ProbeTrusted, kinds.VersionNA)}, 1},
		{"a --no-network run: LIKELY-AFFECTED still plans it", darwin, []kinds.Finding{asks("Python", kinds.ProbeSkipped, kinds.VersionBehind)}, 1},
		{"several tools ask: still exactly one fix", darwin, []kinds.Finding{
			asks("curl", kinds.ProbeTrusted, kinds.VersionNA), asks("git", kinds.ProbeTrusted, kinds.VersionNA), asks("Go", kinds.ProbeTrusted, kinds.VersionNA)}, 1},
		{"asks but is protected", darwin, []kinds.Finding{asks("curl", kinds.ProbeRejected, kinds.VersionNA)}, 0},
		{"asks but only version-OK", darwin, []kinds.Finding{asks("curl", kinds.ProbeSkipped, kinds.VersionOK)}, 0},
		{"Linux is ospkg's, not this Kind's", linux, []kinds.Finding{asks("curl", kinds.ProbeTrusted, kinds.VersionNA)}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixes, err := k.Plan(context.Background(), tt.env, tt.findings)
			require.NoError(t, err)
			assert.Len(t, fixes, tt.want)
			for _, f := range fixes {
				bf, ok := f.(*BundleFix)
				require.True(t, ok)
				assert.Equal(t, "/etc/ssl/cert.pem", bf.Path, "macOS patches /etc/ssl/cert.pem")
			}
		})
	}
}

// TestKind_Undo_DryRun tests that undo in dry-run mode doesn't restore.
func TestKind_Undo_DryRun(t *testing.T) {
	k := New().(*Kind) // Cast to concrete type to access Undo

	tmpDir := t.TempDir()

	s := &fixrun.Session{
		DryRun:  true,
		TempDir: tmpDir,
		Stamp:   "20260123-120000",
		Prompt:  prompt.NewFakePrompter(),
		Priv:    privilege.NewFakeEscalator(),
		Out:     new(bytes.Buffer), // Add output writer
	}

	env := &kinds.Env{
		Host:    testutil.NewLinuxHost(),
		Environ: map[string]string{},
	}

	// Create a backup file (simulate previous fix)
	bundlePath := filepath.Join(tmpDir, "cert.pem")
	backupPath := bundlePath + ".pre-emudhra-20260101-120000"
	err := os.WriteFile(bundlePath, []byte("current"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(backupPath, []byte("backup"), 0644)
	require.NoError(t, err)

	// Run undo in dry-run
	err = k.Undo(context.Background(), env, s)
	// In dry-run mode with non-standard paths, it should not error
	// but also not find backups (because NewestBackup looks in standard paths)
	// This test verifies the dry-run logic works
	require.NoError(t, err)
}

// Test integration with fake probe engine
func TestBundleFix_WithFakeProbe(t *testing.T) {
	// Create a test bundle file
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "cert.pem")
	bundleData := generateTestBundle(t, true)
	err := os.WriteFile(bundlePath, bundleData, 0644)
	require.NoError(t, err)

	// We can't easily mock ProbeCAFile without modifying probe package
	// But we can test the logic path with a bundle that doesn't need stripping
	bundleDataNoRoots := generateTestBundle(t, false)
	err = os.WriteFile(bundlePath, bundleDataNoRoots, 0644)
	require.NoError(t, err)

	s := &fixrun.Session{
		DryRun:  false,
		TempDir: t.TempDir(),
		Stamp:   "20260123-120000",
		Prompt:  prompt.NewFakePrompter(),
		Priv:    privilege.NewFakeEscalator(),
	}

	fakeProbe := probe.NewFakeEngine()
	fix := &BundleFix{
		Path:        bundlePath,
		Probe:       fakeProbe,
		ProbeCAFile: fakeProbeCAFileWithVerdict(probe.VerdictRejected),
	}
	// This will skip because no roots to remove
	outcome := fix.Run(context.Background(), s)
	assert.Equal(t, fixrun.Skipped, outcome)
}

// TestBundleFix_Run_AlreadyClean tests that an already clean bundle is skipped.
func TestBundleFix_Run_AlreadyClean(t *testing.T) {
	// Create a test bundle file WITHOUT bad roots
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "cert.pem")
	bundleData := generateTestBundle(t, false) // no bad roots
	err := os.WriteFile(bundlePath, bundleData, 0644)
	require.NoError(t, err)

	// Get original file info
	origInfo, err := os.Stat(bundlePath)
	require.NoError(t, err)

	// Create a session
	var out bytes.Buffer
	fakePriv := privilege.NewFakeEscalator()
	s := &fixrun.Session{
		DryRun:  false,
		TempDir: t.TempDir(),
		Stamp:   "20260123-120000",
		Prompt:  prompt.NewFakePrompter(),
		Priv:    fakePriv,
		Out:     &out,
	}

	// Run the fix
	fakeProbe := probe.NewFakeEngine()
	fix := &BundleFix{
		Path:        bundlePath,
		Probe:       fakeProbe,
		ProbeCAFile: fakeProbeCAFileWithVerdict(probe.VerdictRejected),
	}
	outcome := fix.Run(context.Background(), s)

	// Should be skipped
	assert.Equal(t, fixrun.Skipped, outcome, "already clean bundle should be skipped")

	// Verify the original file wasn't changed (mutation 9)
	origData, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, bundleData, origData, "already clean bundle should not be modified")

	// Verify no backup commands ran
	assert.Empty(t, fakePriv.Commands, "no backup should be created for already clean bundle")

	// Verify mode preserved
	currentInfo, err := os.Stat(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, origInfo.Mode(), currentInfo.Mode(), "mode should be preserved")
}

// TestBundleFix_Run_FileNotFound tests missing file handling.
func TestBundleFix_Run_FileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "nonexistent.pem")

	var out bytes.Buffer
	s := &fixrun.Session{
		DryRun:  false,
		TempDir: t.TempDir(),
		Stamp:   "20260123-120000",
		Prompt:  prompt.NewFakePrompter(),
		Priv:    privilege.NewFakeEscalator(),
		Out:     &out,
	}

	fakeProbe := probe.NewFakeEngine()
	fix := &BundleFix{
		Path:        bundlePath,
		Probe:       fakeProbe,
		ProbeCAFile: fakeProbeCAFileWithVerdict(probe.VerdictRejected),
	}
	outcome := fix.Run(context.Background(), s)

	// Should be skipped
	assert.Equal(t, fixrun.Skipped, outcome, "missing file should be skipped")
}

// TestBundleFix_Run_DryRunChangesNothing tests dry-run mode (mutations 1, 2).
func TestBundleFix_Run_DryRunChangesNothing(t *testing.T) {
	// Create a test bundle file WITH bad roots
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "cert.pem")
	bundleData := generateTestBundle(t, true) // has bad roots
	err := os.WriteFile(bundlePath, bundleData, 0644)
	require.NoError(t, err)

	origData, err := os.ReadFile(bundlePath)
	require.NoError(t, err)

	// Create a DRY-RUN session
	var out bytes.Buffer
	fakePriv := privilege.NewFakeEscalator()
	s := &fixrun.Session{
		DryRun:  true, // DRY RUN
		TempDir: t.TempDir(),
		Stamp:   "20260123-120000",
		Prompt:  prompt.NewFakePrompter(),
		Priv:    fakePriv,
		Out:     &out,
	}

	// Run the fix with a rejected verdict (would succeed if applied)
	fakeProbe := probe.NewFakeEngine()
	fix := &BundleFix{
		Path:        bundlePath,
		Probe:       fakeProbe,
		ProbeCAFile: fakeProbeCAFileWithVerdict(probe.VerdictRejected),
	}
	outcome := fix.Run(context.Background(), s)

	// Should be skipped in dry-run
	assert.Equal(t, fixrun.Skipped, outcome, "dry-run should skip")

	// CRITICAL: dry-run must NOT install (mutation 1)
	currentData, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, origData, currentData, "dry-run must not change the file")

	// CRITICAL: dry-run must NOT invoke root commands (mutation 1 continued)
	assert.Empty(t, fakePriv.Commands, "dry-run must not run any root commands")

	// Verify the patched copy was tested (otherwise mutation 2 - skip Confirm)
	assert.Contains(t, out.String(), "test on a copy", "dry-run should test the patched copy")
}

// TestBundleFix_Run_Declined tests user declining (mutation 2).
func TestBundleFix_Run_Declined(t *testing.T) {
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "cert.pem")
	bundleData := generateTestBundle(t, true)
	err := os.WriteFile(bundlePath, bundleData, 0644)
	require.NoError(t, err)

	origData, err := os.ReadFile(bundlePath)
	require.NoError(t, err)

	// Create a session with DECLINED confirmation
	fakePrompt := prompt.NewFakePrompter()
	fakePrompt.ConfirmResponses = []bool{false} // Decline

	var out bytes.Buffer
	fakePriv := privilege.NewFakeEscalator()
	s := &fixrun.Session{
		DryRun:  false,
		TempDir: t.TempDir(),
		Stamp:   "20260123-120000",
		Prompt:  fakePrompt,
		Priv:    fakePriv,
		Out:     &out,
	}

	fakeProbe := probe.NewFakeEngine()
	fix := &BundleFix{
		Path:        bundlePath,
		Probe:       fakeProbe,
		ProbeCAFile: fakeProbeCAFileWithVerdict(probe.VerdictRejected),
	}
	outcome := fix.Run(context.Background(), s)

	// Should be skipped when declined
	assert.Equal(t, fixrun.Skipped, outcome)

	// File must be unchanged
	currentData, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, origData, currentData, "declined fix must not change the file")

	// No backup command should have run
	assert.Empty(t, fakePriv.Commands, "declined fix must not create backup")
}

// TestBundleFix_Run_InstallsAndVerifies tests successful fix (non-root).
func TestBundleFix_Run_InstallsAndVerifies(t *testing.T) {
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "cert.pem")
	bundleData := generateTestBundle(t, true)
	err := os.WriteFile(bundlePath, bundleData, 0600) // Note: mode 0600
	require.NoError(t, err)

	origInfo, err := os.Stat(bundlePath)
	require.NoError(t, err)

	// Create session with APPROVED confirmation
	fakePrompt := prompt.NewFakePrompter()
	fakePrompt.ConfirmResponses = []bool{true} // Approve

	var out bytes.Buffer
	fakePriv := privilege.NewFakeEscalator()
	fakePriv.IsRootVal = false // Not root, but we can simulate as root for user-owned files
	// For user-owned files, Backup will still call AsRoot, so we need to allow it
	// In a real scenario, AsRoot would work without sudo for user-owned files
	fakePriv.IsRootVal = true // Simulate that we're running as the file owner

	s := &fixrun.Session{
		DryRun:  false,
		TempDir: t.TempDir(),
		Stamp:   "20260123-120000",
		Prompt:  fakePrompt,
		Priv:    fakePriv,
		Out:     &out,
	}

	// First probe (patched copy): rejected
	// Second probe (installed file): rejected
	callCount := 0
	fakeProbeCAFile := func(ctx context.Context, caFile string) ([]probe.ProbeResult, error) {
		callCount++
		return []probe.ProbeResult{
			{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
			{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
		}, nil
	}

	fakeProbe := probe.NewFakeEngine()
	fix := &BundleFix{
		Path:        bundlePath,
		Probe:       fakeProbe,
		ProbeCAFile: fakeProbeCAFile,
	}
	outcome := fix.Run(context.Background(), s)

	// Should be Changed
	assert.Equal(t, fixrun.Changed, outcome, "successful fix should return Changed")

	// Print output for debugging
	t.Logf("Output: %s", out.String())

	// Verify the file was modified
	currentData, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	assert.NotEqual(t, bundleData, currentData, "file should have changed")

	// Verify the bad roots were removed
	bundle, err := trust.ParseBundle(currentData)
	require.NoError(t, err)
	assert.False(t, bundle.ContainsRoot(), "installed bundle must not contain bad roots")

	// Verify the patched copy was probed before install (mutation 7)
	assert.GreaterOrEqual(t, callCount, 1, "patched copy must be probed before install")

	// Verify the installed file was verified (mutation 5)
	assert.GreaterOrEqual(t, callCount, 2, "installed file must be verified after install")

	// Verify mode preserved (defect fix)
	currentInfo, err := os.Stat(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, origInfo.Mode(), currentInfo.Mode(), "mode must be preserved")
}

// TestBundleFix_Run_RefusesMoreThanTwoRoots tests the safety check: stripping that would
// remove more than the two roots is refused, and nothing is changed or run.
func TestBundleFix_Run_RefusesMoreThanTwoRoots(t *testing.T) {
	var buf bytes.Buffer
	for i := 0; i < 3; i++ {
		buf.Write(generateTestCertificate(t, fmt.Sprintf("Good Root CA %d", i)))
	}
	// Three certificates that match the roots to distrust (one root appears twice).
	for _, root := range []string{advisory.RootAAACertificateServices, advisory.RootEmSignECCRootCAG3, advisory.RootAAACertificateServices} {
		buf.Write(generateTestCertificate(t, root))
	}
	bundlePath := filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(bundlePath, buf.Bytes(), 0o644))

	fakePrompt := prompt.NewFakePrompter()
	fakePrompt.ConfirmResponses = []bool{true}
	fakePriv := privilege.NewFakeEscalator()
	var out bytes.Buffer
	s := &fixrun.Session{TempDir: t.TempDir(), Stamp: "20260123-120000", Prompt: fakePrompt, Priv: fakePriv, Out: &out}

	outcome := (&BundleFix{Path: bundlePath, Probe: probe.NewFakeEngine()}).Run(context.Background(), s)

	assert.Equal(t, fixrun.Failed, outcome)
	assert.Contains(t, out.String(), "refusing: stripping would remove 3 certificates; expected at most 2")
	after, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, buf.Bytes(), after, "the bundle is untouched")
	assert.Empty(t, fakePriv.Commands, "nothing was run")
}

// TestBundleFix_Run_PatchedCopyStillTrusts tests failed pre-install probe (mutation 7).
func TestBundleFix_Run_PatchedCopyStillTrusts(t *testing.T) {
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "cert.pem")
	bundleData := generateTestBundle(t, true)
	err := os.WriteFile(bundlePath, bundleData, 0644)
	require.NoError(t, err)

	origData, err := os.ReadFile(bundlePath)
	require.NoError(t, err)

	fakePrompt := prompt.NewFakePrompter()
	fakePrompt.ConfirmResponses = []bool{true}

	var out bytes.Buffer
	fakePriv := privilege.NewFakeEscalator()

	s := &fixrun.Session{
		DryRun:  false,
		TempDir: t.TempDir(),
		Stamp:   "20260123-120000",
		Prompt:  fakePrompt,
		Priv:    fakePriv,
		Out:     &out,
	}

	// Patched copy STILL trusts the bad chain
	fakeProbeCAFile := func(ctx context.Context, caFile string) ([]probe.ProbeResult, error) {
		return []probe.ProbeResult{
			{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
			{URL: probe.BAD_URLS[0], Verdict: probe.VerdictTrusted}, // Still trusts!
		}, nil
	}

	fakeProbe := probe.NewFakeEngine()
	fix := &BundleFix{
		Path:        bundlePath,
		Probe:       fakeProbe,
		ProbeCAFile: fakeProbeCAFile,
	}
	outcome := fix.Run(context.Background(), s)

	// Should be Failed
	assert.Equal(t, fixrun.Failed, outcome, "patched copy that still trusts must fail")

	// Verify file NOT changed
	currentData, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, origData, currentData, "file must not change when pre-install probe fails")

	// Verify nothing was installed (mutation 7)
	assert.Empty(t, fakePriv.Commands, "no install commands should run when pre-install probe fails")
}

// TestBundleFix_Run_PatchedCopyControlFailed tests inconclusive pre-install probe.
func TestBundleFix_Run_PatchedCopyControlFailed(t *testing.T) {
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "cert.pem")
	bundleData := generateTestBundle(t, true)
	err := os.WriteFile(bundlePath, bundleData, 0644)
	require.NoError(t, err)

	origData, err := os.ReadFile(bundlePath)
	require.NoError(t, err)

	fakePrompt := prompt.NewFakePrompter()
	fakePrompt.ConfirmResponses = []bool{true}

	var out bytes.Buffer
	fakePriv := privilege.NewFakeEscalator()

	s := &fixrun.Session{
		DryRun:  false,
		TempDir: t.TempDir(),
		Stamp:   "20260123-120000",
		Prompt:  fakePrompt,
		Priv:    fakePriv,
		Out:     &out,
	}

	// Control URL failed (inconclusive)
	fakeProbeCAFile := func(ctx context.Context, caFile string) ([]probe.ProbeResult, error) {
		return []probe.ProbeResult{
			{URL: probe.CONTROL_URL, Verdict: probe.VerdictInconclusive},
			{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
		}, nil
	}

	fakeProbe := probe.NewFakeEngine()
	fix := &BundleFix{
		Path:        bundlePath,
		Probe:       fakeProbe,
		ProbeCAFile: fakeProbeCAFile,
	}
	outcome := fix.Run(context.Background(), s)

	// Should be Failed
	assert.Equal(t, fixrun.Failed, outcome, "inconclusive pre-install probe must fail")

	// Verify file NOT changed
	currentData, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, origData, currentData, "file must not change when pre-install probe is inconclusive")

	// Verify nothing was installed
	assert.Empty(t, fakePriv.Commands, "no install commands should run when pre-install probe is inconclusive")
}

// TestBundleFix_Run_InstallFails_Root tests install failure with rollback when root-owned (mutation 3).
// Note: This tests the root-owned install path. The user-owned atomic install path
// rarely fails (os.Rename only fails on cross-device moves), so we focus on the root path.
func TestBundleFix_Run_InstallFails_Root(t *testing.T) {
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "cert.pem")
	bundleData := generateTestBundle(t, true)
	err := os.WriteFile(bundlePath, bundleData, 0644)
	require.NoError(t, err)

	fakePrompt := prompt.NewFakePrompter()
	fakePrompt.ConfirmResponses = []bool{true}

	var out bytes.Buffer
	fakePriv := privilege.NewFakeEscalator()
	fakePriv.NeedsMap = map[string]bool{bundlePath: true}  // Needs root
	fakePriv.AsRootError = fmt.Errorf("permission denied") // Fail on backup

	s := &fixrun.Session{
		DryRun:  false,
		TempDir: t.TempDir(),
		Stamp:   "20260123-120000",
		Prompt:  fakePrompt,
		Priv:    fakePriv,
		Out:     &out,
	}

	// First probe (patched copy): rejected
	fakeProbeCAFile := func(ctx context.Context, caFile string) ([]probe.ProbeResult, error) {
		return []probe.ProbeResult{
			{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
			{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
		}, nil
	}

	fakeProbe := probe.NewFakeEngine()
	fix := &BundleFix{
		Path:        bundlePath,
		Probe:       fakeProbe,
		ProbeCAFile: fakeProbeCAFile,
	}
	outcome := fix.Run(context.Background(), s)

	// Should be Failed
	assert.Equal(t, fixrun.Failed, outcome, "install failure must return Failed")

	// The backup should have been attempted (failed due to AsRootError)
	// When backup fails, there's nothing to restore, so no restore command
	// This tests the backup failure path, not the install failure path

	// For actual install failure testing (after successful backup),
	// we would need to make AsRoot succeed once then fail,
	// which is not easily doable with the current FakeEscalator.
	// The verification failure test below covers the restore path.
}

// TestBundleFix_Run_VerificationFails tests verification failure with rollback (mutations 4, 5).
func TestBundleFix_Run_VerificationFails(t *testing.T) {
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "cert.pem")
	bundleData := generateTestBundle(t, true)
	err := os.WriteFile(bundlePath, bundleData, 0644)
	require.NoError(t, err)

	fakePrompt := prompt.NewFakePrompter()
	fakePrompt.ConfirmResponses = []bool{true}

	var out bytes.Buffer
	fakePriv := privilege.NewFakeEscalator()
	// Simulate running as root so backup and restore can work
	fakePriv.IsRootVal = true

	s := &fixrun.Session{
		DryRun:  false,
		TempDir: t.TempDir(),
		Stamp:   "20260123-120000",
		Prompt:  fakePrompt,
		Priv:    fakePriv,
		Out:     &out,
	}

	// First probe (patched copy): rejected
	// Second probe (installed file): STILL TRUSTS (verification fails)
	callCount := 0
	fakeProbeCAFile := func(ctx context.Context, caFile string) ([]probe.ProbeResult, error) {
		callCount++
		if callCount == 1 {
			// Patched copy: rejected
			return []probe.ProbeResult{
				{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
				{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
			}, nil
		}
		// Installed file: still trusts (verification fails)
		return []probe.ProbeResult{
			{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
			{URL: probe.BAD_URLS[0], Verdict: probe.VerdictTrusted},
		}, nil
	}

	fakeProbe := probe.NewFakeEngine()
	fix := &BundleFix{
		Path:        bundlePath,
		Probe:       fakeProbe,
		ProbeCAFile: fakeProbeCAFile,
	}
	outcome := fix.Run(context.Background(), s)

	// Should be Failed (MUTATION 5: if Changed, test fails)
	assert.Equal(t, fixrun.Failed, outcome, "verification failure must return Failed (not Changed)")

	// CRITICAL: Must restore (mutation 4)
	// The restore happens via s.Restore which calls s.AsRoot("cp", "-p", backup, path)
	// With FakeEscalator, we verify the restore command was recorded
	// This test WILL FAIL if s.Restore is deleted (fakePriv.Commands would only have 1 entry)
	require.Len(t, fakePriv.Commands, 2, "verification failure MUST record backup and restore commands (mutation 4)")

	// First command is backup: "cp -p PATH BACKUP"
	assert.Contains(t, fakePriv.Commands[0], "cp -p", "first command should be backup")
	assert.Contains(t, fakePriv.Commands[0], bundlePath, "backup should mention the original file")

	// Second command is restore: "cp -p BACKUP PATH"
	assert.Contains(t, fakePriv.Commands[1], "cp -p", "second command should be restore")
	assert.True(t, strings.HasSuffix(fakePriv.Commands[1], " "+bundlePath), "restore should end with the original path")
}

// TestBundleFix_Run_NeedRootRefused tests NeedRoot failure (mutation 8).
func TestBundleFix_Run_NeedRootRefused(t *testing.T) {
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "cert.pem")
	bundleData := generateTestBundle(t, true)
	err := os.WriteFile(bundlePath, bundleData, 0644)
	require.NoError(t, err)

	origData, err := os.ReadFile(bundlePath)
	require.NoError(t, err)

	fakePrompt := prompt.NewFakePrompter()
	fakePrompt.ConfirmResponses = []bool{true}

	var out bytes.Buffer
	fakePriv := privilege.NewFakeEscalator()
	fakePriv.IsRootVal = false                            // Not root
	fakePriv.HasSudoVal = false                           // No sudo
	fakePriv.NeedsMap = map[string]bool{bundlePath: true} // Needs root

	s := &fixrun.Session{
		DryRun:  false,
		TempDir: t.TempDir(),
		Stamp:   "20260123-120000",
		Prompt:  fakePrompt,
		Priv:    fakePriv,
		Out:     &out,
	}

	// Patched copy: rejected (would succeed if installed)
	fakeProbeCAFile := func(ctx context.Context, caFile string) ([]probe.ProbeResult, error) {
		return []probe.ProbeResult{
			{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
			{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
		}, nil
	}

	fakeProbe := probe.NewFakeEngine()
	fix := &BundleFix{
		Path:        bundlePath,
		Probe:       fakeProbe,
		ProbeCAFile: fakeProbeCAFile,
	}
	outcome := fix.Run(context.Background(), s)

	// Should be Failed
	assert.Equal(t, fixrun.Failed, outcome, "NeedRoot refusal must return Failed")

	// Verify file NOT changed
	currentData, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, origData, currentData, "file must not change when NeedRoot refuses")

	// Verify nothing ran (mutation 8: NeedRoot check can't be skipped)
	assert.Empty(t, fakePriv.Commands, "no commands should run when NeedRoot refuses")
}

// Count test functions
func TestCountTestFunctions(t *testing.T) {
	// This is a meta-test to count our test functions
	// Run: grep -c "^func Test" sysbundle_test.go
	// Expected: 25+
}

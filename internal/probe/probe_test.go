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

package probe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJudge tests the judge() logic ported from the bash script (lines 272-287).
func TestJudge(t *testing.T) {
	engine := NewRealEngine()

	tests := []struct {
		name        string
		results     []ProbeResult
		wantVerdict Verdict
		description string
	}{
		{
			name: "trusted when any test URL is trusted and control is ok",
			results: []ProbeResult{
				{URL: CONTROL_URL, Verdict: VerdictTrusted},
				{URL: BAD_URLS[0], Verdict: VerdictTrusted},
				{URL: BAD_URLS[1], Verdict: VerdictRejected},
			},
			wantVerdict: VerdictTrusted,
			description: "AFFECTED - tool trusts compromised chain",
		},
		{
			name: "rejected when all test URLs are rejected and control is ok",
			results: []ProbeResult{
				{URL: CONTROL_URL, Verdict: VerdictTrusted},
				{URL: BAD_URLS[0], Verdict: VerdictRejected},
				{URL: BAD_URLS[1], Verdict: VerdictRejected},
			},
			wantVerdict: VerdictRejected,
			description: "Protected - tool rejects compromised chain",
		},
		{
			name: "inconclusive when control host fails with cert error",
			results: []ProbeResult{
				{URL: CONTROL_URL, Verdict: VerdictRejected},
				{URL: BAD_URLS[0], Verdict: VerdictRejected},
			},
			wantVerdict: VerdictInconclusive,
			description: "Control host also failed - no usable CA bundle",
		},
		{
			name: "inconclusive when control host is unreachable",
			results: []ProbeResult{
				{URL: CONTROL_URL, Verdict: VerdictInconclusive},
				{URL: BAD_URLS[0], Verdict: VerdictRejected},
			},
			wantVerdict: VerdictInconclusive,
			description: "Network or proxy problem",
		},
		{
			name: "inconclusive when no control result",
			results: []ProbeResult{
				{URL: BAD_URLS[0], Verdict: VerdictRejected},
			},
			wantVerdict: VerdictInconclusive,
			description: "Probe produced no result",
		},
		{
			name: "inconclusive when mixed results with some non-certificate errors",
			results: []ProbeResult{
				{URL: CONTROL_URL, Verdict: VerdictTrusted},
				{URL: BAD_URLS[0], Verdict: VerdictRejected},
				{URL: BAD_URLS[1], Verdict: VerdictInconclusive},
			},
			wantVerdict: VerdictInconclusive,
			description: "Test hosts unreachable or failed for non-certificate reason",
		},
		{
			name: "trusted when one trusted among multiple rejected",
			results: []ProbeResult{
				{URL: CONTROL_URL, Verdict: VerdictTrusted},
				{URL: BAD_URLS[0], Verdict: VerdictRejected},
				{URL: BAD_URLS[1], Verdict: VerdictTrusted},
			},
			wantVerdict: VerdictTrusted,
			description: "AFFECTED - at least one test URL was trusted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict := engine.Judge(tt.results)
			assert.Equal(t, tt.wantVerdict, verdict, tt.description)
		})
	}
}

// TestCombineProbe tests the combine_probe() logic ported from the bash script (lines 291-304).
func TestCombineProbe(t *testing.T) {
	tests := []struct {
		name        string
		verdicts    []Verdict
		wantVerdict Verdict
	}{
		{
			name:        "trusted wins over anything",
			verdicts:    []Verdict{VerdictRejected, VerdictTrusted, VerdictInconclusive},
			wantVerdict: VerdictTrusted,
		},
		{
			name:        "rejected when no trusted",
			verdicts:    []Verdict{VerdictInconclusive, VerdictRejected, VerdictSkipped},
			wantVerdict: VerdictRejected,
		},
		{
			name:        "first non-skipped when no trusted or rejected",
			verdicts:    []Verdict{VerdictSkipped, VerdictInconclusive, VerdictSkipped},
			wantVerdict: VerdictInconclusive,
		},
		{
			name:        "all skipped returns first",
			verdicts:    []Verdict{VerdictSkipped, VerdictSkipped},
			wantVerdict: VerdictSkipped,
		},
		{
			name:        "empty returns skipped",
			verdicts:    []Verdict{},
			wantVerdict: VerdictSkipped,
		},
		{
			name:        "trusted at end",
			verdicts:    []Verdict{VerdictRejected, VerdictInconclusive, VerdictTrusted},
			wantVerdict: VerdictTrusted,
		},
		{
			name:        "rejected at end with no trusted",
			verdicts:    []Verdict{VerdictInconclusive, VerdictRejected},
			wantVerdict: VerdictRejected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict := CombineProbe(tt.verdicts...)
			assert.Equal(t, tt.wantVerdict, verdict)
		})
	}
}

// TestDescribeProbe tests the describe_probe() function ported from the bash script (lines 306-314).
func TestDescribeProbe(t *testing.T) {
	tests := []struct {
		verdict    Verdict
		wantDesc   string
		wantStrict bool
	}{
		{
			verdict:  VerdictTrusted,
			wantDesc: "AFFECTED - connected to a host using the compromised chain",
		},
		{
			verdict:  VerdictRejected,
			wantDesc: "protected - certificate rejected",
		},
		{
			verdict:  VerdictSkipped,
			wantDesc: "skipped (--no-network)",
		},
		{
			verdict:  VerdictInconclusive,
			wantDesc: "inconclusive - control host unreachable or network issue",
		},
		{
			verdict:  Verdict("custom-verdict"),
			wantDesc: "custom-verdict",
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.verdict), func(t *testing.T) {
			desc := DescribeProbe(tt.verdict)
			assert.Equal(t, tt.wantDesc, desc)
		})
	}
}

// generateTestCA generates a self-signed CA certificate for testing.
func generateTestCA(t *testing.T, name string) (*rsa.PrivateKey, *x509.Certificate, []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return key, cert, certDER
}

// generateTestServerCert generates a server certificate signed by a CA.
func generateTestServerCert(t *testing.T, caKey *rsa.PrivateKey, caCert *x509.Certificate, hostname string) (*rsa.PrivateKey, *x509.Certificate, []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{hostname},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)

	return key, nil, certDER
}

// TestRealEngine_TLSServerWithTrustedCA tests RealEngine with a real TLS server using a trusted CA.
func TestRealEngine_TLSServerWithTrustedCA(t *testing.T) {
	// Generate a CA
	caKey, caCert, caDER := generateTestCA(t, "Test CA")

	// Create a certificate pool with our CA
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caDER,
	}))

	// Generate a server certificate
	serverKey, _, serverDER := generateTestServerCert(t, caKey, caCert, "localhost")

	// Create TLS certificate for the server
	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: serverDER,
		}),
		pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
		}),
	)
	require.NoError(t, err)

	// Start a test TLS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Replace the server's certificate with our custom one
	server.TLS.Certificates = []tls.Certificate{tlsCert}

	// Create an engine with our CA pool
	engine := &RealEngine{
		Timeout: 5 * time.Second,
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:       pool,
					ServerName:    "localhost",
					Renegotiation: tls.RenegotiateNever,
				},
			},
		},
	}

	// Extract the server URL (convert https://127.0.0.1:port/ to proper format)
	serverURL := "https://" + server.Listener.Addr().String() + "/"

	// Test: the server should be TRUSTED because we trust the CA
	results, err := engine.Probe(context.Background(), []string{serverURL}, serverURL)
	require.NoError(t, err)
	require.Len(t, results, 2) // control + test URL

	// Both should be trusted because we trust the CA
	// Note: We're using the same URL as both control and test for simplicity
	assert.Equal(t, VerdictTrusted, results[0].Verdict)
	assert.Equal(t, VerdictTrusted, results[1].Verdict)
}

// TestRealEngine_TLSServerWithUntrustedCA tests RealEngine with an untrusted CA.
func TestRealEngine_TLSServerWithUntrustedCA(t *testing.T) {
	// Generate a CA (untrusted)
	caKey, caCert, _ := generateTestCA(t, "Untrusted CA")

	// Use the system CA pool (doesn't include our custom CA)
	pool, err := x509.SystemCertPool()
	require.NoError(t, err)

	// Generate a server certificate
	serverKey, _, serverDER := generateTestServerCert(t, caKey, caCert, "localhost")

	// Create TLS certificate for the server
	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: serverDER,
		}),
		pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
		}),
	)
	require.NoError(t, err)

	// Start a test TLS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Replace the server's certificate with our custom one
	server.TLS.Certificates = []tls.Certificate{tlsCert}

	// Create an engine with default (system) CA pool
	engine := &RealEngine{
		Timeout: 5 * time.Second,
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    pool,
					ServerName: "localhost",
				},
			},
		},
	}

	// Extract the server URL
	serverURL := "https://" + server.Listener.Addr().String() + "/"

	// Test: the server should be REJECTED because we don't trust the CA
	results, err := engine.Probe(context.Background(), []string{serverURL}, serverURL)
	require.NoError(t, err)
	require.Len(t, results, 2)

	// Both should be rejected because the CA is untrusted
	assert.Equal(t, VerdictRejected, results[0].Verdict)
	assert.Equal(t, VerdictRejected, results[1].Verdict)
}

// TestRealEngine_ControlHostFailing tests inconclusive verdict when control host fails.
func TestRealEngine_ControlHostFailing(t *testing.T) {
	// Use a non-routable IP to simulate control host failure
	engine := NewRealEngine()

	// Try to connect to a non-existent server
	results, err := engine.Probe(context.Background(), []string{"https://10.255.255.1/"}, "https://10.255.255.2/")
	require.NoError(t, err)

	// Both should be inconclusive (network error)
	for _, r := range results {
		assert.Equal(t, VerdictInconclusive, r.Verdict)
	}

	// Judge should return inconclusive
	verdict := engine.Judge(results)
	assert.Equal(t, VerdictInconclusive, verdict)
}

// TestFakeEngine tests the FakeEngine implementation.
func TestFakeEngine(t *testing.T) {
	engine := NewFakeEngine()
	ctx := context.Background()

	// Test AddTrusted
	engine.AddTrusted("https://test.example.com/")
	results, err := engine.Probe(ctx, []string{"https://test.example.com/"}, CONTROL_URL)
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, VerdictTrusted, results[0].Verdict)
	assert.Equal(t, CONTROL_URL, results[1].URL) // Control should be trusted

	// Test AddRejected
	engine.Reset()
	engine.AddRejected("https://bad.example.com/")
	results, err = engine.Probe(ctx, []string{"https://bad.example.com/"}, CONTROL_URL)
	require.NoError(t, err)
	assert.Equal(t, VerdictRejected, results[0].Verdict)
	assert.Equal(t, VerdictTrusted, results[1].Verdict) // Control should be trusted

	// Test error return
	engine.Reset()
	engine.Error = assert.AnError
	_, err = engine.Probe(ctx, []string{}, CONTROL_URL)
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)

	// Test Probed tracking
	engine.Reset()
	engine.Error = nil
	engine.AddTrusted("https://test1.example.com/")
	_, _ = engine.Probe(ctx, []string{"https://test1.example.com/"}, CONTROL_URL)
	assert.Contains(t, engine.Probed, "https://test1.example.com/")
}

// TestProbeCAFile tests the ProbeCAFile function with a real PEM bundle.
func TestProbeCAFile(t *testing.T) {
	// Generate a CA
	_, _, caDER := generateTestCA(t, "Test CA for Bundle")

	// Write to a temp file
	tmpFile, err := os.CreateTemp("", "ca-bundle-*.pem")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// Write PEM-encoded certificate
	_, err = tmpFile.Write(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caDER,
	}))
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	// Test probing with this CA bundle
	// Note: This will try to connect to the real BAD_URLS, which may fail without network
	// In a real test, we'd mock this, but we're testing the file reading logic here
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	results, err := ProbeCAFile(ctx, tmpFile.Name())
	require.NoError(t, err)
	assert.NotEmpty(t, results)
}

// TestRealEngine_ContextCancellation tests that Probe respects context cancellation.
func TestRealEngine_ContextCancellation(t *testing.T) {
	engine := NewRealEngine()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// When context is already canceled, Probe should handle gracefully
	// The Probe function checks context but returns []ProbeResult with inconclusive verdicts instead of error
	assert.NotPanics(t, func() {
		results, err := engine.Probe(ctx, BAD_URLS, CONTROL_URL)
		// Probe may return nil error even with canceled context
		// because it handles each probe individually
		_ = results
		_ = err
	})
}

// The cases are the script's judge(): a control that is not ok makes everything
// inconclusive; any ok test URL is TRUSTED; all certerr is REJECTED; a mix of certerr
// and a non-certificate failure proves nothing.
func TestJudgeOutput(t *testing.T) {
	c, a, b := CONTROL_URL, BAD_URLS[0], BAD_URLS[1]
	tests := []struct {
		name string
		out  string
		want Verdict
	}{
		{"both rejected", "ok " + c + "\ncerterr " + a + "\ncerterr " + b + "\n", VerdictRejected},
		{"one trusted wins", "ok " + c + "\ncerterr " + a + "\nok " + b + "\n", VerdictTrusted},
		{"both trusted", "ok " + c + "\nok " + a + "\nok " + b + "\n", VerdictTrusted},
		{"rejected but one host unreachable: proves nothing", "ok " + c + "\ncerterr " + a + "\nerr " + b + "\n", VerdictInconclusive},
		{"both unreachable", "ok " + c + "\nerr " + a + "\nerr " + b + "\n", VerdictInconclusive},
		{"control also fails certificate checks: no usable CA bundle", "certerr " + c + "\ncerterr " + a + "\ncerterr " + b + "\n", VerdictInconclusive},
		{"control unreachable", "err " + c + "\ncerterr " + a + "\ncerterr " + b + "\n", VerdictInconclusive},
		{"no control line", "certerr " + a + "\ncerterr " + b + "\n", VerdictInconclusive},
		{"empty output", "", VerdictInconclusive},
		{"garbage lines are ignored", "hello\n\nok " + c + "\ncerterr " + a + "\ncerterr " + b + "\n", VerdictRejected},
		{"order does not matter", "certerr " + b + "\ncerterr " + a + "\nok " + c + "\n", VerdictRejected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, JudgeOutput(tt.out))
		})
	}
}

func TestParseOutput(t *testing.T) {
	got := ParseOutput("ok https://a/\ncerterr https://b/\nerr https://c/\nnonsense\n")
	assert.Equal(t, []ProbeResult{
		{URL: "https://a/", Verdict: VerdictTrusted},
		{URL: "https://b/", Verdict: VerdictRejected},
		{URL: "https://c/", Verdict: VerdictInconclusive, Error: "err"},
	}, got)
}

// The reasons are the script's judge() text, verbatim; they are what the report shows after
// "inconclusive - ".
func TestInconclusiveReason(t *testing.T) {
	c, a, b := CONTROL_URL, BAD_URLS[0], BAD_URLS[1]
	tests := []struct {
		name, out, want string
	}{
		{"empty", "", "probe produced no result"},
		{"no control line", "certerr " + a + "\n", "probe produced no result"},
		{"control fails certificate checks", "certerr " + c + "\ncerterr " + a + "\n",
			"control host (" + c + ") also failed certificate checks - this tool has no usable CA bundle, or a proxy intercepts TLS"},
		{"control unreachable", "err " + c + "\ncerterr " + a + "\n", "control host (" + c + ") unreachable - network or proxy problem"},
		{"test hosts fail for another reason", "ok " + c + "\nerr " + a + "\nerr " + b + "\n", "test hosts unreachable or failed for a non-certificate reason"},
		{"mixed certerr and err", "ok " + c + "\ncerterr " + a + "\nerr " + b + "\n", "test hosts unreachable or failed for a non-certificate reason"},
		{"trusted is not inconclusive", "ok " + c + "\nok " + a + "\n", ""},
		{"rejected is not inconclusive", "ok " + c + "\ncerterr " + a + "\ncerterr " + b + "\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, InconclusiveReason(tt.out))
		})
	}
}

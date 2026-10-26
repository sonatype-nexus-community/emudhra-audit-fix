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

// Package probe provides the TLS probe engine.
// Uses BAD_URLS and CONTROL_URL to test if a tool trusts the compromised chain.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// The test hosts that chain to the compromised intermediates.
var BAD_URLS = []string{
	"https://dv-g3b-emudhra.we-have-a-problem.com/",
	"https://dv-g3b-aaa-emudhra.we-have-a-problem.com/",
}

// The control host must NOT chain to either root the advisory says to distrust.
// (github.com chains to AAA Certificate Services via DigiCert.)
var CONTROL_URL = "https://github.com/"

// Verdict represents the outcome of a TLS probe.
type Verdict string

const (
	VerdictTrusted      Verdict = "trusted"      // AFFECTED - connected to compromised chain
	VerdictRejected     Verdict = "rejected"     // Protected - certificate rejected
	VerdictInconclusive Verdict = "inconclusive" // Control failed or network error
	VerdictSkipped      Verdict = "skipped"      // Skipped (--no-network)
)

// ProbeResult represents the result of probing a URL.
type ProbeResult struct {
	URL     string
	Verdict Verdict
	Error   string // Error message if not ok
}

// Engine is the interface for executing TLS probes.
type Engine interface {
	// Probe probes a list of URLs and returns results.
	Probe(ctx context.Context, urls []string, controlURL string) ([]ProbeResult, error)

	// Judge combines probe results into an overall verdict.
	Judge(results []ProbeResult) Verdict
}

// RealEngine is the real implementation that executes TLS probes using net/http.
type RealEngine struct {
	// Timeout is the per-request timeout (default 10 seconds).
	Timeout time.Duration

	// Client is the HTTP client to use (if nil, a default is created).
	Client *http.Client
}

// NewRealEngine creates a new RealEngine with default settings.
func NewRealEngine() *RealEngine {
	return &RealEngine{
		Timeout: 10 * time.Second,
	}
}

// Probe probes URLs and returns results.
// This ports curl_probe_all from the bash script (lines 543-555).
func (e *RealEngine) Probe(ctx context.Context, urls []string, controlURL string) ([]ProbeResult, error) {
	// Create HTTP client with TLS verification enabled
	client := e.Client
	if client == nil {
		client = &http.Client{
			Timeout: e.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
				},
			},
		}
	}

	// Probe all URLs (including control URL)
	allURLs := append([]string{controlURL}, urls...)
	results := make([]ProbeResult, len(allURLs))

	for i, url := range allURLs {
		results[i] = e.probeURL(ctx, client, url)
	}

	return results, nil
}

// probeURL probes a single URL and returns the result.
func (e *RealEngine) probeURL(ctx context.Context, client *http.Client, url string) ProbeResult {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ProbeResult{
			URL:     url,
			Verdict: VerdictInconclusive,
			Error:   fmt.Sprintf("failed to create request: %v", err),
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		// Check if it's a certificate error
		if isCertError(err) {
			return ProbeResult{
				URL:     url,
				Verdict: VerdictRejected,
				Error:   err.Error(),
			}
		}
		// Other error (network, timeout, etc.)
		return ProbeResult{
			URL:     url,
			Verdict: VerdictInconclusive,
			Error:   err.Error(),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	// Success - trust store accepted the certificate
	return ProbeResult{
		URL:     url,
		Verdict: VerdictTrusted,
	}
}

// isCertError checks if an error is a TLS certificate verification error.
func isCertError(err error) bool {
	if err == nil {
		return false
	}

	// Check for x509 errors
	errStr := err.Error()
	return strings.Contains(errStr, "x509:") ||
		strings.Contains(errStr, "certificate") ||
		strings.Contains(errStr, "CERTIFICATE_VERIFY_FAILED") ||
		strings.Contains(errStr, "unknown authority")
}

// Judge combines probe results into an overall verdict.
// Ports the judge() function from the bash script (lines 269-287).
func (e *RealEngine) Judge(results []ProbeResult) Verdict {
	var trusted, rejected, other int
	var ctl Verdict

	for _, r := range results {
		if r.URL == CONTROL_URL {
			ctl = r.Verdict
			continue
		}

		switch r.Verdict {
		case VerdictTrusted:
			trusted++
		case VerdictRejected:
			rejected++
		default:
			other++
		}
	}

	// Control URL must succeed
	if ctl == "" {
		return VerdictInconclusive
	}
	if ctl == VerdictRejected {
		return VerdictInconclusive // Control host also failed - no usable CA bundle
	}
	if ctl != VerdictTrusted {
		return VerdictInconclusive // Network or proxy problem
	}

	// If any test URL was trusted, the tool trusts the compromised chain
	if trusted > 0 {
		return VerdictTrusted
	}

	// If all test URLs were rejected, the tool is protected
	if rejected > 0 && other == 0 {
		return VerdictRejected
	}

	// Mixed or inconclusive results
	return VerdictInconclusive
}

// CombineProbe combines multiple probe verdicts into one overall verdict.
// Any trusted wins; otherwise any rejected; otherwise the first non-skipped verdict.
// Ports combine_probe() from the bash script (lines 289-304).
func CombineProbe(verdicts ...Verdict) Verdict {
	var first Verdict
	var hasRejected bool

	for _, v := range verdicts {
		if v == "" || v == VerdictSkipped {
			continue
		}

		if v == VerdictTrusted {
			return VerdictTrusted
		}

		if v == VerdictRejected {
			hasRejected = true
		}

		if first == "" {
			first = v
		}
	}

	if hasRejected {
		return VerdictRejected
	}

	if first != "" {
		return first
	}

	// All were skipped or empty
	if len(verdicts) > 0 {
		return verdicts[0]
	}
	return VerdictSkipped
}

// DescribeProbe returns a human-readable description of a verdict.
// Ports describe_probe() from the bash script (lines 306-314).
func DescribeProbe(v Verdict) string {
	switch v {
	case VerdictTrusted:
		return "AFFECTED - connected to a host using the compromised chain"
	case VerdictRejected:
		return "protected - certificate rejected"
	case VerdictSkipped:
		return "skipped (--no-network)"
	case VerdictInconclusive:
		return "inconclusive - control host unreachable or network issue"
	default:
		return string(v)
	}
}

// FakeEngine is a test implementation of Engine.
type FakeEngine struct {
	// Results is the queue of probe results to return.
	Results [][]ProbeResult

	// Error is the error to return (if any).
	Error error

	// Probed tracks all URLs probed.
	Probed []string
}

// NewFakeEngine creates a new FakeEngine.
func NewFakeEngine() *FakeEngine {
	return &FakeEngine{
		Results: make([][]ProbeResult, 0),
		Probed:  make([]string, 0),
	}
}

// Probe returns scripted results.
func (f *FakeEngine) Probe(ctx context.Context, urls []string, controlURL string) ([]ProbeResult, error) {
	f.Probed = append(f.Probed, urls...)

	if f.Error != nil {
		return nil, f.Error
	}

	if len(f.Results) == 0 {
		// Return default inconclusive results
		results := make([]ProbeResult, len(urls)+1)
		for i, url := range urls {
			results[i] = ProbeResult{URL: url, Verdict: VerdictInconclusive}
		}
		results[len(urls)] = ProbeResult{URL: controlURL, Verdict: VerdictInconclusive}
		return results, nil
	}

	result := f.Results[0]
	f.Results = f.Results[1:]
	return result, nil
}

// Judge delegates to RealEngine.Judge.
func (f *FakeEngine) Judge(results []ProbeResult) Verdict {
	real := NewRealEngine()
	return real.Judge(results)
}

// AddResult adds a scripted result.
func (f *FakeEngine) AddResult(results []ProbeResult) {
	f.Results = append(f.Results, results)
}

// AddTrusted adds a scripted trusted verdict for a URL.
func (f *FakeEngine) AddTrusted(url string) {
	f.AddResult([]ProbeResult{
		{URL: url, Verdict: VerdictTrusted},
		{URL: CONTROL_URL, Verdict: VerdictTrusted},
	})
}

// AddRejected adds a scripted rejected verdict for a URL.
func (f *FakeEngine) AddRejected(url string) {
	f.AddResult([]ProbeResult{
		{URL: url, Verdict: VerdictRejected},
		{URL: CONTROL_URL, Verdict: VerdictTrusted},
	})
}

// Reset clears the scripted results and probed history.
func (f *FakeEngine) Reset() {
	f.Results = make([][]ProbeResult, 0)
	f.Probed = make([]string, 0)
	f.Error = nil
}

// ProbeCAFile tests a PEM bundle against the test URLs.
// This ports probe_cafile from the bash script (lines 1329-1338).
func ProbeCAFile(ctx context.Context, caFile string) ([]ProbeResult, error) {
	// Read the CA bundle
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read CA file: %w", err)
	}

	// Create a certificate pool
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("no certificates found in %s", caFile)
	}

	// Create HTTP client with custom CA pool
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}

	engine := &RealEngine{
		Timeout: 10 * time.Second,
		Client:  client,
	}

	return engine.Probe(ctx, BAD_URLS, CONTROL_URL)
}

// ParseOutput reads the output of an external probe program: one line per URL,
// "<result> <url>", where result is ok (the TLS connection succeeded, so the tool
// TRUSTS the chain), certerr (a certificate verification failure, so it REJECTS the
// chain) or anything else (a network or non-certificate failure, which proves
// nothing). It is the input format of the script's judge(); Judge turns the results
// into a verdict. Lines that are not "<result> <url>" are ignored.
func ParseOutput(output string) []ProbeResult {
	var results []ProbeResult
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		r := ProbeResult{URL: f[1]}
		switch f[0] {
		case "ok":
			r.Verdict = VerdictTrusted
		case "certerr":
			r.Verdict = VerdictRejected
		default:
			r.Verdict = VerdictInconclusive
			r.Error = f[0]
		}
		results = append(results, r)
	}
	return results
}

// JudgeOutput is the script's judge() over an external probe's output.
func JudgeOutput(output string) Verdict {
	return NewRealEngine().Judge(ParseOutput(output))
}

// InconclusiveReason is the one-line explanation the script's judge() prints after
// "inconclusive:" for a probe's output. It returns "" for output that is not
// inconclusive.
func InconclusiveReason(output string) string {
	results := ParseOutput(output)
	var ctl Verdict
	hasCtl := false
	var trusted, rejected, other int
	for _, r := range results {
		if r.URL == CONTROL_URL {
			ctl, hasCtl = r.Verdict, true
			continue
		}
		switch r.Verdict {
		case VerdictTrusted:
			trusted++
		case VerdictRejected:
			rejected++
		default:
			other++
		}
	}
	switch {
	case !hasCtl:
		return "probe produced no result"
	case ctl == VerdictRejected:
		return "control host (" + CONTROL_URL + ") also failed certificate checks - this tool has no usable CA bundle, or a proxy intercepts TLS"
	case ctl != VerdictTrusted:
		return "control host (" + CONTROL_URL + ") unreachable - network or proxy problem"
	case trusted > 0, rejected > 0 && other == 0:
		return ""
	}
	return "test hosts unreachable or failed for a non-certificate reason"
}

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

package curl

import (
	"context"
	"testing"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

func TestGetVersion(t *testing.T) {
	tests := []struct {
		name           string
		curlOutput     string
		wantVersion    string
		wantTLSBackend string
	}{
		{
			name: "macOS SecureTransport",
			curlOutput: `curl 8.7.1 (x86_64-apple-darwin23.0) libcurl/8.7.1 (SecureTransport) zlib/1.2.12 nghttp2/1.59.0
Release-Date: 2024-03-27
Protocols: file ftp ftps http https
Features: alt-svc AsynchDNS HSTS HTTP2 HTTPS-proxy IPv6 Largefile libz NTLM NTLM_WB SPNEGO SSL threadsafe UnixSockets`,
			wantVersion:    "8.7.1",
			wantTLSBackend: "SecureTransport",
		},
		{
			name: "OpenSSL with parentheses",
			curlOutput: `curl 8.4.0 (x86_64-pc-linux-gnu) libcurl/8.4.0 (OpenSSL/3.0.2) zlib/1.2.13 brotli/1.0.9 zstd/1.5.5 libidn2/2.3.4 libpsl/0.21.2 (+libidn2/2.3.4) libssh2/1.11.0 nghttp2/1.57.0
Release-Date: 2023-10-11
Protocols: file ftp ftps http https imap imaps pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp
Features: alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM NTLM_WB PSL SPNEGO SSL threadsafe TLS-SRP UnixSockets zstd`,
			wantVersion:    "8.4.0",
			wantTLSBackend: "OpenSSL/3.0.2",
		},
		{
			name: "OpenSSL without parentheses",
			curlOutput: `curl 7.81.0 (x86_64-pc-linux-gnu) libcurl/7.81.0 OpenSSL/3.0.2 zlib/1.2.11 brotli/1.0.9 zstd/1.4.8 libidn2/2.3.2 libpsl/0.21.0 (+libidn2/2.3.2) libssh2/1.10.0 nghttp2/1.43.0 librtmp/2.3 OpenLDAP/2.5.16
Release-Date: 2022-01-05
Protocols: file ftp ftps http https imap imaps ldap ldaps pop3 pop3s rtmp rtsp scp sftp smb smbs smtp smtps telnet tftp
Features: alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM NTLM_WB PSL SPNEGO SSL threadsafe TLS-SRP UnixSockets zstd`,
			wantVersion:    "7.81.0",
			wantTLSBackend: "OpenSSL/3.0.2",
		},
		{
			name: "OpenSSL alternate format with extra parentheses",
			curlOutput: `curl 7.88.1 (x86_64-apple-darwin22.0) libcurl/7.88.1 (OpenSSL/3.0.13) zlib/1.2.11 nghttp2/1.51.0
Release-Date: 2023-02-20
Protocols: file ftp ftps http https imap imaps pop3 pop3s rtsp smb smbs smtp smtps telnet tftp
Features: alt-svc AsynchDNS HSTS HTTP2 HTTPS-proxy IPv6 Largefile libz NTLM NTLM_WB SPNEGO SSL threadsafe UnixSockets`,
			wantVersion:    "7.88.1",
			wantTLSBackend: "OpenSSL/3.0.13",
		},
		{
			name: "LibreSSL",
			curlOutput: `curl 8.1.2 (x86_64-pc-linux-gnu) libcurl/8.1.2 (LibreSSL/3.8.2) zlib/1.3.1 nghttp2/1.55.1
Release-Date: 2023-06-05
Protocols: file ftp ftps http https
Features: alt-svc HSTS HTTP2 HTTPS-proxy IPv6 Largefile libz SSL threadsafe UnixSockets`,
			wantVersion:    "8.1.2",
			wantTLSBackend: "LibreSSL/3.8.2",
		},
		{
			name: "GnuTLS",
			curlOutput: `curl 7.88.1 (x86_64-pc-linux-gnu) libcurl/7.88.1 (GnuTLS/3.8.0) zlib/1.2.13
Release-Date: 2023-02-20
Protocols: file ftp ftps http https
Features: alt-svc AsynchDNS HSTS HTTP2 HTTPS-proxy IPv6 Largefile libz NTLM SSL threadsafe UnixSockets`,
			wantVersion:    "7.88.1",
			wantTLSBackend: "GnuTLS/3.8.0",
		},
		{
			name: "mbedTLS",
			curlOutput: `curl 7.88.1 (x86_64-pc-linux-gnu) libcurl/7.88.1 (mbedTLS/3.5.0) zlib/1.2.13
Protocols: file ftp ftps http https
Features: alt-svc AsynchDNS HSTS HTTP2 HTTPS-proxy IPv6 Largefile libz NTLM SSL threadsafe UnixSockets`,
			wantVersion:    "7.88.1",
			wantTLSBackend: "mbedTLS/3.5.0",
		},
		{
			name: "wolfSSL",
			curlOutput: `curl 8.0.1 (x86_64-pc-linux-gnu) libcurl/8.0.1 (wolfSSL/5.6.0)
Release-Date: 2023-03-20
Protocols: file ftp http https
Features: alt-svc HSTS HTTP2 HTTPS-proxy IPv6 Largefile SSL threadsafe UnixSockets`,
			wantVersion:    "8.0.1",
			wantTLSBackend: "wolfSSL/5.6.0",
		},
		{
			name: "Schannel (Windows)",
			curlOutput: `curl 8.4.0 (Windows) libcurl/8.4.0 (Schannel) zlib/1.3 brotli/1.0.9 zstd/1.5.5 WinIDN
Release-Date: 2023-10-11
Protocols: file ftp ftps http https imap imaps pop3 pop3s smtp smtps telnet tftp
Features: alt-svc AsynchDNS brotli HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM SPNEGO SSL threadsafe UnixSockets zstd`,
			wantVersion:    "8.4.0",
			wantTLSBackend: "Schannel",
		},
		{
			name: "should not capture libidn2 as TLS backend",
			curlOutput: `curl 8.4.0 (x86_64-pc-linux-gnu) libcurl/8.4.0 (OpenSSL/3.0.2) zlib/1.2.13 brotli/1.0.9 zstd/1.5.5 libidn2/2.3.4 libpsl/0.21.2 (+libidn2/2.3.4) libssh2/1.11.0 nghttp2/1.57.0
Release-Date: 2023-10-11`,
			wantVersion:    "8.4.0",
			wantTLSBackend: "OpenSSL/3.0.2",
		},
		{
			name: "LibreSSL without parentheses",
			curlOutput: `curl 7.87.0 (x86_64-apple-darwin22.1.0) libcurl/7.87.0 LibreSSL/3.3.6 zlib/1.2.11 nghttp2/1.47.0
Release-Date: 2022-12-21
Protocols: file ftp ftps http https imap imaps pop3 pop3s rtsp smb smbs smtp smtps telnet tftp
Features: alt-svc AsynchDNS HSTS HTTP2 HTTPS-proxy IPv6 Largefile libz NTLM NTLM_WB SPNEGO SSL threadsafe UnixSockets`,
			wantVersion:    "7.87.0",
			wantTLSBackend: "LibreSSL/3.3.6",
		},
		{
			name:           "empty output",
			curlOutput:     "",
			wantVersion:    "?",
			wantTLSBackend: "?",
		},
		{
			name:           "malformed output",
			curlOutput:     "not curl output",
			wantVersion:    "?",
			wantTLSBackend: "?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fake runner with curl output
			runner := exec.NewFakeRunner()
			runner.AddResponse("/usr/bin/curl", exec.CommandResult{
				Stdout: tt.curlOutput,
			})

			env := &kinds.Env{
				Run:     runner,
				Environ: make(map[string]string),
			}

			k := &Kind{}
			version, tlsBackend := k.getVersion(context.Background(), env, "/usr/bin/curl")

			if version != tt.wantVersion {
				t.Errorf("getVersion() version = %v, want %v", version, tt.wantVersion)
			}
			if tlsBackend != tt.wantTLSBackend {
				t.Errorf("getVersion() tlsBackend = %v, want %v", tlsBackend, tt.wantTLSBackend)
			}
		})
	}
}

func TestCandidates(t *testing.T) {
	env := testutil.NewTestEnvT(t)
	k := &Kind{}

	candidates := k.candidates(env)

	// Should return only executables that exist
	for _, c := range candidates {
		if !discover.IsExecutable(c) {
			t.Errorf("candidates() returned non-executable: %s", c)
		}
	}
}

func TestEnvNotes(t *testing.T) {
	tests := []struct {
		name      string
		environ   map[string]string
		wantNotes []string
		wantEmpty bool
	}{
		{
			name:      "no environment variables",
			environ:   map[string]string{},
			wantEmpty: true,
		},
		{
			name: "CURL_CA_BUNDLE set",
			environ: map[string]string{
				"CURL_CA_BUNDLE": "/etc/ssl/certs/ca-bundle.crt",
			},
			wantNotes: []string{"CURL_CA_BUNDLE=/etc/ssl/certs/ca-bundle.crt"},
		},
		{
			name: "SSL_CERT_FILE set",
			environ: map[string]string{
				"SSL_CERT_FILE": "/etc/ssl/cert.pem",
			},
			wantNotes: []string{"SSL_CERT_FILE=/etc/ssl/cert.pem"},
		},
		{
			name: "SSL_CERT_DIR set",
			environ: map[string]string{
				"SSL_CERT_DIR": "/etc/ssl/certs",
			},
			wantNotes: []string{"SSL_CERT_DIR=/etc/ssl/certs"},
		},
		{
			name: "REQUESTS_CA_BUNDLE set",
			environ: map[string]string{
				"REQUESTS_CA_BUNDLE": "/etc/ssl/certs/ca-bundle.crt",
			},
			wantNotes: []string{"REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-bundle.crt"},
		},
		{
			name: "GIT_SSL_NO_VERIFY warning",
			environ: map[string]string{
				"GIT_SSL_NO_VERIFY": "1",
			},
			wantNotes: []string{"WARNING: GIT_SSL_NO_VERIFY is set: git skips certificate checks"},
		},
		{
			name: "NODE_TLS_REJECT_UNAUTHORIZED warning",
			environ: map[string]string{
				"NODE_TLS_REJECT_UNAUTHORIZED": "0",
			},
			wantNotes: []string{"WARNING: NODE_TLS_REJECT_UNAUTHORIZED=0: Node skips certificate checks"},
		},
		{
			name: "PYTHONHTTPSVERIFY warning",
			environ: map[string]string{
				"PYTHONHTTPSVERIFY": "0",
			},
			wantNotes: []string{"WARNING: PYTHONHTTPSVERIFY=0 is set (ignored by isolated probes, but affects your own Python scripts)"},
		},
		{
			name: "multiple variables",
			environ: map[string]string{
				"CURL_CA_BUNDLE": "/etc/ssl/certs/ca-bundle.crt",
				"SSL_CERT_FILE":  "/etc/ssl/cert.pem",
			},
			wantNotes: []string{
				"CURL_CA_BUNDLE=/etc/ssl/certs/ca-bundle.crt",
				"SSL_CERT_FILE=/etc/ssl/cert.pem",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := &kinds.Env{Environ: tt.environ}
			k := &Kind{}
			notes := k.envNotes(env)

			if tt.wantEmpty {
				if notes != "" {
					t.Errorf("envNotes() = %v, want empty", notes)
				}
				return
			}

			for _, want := range tt.wantNotes {
				if !contains(notes, want) {
					t.Errorf("envNotes() = %v, want to contain %v", notes, want)
				}
			}
		})
	}
}

func TestAddGuidance(t *testing.T) {
	tests := []struct {
		name                string
		probeResult         kinds.ProbeResult
		curlPath            string
		hostOS              string
		source              discover.Source
		wantCompact         string
		wantNeedsSystemGuid bool
		wantHasFix          bool
	}{
		{
			name:                "not affected - no guidance",
			probeResult:         kinds.ProbeRejected,
			curlPath:            "/usr/bin/curl",
			hostOS:              "darwin",
			wantNeedsSystemGuid: false,
			wantHasFix:          false,
		},
		{
			name:                "affected - brew curl",
			probeResult:         kinds.ProbeTrusted,
			curlPath:            "/opt/homebrew/opt/curl/bin/curl",
			hostOS:              "darwin",
			source:              discover.SourceBrew,
			wantCompact:         "brew upgrade curl ca-certificates",
			wantNeedsSystemGuid: false,
			wantHasFix:          true,
		},
		{
			name:                "affected - macOS system curl",
			probeResult:         kinds.ProbeTrusted,
			curlPath:            "/usr/bin/curl",
			hostOS:              "darwin",
			source:              discover.SourceOther,
			wantCompact:         "patch the system CA bundle (or use Homebrew's curl)",
			wantNeedsSystemGuid: true,
			wantHasFix:          false,
		},
		{
			name:                "affected - Linux curl",
			probeResult:         kinds.ProbeTrusted,
			curlPath:            "/usr/bin/curl",
			hostOS:              "linux",
			source:              discover.SourceOther,
			wantCompact:         "patch the system CA bundle (or use Homebrew's curl)",
			wantNeedsSystemGuid: true,
			wantHasFix:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := kinds.NewFinding("curl", "curl")
			f.ProbeResult = tt.probeResult
			f.Path = tt.curlPath

			host := platform.Host{OS: tt.hostOS}
			k := &Kind{}

			// Mock discover.WhereFrom for brew test
			// The addGuidance function calls discover.WhereFrom internally
			k.addGuidance(&f, tt.curlPath, host)

			if f.NeedsSystemGuidance != tt.wantNeedsSystemGuid {
				t.Errorf("NeedsSystemGuidance = %v, want %v", f.NeedsSystemGuidance, tt.wantNeedsSystemGuid)
			}

			if f.HasFix != tt.wantHasFix {
				t.Errorf("HasFix = %v, want %v", f.HasFix, tt.wantHasFix)
			}

			if tt.wantCompact != "" && f.GuidanceCompact != tt.wantCompact {
				t.Errorf("GuidanceCompact = %v, want %v", f.GuidanceCompact, tt.wantCompact)
			}
		})
	}
}

func TestAudit(t *testing.T) {
	t.Run("finds curl installations and probes them", func(t *testing.T) {
		env := testutil.NewTestEnvT(t)

		// Create fake curl
		curlPath := "/usr/bin/curl"
		runner := exec.NewFakeRunner()
		runner.AddResponse(curlPath, exec.CommandResult{
			Stdout: "curl 8.7.1 (x86_64-apple-darwin23.0) libcurl/8.7.1 (SecureTransport) zlib/1.2.12 nghttp2/1.59.0\n",
		})
		env.Run = runner

		// Set up probe engine with control URL and both test URLs
		probeEngine := probe.NewFakeEngine()
		probeEngine.AddResult([]probe.ProbeResult{
			{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
			{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
			{URL: probe.BAD_URLS[1], Verdict: probe.VerdictRejected},
		})
		env.Probe = probeEngine

		// Set PATH to find curl
		env.Environ["PATH"] = "/usr/bin"

		k := &Kind{}
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit() error = %v", err)
		}

		if len(findings) == 0 {
			t.Error("Audit() returned no findings")
		}

		for _, f := range findings {
			if f.Kind != "curl" {
				t.Errorf("Finding.Kind = %v, want curl", f.Kind)
			}
			if f.ProbeResult == "" {
				t.Error("Finding.ProbeResult is empty")
			}
		}
	})

	t.Run("skips probe when offline", func(t *testing.T) {
		env := testutil.NewTestEnvT(t)
		env.Offline = true

		// Create fake curl
		curlPath := "/usr/bin/curl"
		runner := exec.NewFakeRunner()
		runner.AddResponse(curlPath, exec.CommandResult{
			Stdout: "curl 8.7.1 (x86_64-apple-darwin23.0) libcurl/8.7.1 (SecureTransport)\n",
		})
		env.Run = runner

		// Set PATH to find curl
		env.Environ["PATH"] = "/usr/bin"

		k := &Kind{}
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit() error = %v", err)
		}

		for _, f := range findings {
			if f.ProbeResult != kinds.ProbeSkipped {
				t.Errorf("Finding.ProbeResult = %v, want skipped", f.ProbeResult)
			}
		}
	})
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(s) > 0 && containsSubstring(s, sub)))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

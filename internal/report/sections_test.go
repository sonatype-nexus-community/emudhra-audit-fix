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

package report

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
)

func hdr() Header {
	return Header{Version: "1.2.3", Uname: "Darwin 27.0.0 arm64", Now: time.Date(2026, 10, 26, 13, 41, 26, 0, time.UTC),
		ProbeHosts: "https://a/ https://b/ (control: https://c/)"}
}

func TestHeaderMatchesTheScript(t *testing.T) {
	var out bytes.Buffer
	(&Reporter{Verbose: 1, Output: &out}).PrintHeader(hdr())
	assert.Equal(t, "eMudhra intermediate CA compromise - developer tool audit (v1.2.3, read-only)\n"+
		"Host: Darwin 27.0.0 arm64   Date: 2026-10-26 13:41:26 UTC\n"+
		"Reference: https://emudhra.we-have-a-problem.com/\n"+
		"Probe hosts: https://a/ https://b/ (control: https://c/)\n\n", out.String())

	out.Reset()
	h := hdr()
	h.NoNetwork = true
	(&Reporter{Verbose: 1, Output: &out}).PrintHeader(h)
	assert.Contains(t, out.String(), "Mode: version checks only (--no-network)\n\n")
	assert.NotContains(t, out.String(), "Probe hosts")

	out.Reset()
	(&Reporter{Output: &out}).PrintHeader(hdr())
	assert.Equal(t, "eMudhra CA compromise audit v1.2.3 - Darwin 27.0.0 arm64 - 2026-10-26\n\n", out.String())

	out.Reset()
	(&Reporter{Output: &out}).PrintHeader(h)
	assert.Equal(t, "eMudhra CA compromise audit v1.2.3 - Darwin 27.0.0 arm64 - 2026-10-26 - version checks only\n\n", out.String())
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestEnvironmentBlock(t *testing.T) {
	cases := []struct {
		name    string
		verbose int
		vars    map[string]string
		want    string
	}{
		{"compact says nothing when nothing is set", 0, nil, ""},
		{"compact ignores an unrelated variable", 0, map[string]string{"HOME": "/h"}, ""},
		{"verbose says none are set", 1, nil, "== CA-related environment ==\n  no CA-related variables set\n  The probes below inherit this environment, so each result is how the tool behaves in this shell.\n\n"},
		{"compact lists what could change the results", 0, map[string]string{"SSL_CERT_FILE": "/ca.pem", "NODE_EXTRA_CA_CERTS": "/n.pem"},
			"CA-related environment (affects the results below):\n  SSL_CERT_FILE=/ca.pem\n  NODE_EXTRA_CA_CERTS=/n.pem\n\n"},
		{"verbose lists them in the script's order", 1, map[string]string{"NODE_USE_SYSTEM_CA": "1", "CURL_CA_BUNDLE": "/c"},
			"== CA-related environment ==\n  CURL_CA_BUNDLE=/c\n  NODE_USE_SYSTEM_CA=1\n  The probes below inherit"},
		{"option variables only when they mention certificates", 0, map[string]string{"NODE_OPTIONS": "--use-openssl-ca --max-old-space-size=4096", "JAVA_TOOL_OPTIONS": "-Xmx1g"}, ""},
		{"a trust store option counts", 0, map[string]string{"JAVA_TOOL_OPTIONS": "-Djavax.net.ssl.trustStore=/ts"},
			"CA-related environment (affects the results below):\n  JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=/ts\n\n"},
		{"cert in an option counts", 0, map[string]string{"JDK_JAVA_OPTIONS": "-Dx.certpath=1"}, "  JDK_JAVA_OPTIONS=-Dx.certpath=1\n"},
		{"tls in an option counts", 0, map[string]string{"JDK_JAVA_OPTIONS": "-Dhttps.protocols=TLSv1.3 -Dtls.x=1"}, "  JDK_JAVA_OPTIONS=-Dhttps.protocols=TLSv1.3 -Dtls.x=1\n"},
		{"lower-case truststore counts", 0, map[string]string{"JAVA_TOOL_OPTIONS": "-Djavax.net.ssl.truststore=/t"}, "  JAVA_TOOL_OPTIONS=-Djavax.net.ssl.truststore=/t\n"},
		{"a node option naming a CA counts", 0, map[string]string{"NODE_OPTIONS": "--use-system-ca"},
			"  NODE_OPTIONS=--use-system-ca\n"},
		{"git verification off warns", 0, map[string]string{"GIT_SSL_NO_VERIFY": "1"},
			"  WARNING GIT_SSL_NO_VERIFY is set: git skips certificate checks, so git will report AFFECTED.\n"},
		{"node verification off warns", 0, map[string]string{"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
			"  WARNING NODE_TLS_REJECT_UNAUTHORIZED=0: Node skips certificate checks, so Node will report AFFECTED.\n"},
		{"node verification left on does not", 0, map[string]string{"NODE_TLS_REJECT_UNAUTHORIZED": "1"}, ""},
		{"python verification off warns", 0, map[string]string{"PYTHONHTTPSVERIFY": "0"},
			"  WARNING PYTHONHTTPSVERIFY=0 is set (ignored by the isolated probes, but affects your own Python scripts).\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			(&Reporter{Verbose: c.verbose, Output: &out}).PrintEnvironment(env(c.vars))
			if c.want == "" {
				assert.Empty(t, out.String())
			} else {
				assert.Contains(t, out.String(), c.want)
			}
		})
	}
}

func TestVerboseReportGroupsFindingsUnderTheirSections(t *testing.T) {
	a := kinds.NewFinding("curl", "curl")
	a.Version, a.Path = "8.7.1", "/usr/bin/curl"
	a.SetProbe(kinds.ProbeRejected, "")
	stray := kinds.NewFinding("zzz", "Stray")
	stray.Path = "/s"
	stray.SetProbe(kinds.ProbeRejected, "")
	var out bytes.Buffer
	r := &Reporter{Verbose: 1, Output: &out, Sections: []Section{
		{ID: "curl", Title: "curl", None: "not found"},
		{ID: "deno", Title: "Deno", None: "not found"},
		{ID: "sys", Title: "System CA bundle files", None: "none found", Note: "Note: Keychain."},
	}}

	_ = r.Report([]kinds.Finding{a, stray})

	got := out.String()
	assert.Contains(t, got, "== curl ==\n[OK] curl 8.7.1\n")
	assert.Contains(t, got, "== Deno ==\n  not found\n\n== System CA bundle files ==\n  none found\n\n  Note: Keychain.\n\n")
	assert.Less(t, bytes.Index([]byte(got), []byte("== curl ==")), bytes.Index([]byte(got), []byte("== Deno ==")))
	assert.Contains(t, got, "[OK] Stray", "a finding whose Kind has no section is still shown")
}

func TestCompactReportHasNoSectionHeaders(t *testing.T) {
	var out bytes.Buffer
	r := &Reporter{Output: &out, Sections: []Section{{ID: "deno", Title: "Deno", None: "not found"}}}
	_ = r.Report(nil)
	assert.NotContains(t, out.String(), "== Deno ==")
}

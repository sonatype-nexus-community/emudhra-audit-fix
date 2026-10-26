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
	"strings"
	"time"
)

// Section is one tool's part of the verbose report: the script's audit_start title, and what
// the report says when the tool was not found (audit_none).
type Section struct {
	// ID is the Kind whose findings belong in this section.
	ID string
	// Title is the section header text, e.g. "Java (JRE/JDK)".
	Title string
	// None is printed under the header, and the title listed under "Not installed / not
	// applicable" in the compact report, when the Kind found nothing.
	None string
	// Note is printed under the section in the verbose report, whether or not anything was found.
	Note string
}

// Header ports the script's opening lines. uname is `uname -srm` for -v and `uname -sm` for the
// compact line; probeHosts is the "Probe hosts" text shown when the network is used.
type Header struct {
	Version    string
	Uname      string
	Now        time.Time
	NoNetwork  bool
	ProbeHosts string // verbose only: "<bad urls> (control: <url>)"
}

// PrintHeader writes the header: a one-line banner by default, the four-line one with -v.
func (r *Reporter) PrintHeader(h Header) {
	if r.Verbose >= 1 {
		r.printf("%seMudhra intermediate CA compromise - developer tool audit%s (v%s, read-only)\n", r.c(cBld), r.c(cOff), h.Version)
		r.printf("Host: %s   Date: %s\n", h.Uname, h.Now.Format("2006-01-02 15:04:05 MST"))
		r.printf("Reference: https://emudhra.we-have-a-problem.com/\n")
		if h.NoNetwork {
			r.printf("Mode: version checks only (--no-network)\n")
		} else {
			r.printf("Probe hosts: %s\n", h.ProbeHosts)
		}
		r.printf("\n")
		return
	}
	suffix := ""
	if h.NoNetwork {
		suffix = " - version checks only"
	}
	r.printf("%seMudhra CA compromise audit%s v%s - %s - %s%s\n\n", r.c(cBld), r.c(cOff), h.Version, h.Uname, h.Now.Format("2006-01-02"), suffix)
}

// caEnvVars is the script's ENV_CA_VARS.
var caEnvVars = []string{"SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "PIP_CERT",
	"GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA"}

// PrintEnvironment ports audit_env: the CA-related variables that change what the probes see.
// With -v it is always a section; otherwise it is printed only when something is set that could
// change the results.
func (r *Reporter) PrintEnvironment(getenv func(string) string) {
	var out strings.Builder
	any, warn := false, false
	for _, v := range caEnvVars {
		if val := getenv(v); val != "" {
			out.WriteString("  " + v + "=" + val + "\n")
			any = true
		}
	}
	for _, v := range []string{"NODE_OPTIONS", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS"} {
		val := getenv(v)
		for _, sub := range []string{"system-ca", "extra-ca", "cert", "tls", "trustStore", "truststore"} {
			if strings.Contains(val, sub) {
				out.WriteString("  " + v + "=" + val + "\n")
				any = true
				break
			}
		}
	}
	warning := func(msg string) {
		out.WriteString("  " + r.c(cRed) + "WARNING" + r.c(cOff) + " " + msg + "\n")
		warn = true
	}
	if getenv("GIT_SSL_NO_VERIFY") != "" {
		warning("GIT_SSL_NO_VERIFY is set: git skips certificate checks, so git will report AFFECTED.")
	}
	if getenv("NODE_TLS_REJECT_UNAUTHORIZED") == "0" {
		warning("NODE_TLS_REJECT_UNAUTHORIZED=0: Node skips certificate checks, so Node will report AFFECTED.")
	}
	if getenv("PYTHONHTTPSVERIFY") == "0" {
		warning("PYTHONHTTPSVERIFY=0 is set (ignored by the isolated probes, but affects your own Python scripts).")
	}
	if r.Verbose >= 1 {
		r.printf("%s== CA-related environment ==%s\n", r.c(cBld), r.c(cOff))
		if !any {
			r.printf("  no CA-related variables set\n")
		} else {
			r.printf("%s", out.String())
		}
		r.printf("  The probes below inherit this environment, so each result is how the tool behaves in this shell.\n\n")
	} else if any || warn {
		r.printf("%sCA-related environment (affects the results below):%s\n%s\n", r.c(cBld), r.c(cOff), out.String())
	}
}

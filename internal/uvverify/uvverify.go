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

// Package uvverify holds the checks both uv fixers make before and after they change
// anything: that uv itself is fixed enough to be allowed to download (uv_fix_ready), and
// that an interpreter's every Python trust path rejects the compromised chain
// (verify_uv_python). It exists so the two fixers cannot drift apart.
package uvverify

import (
	"context"
	"regexp"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/advisory"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/python"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/version"
)

var strictVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// UVVersion is version_of uv: the second field of the first line of `uv --version`.
func UVVersion(ctx context.Context, s *fixrun.Session, uvBin string) string {
	out := s.Run.Run(ctx, uvBin, "--version").Stdout
	line := strings.SplitN(strings.TrimSpace(out), "\n", 2)[0]
	f := strings.Fields(line)
	if len(f) < 2 {
		return ""
	}
	return f[1]
}

// fixedUV is the first uv release with the fix (the script's UV_FIXED).
func fixedUV() string {
	if v := advisory.GetFixedVersions("uv"); len(v) > 0 {
		return v[0].Version
	}
	return ""
}

// Ready ports uv_fix_ready. uv must itself be fixed before it may download repair packages:
// it would otherwise fetch them through the TLS implementation the advisory is about. The
// version must be a plain x.y.z; anything else ("unknown", a pre-release) is refused.
func Ready(ctx context.Context, s *fixrun.Session, uvBin string) bool {
	v := UVVersion(ctx, s, uvBin)
	fixed := fixedUV()
	if !strictVersion.MatchString(v) || !version.Parse(v).GE(version.Parse(fixed)) {
		shown := v
		if shown == "" {
			shown = "unknown"
		}
		s.Bad("uv %s cannot safely perform these downloads; upgrade uv itself first to %s or later", shown, fixed)
		return false
	}
	return true
}

// Result is the outcome of verifying an interpreter.
type Result struct {
	// Version is the interpreter's version (UV_VERIFY_VERSION), set once it could be read.
	Version string
	// Reason is empty when the interpreter passed; otherwise the script's UV_VERIFY_REASON.
	Reason string
}

// Passed reports whether verification succeeded.
func (r Result) Passed() bool { return r.Reason == "" }

// Python ports verify_uv_python. A successful upgrade must protect EVERY Python trust path
// that can be probed. Unlike the audit summary, an inconclusive component cannot pass: one
// rejected store cannot certify another that could not be tested.
//
// minor is "3.11"; minimum, when set, is the patch the catalogue offered, and an interpreter
// older than it did not receive the upgrade.
func Python(ctx context.Context, env *kinds.Env, p, minor, minimum string) Result {
	pr, err := python.Interpret(ctx, env, p)
	if err != nil || pr.Info == nil {
		return Result{Reason: "Python metadata could not be read"}
	}
	info := pr.Info
	res := Result{Version: info.Version}

	if minorOf(info.Version) != minor || info.Implementation != "cpython" {
		res.Reason = "Python minor version or implementation changed unexpectedly"
		return res
	}
	if minimum != "" && !version.Parse(info.Version).GE(version.Parse(minimum)) {
		res.Reason = "selected Python " + info.Version + " is older than the available patch " + minimum
		return res
	}
	if cf := info.Certifi; cf != "" && !version.Parse(cf).GE(version.Parse(minCertifi())) {
		res.Reason = "certifi " + cf + " is still older than the fixed release " + minCertifi()
		return res
	}
	if pip := info.Pip; pip != "" && !version.Parse(pip).GE(version.Parse(minPip())) {
		res.Reason = "pip " + pip + " is still older than the fixed release " + minPip()
		return res
	}

	// every path that applies must be conclusive AND reject the chain
	modes := []struct {
		name string
		v    probe.Verdict
		skip bool
	}{
		{"default", pr.Default, false},
		{"certifi", pr.Certifi, info.Certifi == ""},
		{"pip", pr.Pip, info.Pip == ""},
	}
	for _, m := range modes {
		if m.skip {
			continue
		}
		if m.v != probe.VerdictRejected {
			shown := string(m.v)
			if shown == "" {
				shown = "no result"
			}
			res.Reason = m.name + " TLS probe: " + shown
			return res
		}
	}
	return res
}

func minorOf(v string) string {
	i := strings.LastIndex(v, ".")
	if i < 0 {
		return v
	}
	return v[:i]
}

func minCertifi() string { return firstFixed("certifi") }
func minPip() string     { return firstFixed("pip") }

func firstFixed(tool string) string {
	if v := advisory.GetFixedVersions(tool); len(v) > 0 {
		return v[0].Version
	}
	return ""
}

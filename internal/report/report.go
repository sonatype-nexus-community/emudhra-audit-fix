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

// Package report renders findings and computes the exit code. It ports the
// script's report(), describe_probe(), describe_version(), compact_why() and
// summary code. The status of a finding is derived by kinds.Finding.Status;
// nothing here chooses it.
package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
)

// ANSI sequences, as the script's C_* variables.
const (
	cRed = "\033[31m"
	cGrn = "\033[32m"
	cYel = "\033[33m"
	cDim = "\033[2m"
	cBld = "\033[1m"
	cOff = "\033[0m"
)

// Counts are the three summary buckets of the script (N_BAD, N_OK, N_UNK).
type Counts struct {
	Bad     int // AFFECTED and LIKELY-AFFECTED
	OK      int // OK and LIKELY-OK
	Unknown int
}

// Reporter renders findings to Output.
type Reporter struct {
	Verbose    int // 0 compact, 1 full detail (-v), 2 also raw probe detail (-vv)
	NoGuidance bool
	Color      bool   // ANSI colour; the caller sets it from tty detection
	Home       string // replaces a leading home directory with ~ in compact lines
	Missing    string // "Not installed / not applicable" list, compact mode only
	Host       platform.Host
	FixMode    bool   // --fix was given: guidance says nothing has been run YET
	ProgName   string // the program name used in "Apply fixes" hints
	Output     io.Writer

	// Sections, in audit order, give the verbose report its per-tool headers. When empty the
	// findings are printed in sequence without them.
	Sections []Section
}

// NewReporter creates a Reporter writing to stdout with no colour. Callers
// that detected a terminal set Color.
func NewReporter(verbose int, noGuidance bool) *Reporter {
	return &Reporter{Verbose: verbose, NoGuidance: noGuidance, Output: os.Stdout}
}

func (r *Reporter) c(code string) string {
	if r.Color {
		return code
	}
	return ""
}

func (r *Reporter) printf(format string, a ...any) {
	_, _ = fmt.Fprintf(r.Output, format, a...)
}

// Tally counts findings into the script's three buckets.
func Tally(findings []kinds.Finding) Counts {
	var n Counts
	for _, f := range findings {
		switch s := f.Status(); {
		case s.IsBad():
			n.Bad++
		case s.IsOK():
			n.OK++
		default:
			n.Unknown++
		}
	}
	return n
}

// Report renders every finding, then the summary.
func (r *Reporter) Report(findings []kinds.Finding) error {
	if r.Verbose >= 1 && len(r.Sections) > 0 {
		r.renderSections(findings)
	} else {
		for _, f := range findings {
			r.renderFinding(f)
		}
	}
	r.renderSummary(Tally(findings))
	if !r.NoGuidance {
		r.renderGuidance(findings)
	}
	return nil
}

func (r *Reporter) statusColor(s kinds.Status) string {
	switch {
	case s.IsBad():
		return r.c(cRed)
	case s.IsOK():
		return r.c(cGrn)
	}
	return r.c(cYel)
}

// renderSections prints each tool's header, then its findings or why there are none
// (audit_start / audit_none). Findings of a Kind with no section follow, so none is lost.
func (r *Reporter) renderSections(findings []kinds.Finding) {
	known := map[string]bool{}
	for _, sec := range r.Sections {
		known[sec.ID] = true
		r.printf("%s== %s ==%s\n", r.c(cBld), sec.Title, r.c(cOff))
		n := 0
		for _, f := range findings {
			if f.Kind == sec.ID {
				r.renderFinding(f)
				n++
			}
		}
		if n == 0 {
			r.printf("  %s\n\n", sec.None)
		}
		if sec.Note != "" {
			r.printf("  %s\n\n", sec.Note)
		}
	}
	for _, f := range findings {
		if !known[f.Kind] {
			r.renderFinding(f)
		}
	}
}

// renderFinding ports the output half of report().
func (r *Reporter) renderFinding(f kinds.Finding) {
	status := f.Status()
	col := r.statusColor(status)
	ver := f.Version

	if r.Verbose >= 1 {
		r.printf("%s%s[%s]%s %s %s\n", r.c(cBld), col, status, r.c(cOff), f.Tool, ver)
		r.printf("    path:    %s\n", f.Path)
		vtxt := DescribeVersion(f.VersionCheck)
		if f.VersionNote != "" {
			vtxt += " - " + f.VersionNote
		}
		r.printf("    version: %s\n", vtxt)
		r.printf("    probe:   %s\n", DescribeProbe(f))
		if f.Notes != "" {
			r.printf("%s\n", f.Notes)
		}
		r.printf("\n")
		return
	}

	r.printf("%s%s[%s]%s %s %s", r.c(cBld), col, status, r.c(cOff), f.Tool, ver)
	r.printf("  %s%s%s", r.c(cDim), discover.CompactPath(f.Path, r.Home), r.c(cOff))
	if why := CompactWhy(f); why != "" {
		r.printf("  - %s", why)
	}
	r.printf("\n")
}

// renderSummary ports the script's closing summary.
func (r *Reporter) renderSummary(n Counts) {
	if r.Verbose >= 1 {
		r.printf("%s== Summary ==%s\n", r.c(cBld), r.c(cOff))
		r.printf("  affected / likely affected: %d\n  ok / likely ok:             %d\n  unknown:                    %d\n\n", n.Bad, n.OK, n.Unknown)
		r.printf("Notes: 'AFFECTED'/'OK' come from a live probe. 'LIKELY-*' are version-only.\n")
		r.printf("Not covered yet: Rust crates in your projects (rustls-webpki, webpki-roots), Perl Mozilla::CA, Composer,\n")
		r.printf("Elixir/Erlang, containers and per-project virtualenvs/node_modules.\n\n")
		return
	}
	if r.Missing != "" {
		r.printf("%sNot installed / not applicable:%s %s\n\n", r.c(cDim), r.c(cOff), r.Missing)
	}
	r.printf("%sSummary:%s %s%d affected%s, %s%d ok%s, %s%d unknown%s   (-v for the full report)\n\n",
		r.c(cBld), r.c(cOff),
		r.c(cRed), n.Bad, r.c(cOff),
		r.c(cGrn), n.OK, r.c(cOff),
		r.c(cYel), n.Unknown, r.c(cOff))
}

// DescribeProbe ports describe_probe(). The reason text for skipped and
// inconclusive probes is the finding's Evidence.
func DescribeProbe(f kinds.Finding) string {
	switch f.ProbeResult {
	case kinds.ProbeTrusted:
		return "AFFECTED - connected to a host using the compromised chain"
	case kinds.ProbeRejected:
		return "protected - certificate rejected"
	case kinds.ProbeSkipped:
		return "skipped (" + f.Evidence + ")"
	case kinds.ProbeInconclusive:
		return "inconclusive - " + f.Evidence
	}
	return string(f.ProbeResult)
}

// DescribeVersion ports describe_version().
func DescribeVersion(v kinds.VersionCheck) string {
	switch v {
	case kinds.VersionOK:
		return "up to date"
	case kinds.VersionBehind:
		return "BEHIND"
	case kinds.VersionNoFix:
		return "NO FIX for this release line"
	case kinds.VersionNA:
		return "n/a"
	}
	return "could not determine"
}

// CompactWhy ports compact_why(): the one reason worth showing next to a
// status in compact mode.
func CompactWhy(f kinds.Finding) string {
	vn := f.VersionNote
	if i := strings.Index(vn, " (page lists"); i >= 0 {
		vn = vn[:i]
	}
	behind := f.VersionCheck == kinds.VersionBehind || f.VersionCheck == kinds.VersionNoFix
	switch f.Status() {
	case kinds.StatusAffected:
		if behind {
			return "trusts the compromised chain; also behind (" + vn + ")"
		}
		return "trusts the compromised chain"
	case kinds.StatusOK:
		if behind {
			return "rejects the chain, but older than the fixed release (" + vn + ")"
		}
		return "rejects the chain"
	case kinds.StatusLikelyAffected, kinds.StatusLikelyOK:
		return "version-only: " + vn
	}
	switch f.ProbeResult {
	case kinds.ProbeInconclusive, kinds.ProbeSkipped:
		why := f.Evidence
		if len(why) > 90 {
			why = why[:90]
		}
		return why
	}
	return ""
}

// ExitCode is 1 when at least one finding is AFFECTED or LIKELY-AFFECTED and
// 0 otherwise, as the script's "[ N_BAD -gt 0 ] && exit 1". Usage errors (2)
// are handled by the caller.
func ExitCode(findings []kinds.Finding) int {
	if Tally(findings).Bad > 0 {
		return 1
	}
	return 0
}

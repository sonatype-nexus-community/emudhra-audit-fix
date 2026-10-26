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

// Package kinds defines the Kind interface, Env, Finding, and Action types.
// A Kind is one class of thing we audit and may fix. Each Kind owns its
// discovery, audit, fix plan, fix execution, and undo.
package kinds

import (
	"context"
	"log/slog"
	"os"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/backup"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/privilege"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/prompt"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/version"
)

// Kind is one class of thing we audit and may fix.
type Kind interface {
	// ID is the stable identifier used by --only and in reports (e.g. "uv", "java").
	ID() string

	// Describe is a one-line human description for list-kinds and README generation.
	Describe() string

	// Applicable reports whether this Kind makes sense on this host at all.
	// Cheap: no network, no heavy discovery. A false result is reported as "skipped: <reason>".
	Applicable(h platform.Host) Applicability

	// Audit discovers installations and returns findings (verdict + evidence).
	Audit(ctx context.Context, env *Env) ([]Finding, error)
}

// Fixer is optionally implemented by Kinds that can remediate. Plan turns the
// Kind's findings into the fixes --fix may offer; it has no side effects. Each
// returned fixrun.Fix does its own confirm, backup, apply, verify and restore
// through its fixrun.Session. Plan is the script's plan_add: only findings the
// script would schedule produce a Fix.
//
// Plan receives the findings of EVERY Kind, in registry order, not only its
// own: in the script one tool's audit can schedule another Kind's fix (a Python
// finding that sets NeedsPipGuidance plans the macOS pip fix). A Fixer picks
// out the findings it acts on, by Finding.Kind and the flags on the finding.
type Fixer interface {
	Kind
	// FixOrder ranks this Kind's fixes among all Kinds'; lower runs first. Use
	// the Fix* constants, which are the script's run_fixes order.
	FixOrder() int
	Plan(ctx context.Context, env *Env, findings []Finding) ([]fixrun.Fix, error)
}

// The order in which --fix runs Kinds, from the script's run_fixes:
// "package/upgrade fixes first, then the system store, then the stop-gaps that
// depend on it". It is independent of the audit order, which is the registry
// order. Each Fixer returns one of these from FixOrder.
const (
	FixBrew     = 10
	FixSys      = 20 // sysbundle and ospkg
	FixJava     = 30
	FixMacPip   = 40
	FixNode     = 50
	FixUV       = 60
	FixUVPython = 70
	FixUVTools  = 80
	FixRustup   = 90
)

// VersionOnlyProbeReason is why audits of tools that cannot be probed show "skipped": the script's
// text for rustup, uv, pixi, mise and Claude Code.
const VersionOnlyProbeReason = "no safe way to probe this tool's own TLS - version check only"

// Absent is implemented by a Kind whose "found nothing" message in the verbose report is not the
// default "not found" (the script's audit_none TEXT).
type Absent interface {
	AbsentText(env *Env) string
}

// SectionNoter is implemented by a Kind that adds a note under its section in the verbose report,
// whether or not it found anything.
type SectionNoter interface {
	SectionNote(env *Env) string
}

// Undoer is optionally implemented by Kinds whose backups --undo restores. It
// ports the Kind's part of run_undo: find the newest FILE.pre-emudhra-* backups
// the Kind knows about, say what would be restored, and (outside a dry run)
// confirm and restore each.
type Undoer interface {
	Kind
	Undo(ctx context.Context, env *Env, s *fixrun.Session) error
}

// Applicability reports whether a Kind is applicable to a host.
type Applicability struct {
	Applies bool
	Reason  string // shown when !Applies, e.g. "macOS only"
}

// Env carries injected dependencies so Kinds are testable.
type Env struct {
	Host           platform.Host
	Run            exec.Runner
	Probe          probe.Engine
	Prompt         prompt.Prompter
	Priv           privilege.Escalator
	Log            *slog.Logger
	DryRun         bool
	Yes            bool
	Offline        bool
	WorkaroundOnly bool
	TempDir        string
	Backup         backup.Store

	// Environ overrides the process environment for tests: when non-nil,
	// Getenv reads only from it. Production leaves it nil.
	Environ map[string]string
}

// Getenv returns the value of an environment variable. Kinds must use this,
// never os.Getenv, so tests can supply a fixed environment.
func (e *Env) Getenv(key string) string {
	if e.Environ != nil {
		return e.Environ[key]
	}
	return os.Getenv(key)
}

// Path returns the PATH to search for executables, as `command -v` would.
func (e *Env) Path() string { return e.Getenv("PATH") }

// Home returns the user's home directory, from HOME.
func (e *Env) Home() string { return e.Getenv("HOME") }

// ProbeResult represents the result of a TLS probe for a finding.
type ProbeResult string

const (
	ProbeTrusted      ProbeResult = "trusted"      // AFFECTED - trusted the compromised chain
	ProbeRejected     ProbeResult = "rejected"     // Protected - certificate rejected
	ProbeInconclusive ProbeResult = "inconclusive" // Could not determine
	ProbeSkipped      ProbeResult = "skipped"      // Skipped (--no-network)
)

// VersionCheck is the outcome of comparing an installed version with the
// fixed release. It ports the script's VC values (ok, behind, nofix, na,
// unknown).
type VersionCheck string

const (
	VersionOK      VersionCheck = "ok"      // at or past the fixed release
	VersionBehind  VersionCheck = "behind"  // older than the fixed release
	VersionNoFix   VersionCheck = "nofix"   // no fixed release for this line
	VersionNA      VersionCheck = "na"      // no version check applies
	VersionUnknown VersionCheck = "unknown" // version could not be read
)

// Status is the reported status of a finding. It is DERIVED from the probe
// result and the version check by Finding.Status; Kinds must not choose it.
// The values and their meaning are the script's report() statuses.
type Status string

const (
	StatusAffected       Status = "AFFECTED"        // probe: trusts the compromised chain
	StatusLikelyAffected Status = "LIKELY-AFFECTED" // no conclusive probe, version behind or no fix
	StatusOK             Status = "OK"              // probe: rejects the chain
	StatusLikelyOK       Status = "LIKELY-OK"       // no conclusive probe, version fixed
	StatusUnknown        Status = "UNKNOWN"         // cannot tell
)

// IsBad reports whether the status counts as affected for the summary and
// the exit code (AFFECTED and LIKELY-AFFECTED).
func (s Status) IsBad() bool { return s == StatusAffected || s == StatusLikelyAffected }

// IsOK reports whether the status counts as OK (OK and LIKELY-OK).
func (s Status) IsOK() bool { return s == StatusOK || s == StatusLikelyOK }

// Verdict is the former name of Status.
//
// Deprecated: use Status. Retained only so branches written against the
// earlier model keep compiling while they are migrated.
type Verdict = Status

// Finding carries all information about an audited item.
type Finding struct {
	// Kind is the ID of the Kind that produced this finding.
	Kind string

	// Tool is the tool name (e.g., "node", "uv", "java").
	Tool string

	// Path is the path to the installation (if applicable).
	Path string

	// Version is the detected version (if any).
	Version string

	// FixedVersion is the minimum fixed version (if known).
	FixedVersion string

	// ProbeResult is the TLS probe outcome (if probed).
	ProbeResult ProbeResult

	// Evidence is additional context or diagnostic information.
	Evidence string

	// Notes is additional notes or warnings.
	Notes string

	// GuidanceCompact is one-line remediation guidance (compact mode).
	GuidanceCompact string

	// GuidanceFull is multi-line detailed remediation guidance (verbose mode).
	GuidanceFull []string

	// NeedsSystemGuidance asks the report to print the shared "System trust
	// store" block once (the script's FIXSYS). Set it when the remedy is to
	// patch the OS CA bundle; do not copy the recipe text into the Finding.
	NeedsSystemGuidance bool

	// NeedsPipGuidance asks the report to print the shared "Built-in pip
	// (macOS)" block once (the script's FIXPIP).
	NeedsPipGuidance bool

	// HasFix records that --fix can act on this finding (the script's
	// plan_add), so the report offers "Apply fixes: ... --fix --dry-run".
	HasFix bool

	// VersionCheck is how Version compares with FixedVersion. Kinds with no
	// version check leave it empty (treated as VersionNA).
	VersionCheck VersionCheck

	// VersionNote explains the version check, e.g. "fixed in 1.26.10".
	VersionNote string

	// Requests ask other Kinds' fixers to act on a target: the script's
	// `plan_add KIND TARGET`. They are for fixes whose trigger is another tool's
	// audit and whose target is more than a flag (the uv Python minor line to
	// upgrade, the uv tool to rebuild). The Kind that owns the fix reads them with
	// RequestsFor.
	Requests []FixRequest
}

// FixRequest is one plan_add: Kind's fixer should act on Target. Minimum is an optional
// version the fix must reach (plan_uv_python's target patch).
type FixRequest struct {
	Kind    string
	Target  string
	Minimum string
}

// NewFinding creates a Finding with no probe and no version check, which
// derives to StatusUnknown until a Kind records facts.
func NewFinding(kind, tool string) Finding {
	return Finding{Kind: kind, Tool: tool, ProbeResult: ProbeSkipped, VersionCheck: VersionNA}
}

// SetProbe records the probe outcome and any evidence.
func (f *Finding) SetProbe(result ProbeResult, evidence string) {
	f.ProbeResult = result
	f.Evidence = evidence
}

// SetVersion records the installed version and how it compares with the
// fixed release. note is the script's VN text (for example "fixed in 2.9.8").
func (f *Finding) SetVersion(version, fixedVersion string, check VersionCheck, note string) {
	f.Version = version
	f.FixedVersion = fixedVersion
	f.VersionCheck = check
	f.VersionNote = note
}

// Status derives the reported status exactly as the script's report() did:
// a conclusive probe wins over the version check; otherwise a version that is
// behind (or has no fix) is LIKELY-AFFECTED and a fixed version is
// LIKELY-OK. An inconclusive or skipped probe with no usable version check is
// UNKNOWN.
func (f Finding) Status() Status {
	switch f.ProbeResult {
	case ProbeTrusted:
		return StatusAffected
	case ProbeRejected:
		return StatusOK
	}
	switch f.VersionCheck {
	case VersionBehind, VersionNoFix:
		return StatusLikelyAffected
	case VersionOK:
		return StatusLikelyOK
	}
	return StatusUnknown
}

// BehindButProtected reports the script's "advise" case: the probe rejects
// the chain (status OK) but the version is behind or has no fix, so the tool
// is protected today and should still be upgraded when convenient.
func (f Finding) BehindButProtected() bool {
	return f.Status() == StatusOK && (f.VersionCheck == VersionBehind || f.VersionCheck == VersionNoFix)
}

// AddGuidance adds remediation guidance.
func (f *Finding) AddGuidance(compact string, full ...string) {
	f.GuidanceCompact = compact
	f.GuidanceFull = append(f.GuidanceFull, full...)
}

// String returns a human-readable summary.
func (f Finding) String() string {
	return f.Tool + " (" + f.Version + "): " + string(f.Status())
}

// WantsSystemFix reports whether any finding asks for the host-wide system
// trust store fix: a bad status (AFFECTED or LIKELY-AFFECTED) on a finding
// whose remedy is to patch the OS CA bundle. It ports the script's
// `[ "$FIXSYS" = 1 ] && plan_add sys system` in report(). The fix is planned
// once per host however many tools ask for it, by the Kind that owns the
// host's store (sysbundle on macOS, ospkg on Linux).
func WantsSystemFix(findings []Finding) bool {
	for _, f := range findings {
		if f.NeedsSystemGuidance && f.Status().IsBad() {
			return true
		}
	}
	return false
}

// RequestsFor collects the requests addressed to a Kind from every finding, as the
// script's plan_add does: duplicates of a target are merged, and where several requests
// name a Minimum for the same target the highest wins (plan_uv_python keeps the newest
// target it is given). The result keeps first-seen order.
func RequestsFor(kind string, findings []Finding) []FixRequest {
	var order []string
	merged := map[string]FixRequest{}
	for _, f := range findings {
		for _, r := range f.Requests {
			if r.Kind != kind || r.Target == "" {
				continue
			}
			cur, seen := merged[r.Target]
			if !seen {
				order = append(order, r.Target)
				merged[r.Target] = r
				continue
			}
			if r.Minimum != "" && (cur.Minimum == "" || version.Parse(r.Minimum).GE(version.Parse(cur.Minimum))) {
				cur.Minimum = r.Minimum
				merged[r.Target] = cur
			}
		}
	}
	out := make([]FixRequest, 0, len(order))
	for _, t := range order {
		out = append(out, merged[t])
	}
	return out
}

// ResultOf converts a probe verdict to the ProbeResult a Finding records.
func ResultOf(v probe.Verdict) ProbeResult {
	switch v {
	case probe.VerdictTrusted:
		return ProbeTrusted
	case probe.VerdictRejected:
		return ProbeRejected
	case probe.VerdictSkipped:
		return ProbeSkipped
	default:
		return ProbeInconclusive
	}
}

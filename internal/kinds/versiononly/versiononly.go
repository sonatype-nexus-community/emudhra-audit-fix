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

// Package versiononly provides a shared helper for Kinds that perform
// version-only audits (pixi, mise, claudecode, rustup, uv) without TLS probes.
// It ports audit_simple and version_of from the legacy script.
package versiononly

import (
	"context"
	"fmt"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/advisory"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/version"
)

// ToolSpec describes a tool that uses version-only auditing.
// It contains the Kind-specific parts that vary between pixi, mise, claudecode, etc.
type ToolSpec struct {
	// ID is the stable identifier for the Kind (e.g., "pixi", "mise", "claudecode").
	ID string

	// Name is the tool name shown in findings (e.g., "pixi", "mise", "Claude Code").
	// This is the first argument to report() in the script, the $label in audit_simple.
	Name string

	// Description is the one-line description for list-kinds (e.g., "Pixi package manager").
	// If empty, Name is used.
	Description string

	// Binary is the executable name (e.g., "pixi", "mise", "claude").
	Binary string

	// AdvisoryTool is the key in internal/advisory for fixed versions (e.g., "pixi", "claude").
	AdvisoryTool string

	// VersionExtract extracts the version from the tool's --version output.
	// The function receives the entire stdout and returns the bare version string.
	// If nil, defaults to discover.ExtractVersion (standard "tool X.Y.Z" format).
	VersionExtract func(output string) string

	// ExtraCandidates are additional candidate paths beyond PATH lookup.
	// These are passed to discover.Candidates.
	ExtraCandidates func(home string) []string

	// Guidance returns upgrade guidance. compact is one line, full is detailed.
	// fixedVersion is the minimum fixed version for this tool.
	Guidance func(fixedVersion string) (compact string, full []string)
}

// Kind implements kinds.Kind for a version-only tool.
type Kind struct {
	spec ToolSpec
}

// New creates a new version-only Kind from the given spec.
func New(spec ToolSpec) kinds.Kind {
	return &Kind{spec: spec}
}

// ID returns the stable identifier.
func (k *Kind) ID() string {
	return k.spec.ID
}

// Describe returns a one-line description.
func (k *Kind) Describe() string {
	if k.spec.Description != "" {
		return k.spec.Description
	}
	return k.spec.Name
}

// Applicable reports that version-only tools apply on all platforms.
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	return kinds.Applicability{Applies: true}
}

// Audit discovers installations and returns findings.
// This ports audit_simple from the bash script (lines 1505-1533).
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	var findings []kinds.Finding

	// Build candidate list
	var candidates []string
	if k.spec.ExtraCandidates != nil {
		candidates = discover.Candidates(k.spec.ExtraCandidates(env.Home())...)
	}

	// Add PATH lookup
	if p := discover.Lookup(k.spec.Binary, env.Path()); p != "" {
		candidates = append(candidates, p)
	}

	// Filter to executables only
	candidates = discover.Executables(candidates)

	// Get fixed version from advisory
	fixedVersions := advisory.GetFixedVersions(k.spec.AdvisoryTool)
	if len(fixedVersions) == 0 {
		// No fixed version known - should not happen in production
		f := kinds.NewFinding(k.spec.ID, k.spec.Name)
		f.Evidence = "no fixed version known for this tool"
		f.SetProbe(kinds.ProbeSkipped, "version check unavailable")
		return []kinds.Finding{f}, nil
	}

	// Use the first fixed version for the primary check
	// (some tools like rustup and node have multiple fixed versions per line)
	fixedVersion := fixedVersions[0].Version

	// Deduplicate by resolved path
	seen := &discover.Seen{}

	for _, path := range candidates {
		// Resolve symlinks and deduplicate
		resolved := discover.Resolve(path)
		key := k.spec.ID + ":" + resolved
		if !seen.First(key) {
			continue
		}

		// Get version via --version
		result := env.Run.Run(ctx, path, "--version")
		if result.Error != nil || result.ExitCode != 0 {
			// Cannot determine version
			f := kinds.NewFinding(k.spec.ID, k.spec.Name)
			f.Path = path
			f.SetProbe(kinds.ProbeSkipped, fmt.Sprintf("version check failed: %v", result.Error))
			f.AddGuidance("(no specific guidance - see https://emudhra.we-have-a-problem.com/)")
			findings = append(findings, f)
			continue
		}

		// Extract version
		var ver string
		if k.spec.VersionExtract != nil {
			ver = k.spec.VersionExtract(result.Stdout)
		} else {
			ver = discover.ExtractVersion(result.Stdout)
		}

		if ver == "" {
			ver = "unknown"
		}

		// Compare with fixed version
		v := version.Parse(ver)
		fixed := version.Parse(fixedVersion)

		f := kinds.NewFinding(k.spec.ID, k.spec.Name)
		f.Path = path

		if v.GE(fixed) {
			// Version is fixed or newer
			f.SetProbe(kinds.ProbeSkipped, kinds.VersionOnlyProbeReason)
			f.SetVersion(ver, fixedVersion, kinds.VersionOK, "fixed in "+fixedVersion)
		} else {
			// Version is behind
			f.SetProbe(kinds.ProbeSkipped, kinds.VersionOnlyProbeReason)
			f.SetVersion(ver, fixedVersion, kinds.VersionBehind, "fixed in "+fixedVersion)
		}

		// Add guidance
		if k.spec.Guidance != nil {
			compact, full := k.spec.Guidance(fixedVersion)
			f.AddGuidance(compact, full...)
		}

		findings = append(findings, f)
	}

	return findings, nil
}

// ExtractFirstField extracts the first field from the first line of output.
// This is used by mise and claudecode (script lines 1594-1595).
func ExtractFirstField(output string) string {
	lines := strings.Split(output, "\n")
	if len(lines) == 0 {
		return ""
	}
	fields := strings.Fields(lines[0])
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

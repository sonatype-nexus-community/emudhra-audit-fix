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

// Package pixi implements the Kind for the pixi package manager.
// Pixi is a package manager for Python projects. This Kind performs
// version-only audits (no TLS probe) against the eMudhra advisory.
package pixi

import (
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/versiononly"
)

// SectionTitle is the audit_start title for pixi, shown in verbose mode.
// Note: pixi uses audit_simple which passes "$label" to report, and the label is "pixi".
const SectionTitle = "pixi"

// New creates a new pixi Kind.
func New() kinds.Kind {
	return versiononly.New(versiononly.ToolSpec{
		ID:           "pixi",
		Name:         "pixi",
		Description:  "Pixi package manager",
		Binary:       "pixi",
		AdvisoryTool: "pixi",
		// Pixi outputs: "pixi 0.82.1" (standard format, second field)
		// Default discover.ExtractVersion handles this correctly.
		VersionExtract: nil,
		ExtraCandidates: func(home string) []string {
			// $HOME/.pixi/bin/pixi is the primary location (script line 3227)
			return []string{home + "/.pixi/bin/pixi"}
		},
		Guidance: func(fixedVersion string) (string, []string) {
			// From script line 3227:
			// "pixi self-update   (or: brew upgrade pixi)"
			compact := "pixi self-update   (or: brew upgrade pixi)"
			full := []string{
				"Upgrade pixi to " + fixedVersion + " or later: pixi self-update",
			}
			return compact, full
		},
	})
}

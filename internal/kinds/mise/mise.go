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

// Package mise implements the Kind for the mise (formerly rtx) tool version manager.
// Mise is a tool version manager (successor to rtx). This Kind performs
// version-only audits (no TLS probe) against the eMudhra advisory.
package mise

import (
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/versiononly"
)

// SectionTitle is the audit_start title for mise, shown in verbose mode.
// Note: mise uses audit_simple which passes "$label" to report, and the label is "mise".
const SectionTitle = "mise"

// New creates a new mise Kind.
func New() kinds.Kind {
	return versiononly.New(versiononly.ToolSpec{
		ID:           "mise",
		Name:         "mise",
		Description:  "Mise tool version manager",
		Binary:       "mise",
		AdvisoryTool: "mise",
		// Mise outputs: "2026.10.17 linux-arm64 (2024-10-23)" (script line 1594: first field)
		VersionExtract: versiononly.ExtractFirstField,
		ExtraCandidates: func(home string) []string {
			// $HOME/.local/bin/mise is the primary location (script line 3228)
			return []string{home + "/.local/bin/mise"}
		},
		Guidance: func(fixedVersion string) (string, []string) {
			// From script line 3228:
			// "mise self-update   (or: brew upgrade mise)"
			compact := "mise self-update   (or: brew upgrade mise)"
			full := []string{
				"Upgrade mise to " + fixedVersion + " or later: mise self-update",
			}
			return compact, full
		},
	})
}

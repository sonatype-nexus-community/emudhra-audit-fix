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

// Package claudecode implements the Kind for Claude Code CLI.
// Claude Code is an AI-powered development assistant CLI. This Kind performs
// version-only audits (no TLS probe) against the eMudhra advisory.
package claudecode

import (
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/versiononly"
)

// SectionTitle is the audit_start title for Claude Code, shown in verbose mode.
// Note: Claude Code uses audit_simple with label "Claude Code" (script line 3229).
const SectionTitle = "Claude Code"

// New creates a new claudecode Kind.
func New() kinds.Kind {
	return versiononly.New(versiononly.ToolSpec{
		ID:           "claudecode",
		Name:         "Claude Code",
		Description:  "Claude Code",
		Binary:       "claude",
		AdvisoryTool: "claude",
		// Claude Code outputs: "2.1.303" (script line 1595: first field)
		VersionExtract: versiononly.ExtractFirstField,
		ExtraCandidates: func(home string) []string {
			// Two primary locations (script line 3229):
			// $HOME/.local/bin/claude and $HOME/.claude/local/claude
			return []string{
				home + "/.local/bin/claude",
				home + "/.claude/local/claude",
			}
		},
		Guidance: func(fixedVersion string) (string, []string) {
			// From script line 3229:
			// "claude update"
			compact := "claude update"
			full := []string{
				"Upgrade Claude Code to " + fixedVersion + " or later: claude update",
			}
			return compact, full
		},
	})
}

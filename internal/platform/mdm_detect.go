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

package platform

import (
	"context"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
)

func init() {
	// Wire up real MDM detection using the exec package
	detectMDM = realDetectMDM
}

// realDetectMDM implements MDM detection using the exec package.
// Ports the logic from legacy/emudhra-audit-fix.sh line 3093.
func realDetectMDM() MDMStatus {
	runner := exec.NewRealRunner()
	ctx := context.Background()
	result := runner.Run(ctx, "profiles", "status", "-type", "enrollment")

	// Parse output like the bash script line 3093:
	// if profiles status -type enrollment 2>/dev/null </dev/null | grep -qi 'enrolled via DEP: *Yes\|MDM enrollment: *Yes'
	output := result.Stdout + "\n" + result.Stderr
	outputLower := strings.ToLower(output)

	// Check for DEP enrollment: "enrolled via DEP: Yes"
	if strings.Contains(outputLower, "enrolled via dep:") {
		// Extract the line and check for "yes"
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			lineLower := strings.ToLower(line)
			if strings.Contains(lineLower, "enrolled via dep:") {
				if strings.Contains(lineLower, "yes") {
					return MDMStatus{Enrolled: true, Source: "DEP"}
				}
			}
		}
	}

	// Check for MDM enrollment: "MDM enrollment: Yes"
	if strings.Contains(outputLower, "mdm enrollment:") {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			lineLower := strings.ToLower(line)
			if strings.Contains(lineLower, "mdm enrollment:") {
				if strings.Contains(lineLower, "yes") {
					return MDMStatus{Enrolled: true, Source: "MDM"}
				}
			}
		}
	}

	return MDMStatus{Enrolled: false, Source: ""}
}

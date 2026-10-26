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

package ospkg

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

func TestNew(t *testing.T) {
	k := New()
	assert.NotNil(t, k)
	assert.Equal(t, "ospkg", k.ID())
	assert.Equal(t, "OS CA packages (ca-certificates)", k.Describe())
}

func TestApplicable(t *testing.T) {
	k := New()

	tests := []struct {
		name     string
		host     platform.Host
		expected kinds.Applicability
	}{
		{
			name: "darwin not applicable",
			host: platform.Host{
				OS:   "darwin",
				Arch: "arm64",
			},
			expected: kinds.Applicability{
				Applies: false,
				Reason:  "Linux only",
			},
		},
		{
			name: "linux debian applicable",
			host: platform.Host{
				OS:     "linux",
				Arch:   "amd64",
				Family: platform.FamilyDebian,
				Distro: platform.Distro{
					ID:      "ubuntu",
					IDLike:  "debian",
					Version: "22.04",
				},
			},
			expected: kinds.Applicability{
				Applies: true,
			},
		},
		{
			name: "linux redhat applicable",
			host: platform.Host{
				OS:     "linux",
				Arch:   "amd64",
				Family: platform.FamilyRedHat,
				Distro: platform.Distro{
					ID:      "fedora",
					IDLike:  "rhel",
					Version: "40",
				},
			},
			expected: kinds.Applicability{
				Applies: true,
			},
		},
		{
			name: "linux alpine applicable",
			host: platform.Host{
				OS:     "linux",
				Arch:   "amd64",
				Family: platform.FamilyAlpine,
				Distro: platform.Distro{
					ID: "alpine",
				},
			},
			expected: kinds.Applicability{
				Applies: true,
			},
		},
		{
			name: "linux arch applicable",
			host: platform.Host{
				OS:     "linux",
				Arch:   "amd64",
				Family: platform.FamilyArch,
				Distro: platform.Distro{
					ID: "arch",
				},
			},
			expected: kinds.Applicability{
				Applies: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := k.Applicable(tt.host)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAudit_DPKG(t *testing.T) {
	tests := []struct {
		name              string
		host              platform.Host
		runnerSetup       func(*exec.FakeRunner)
		expectedLen       int
		expectedTool      string
		expectedVersion   string
		expectedStatus    kinds.Status
		expectedFixed     string
		expectedGuidance  bool
		expectedNoteCheck string
	}{
		{
			name: "ubuntu 22.04 behind",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyDebian,
				Distro: platform.Distro{
					ID:      "ubuntu",
					Version: "22.04",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddSuccess("dpkg-query -W ca-certificates", "")
				r.AddSuccess("dpkg-query -W -f=${Version} ca-certificates", "20230101")
				// dpkg --compare-versions returns 0 for true, 1 for false
				r.AddError("dpkg --compare-versions 20230101 ge 20260816ubuntu0.22.04.1", 1, "")
			},
			expectedLen:       1,
			expectedTool:      "ca-certificates (dpkg)",
			expectedVersion:   "20230101",
			expectedStatus:    kinds.StatusLikelyAffected,
			expectedFixed:     "20260816ubuntu0.22.04.1",
			expectedGuidance:  true,
			expectedNoteCheck: "fixed in",
		},
		{
			name: "ubuntu 24.04 protected",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyDebian,
				Distro: platform.Distro{
					ID:      "ubuntu",
					Version: "24.04",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddSuccess("dpkg-query -W ca-certificates", "")
				r.AddSuccess("dpkg-query -W -f=${Version} ca-certificates", "20260816ubuntu0.24.04.1")
				// dpkg --compare-versions returns 0 for true
				r.AddSuccess("dpkg --compare-versions 20260816ubuntu0.24.04.1 ge 20260816ubuntu0.24.04.1", "")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (dpkg)",
			expectedVersion:  "20260816ubuntu0.24.04.1",
			expectedStatus:   kinds.StatusLikelyOK,
			expectedFixed:    "20260816ubuntu0.24.04.1",
			expectedGuidance: false,
		},
		{
			name: "debian 12 behind with tilde",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyDebian,
				Distro: platform.Distro{
					ID:      "debian",
					Version: "12",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddSuccess("dpkg-query -W ca-certificates", "")
				r.AddSuccess("dpkg-query -W -f=${Version} ca-certificates", "20250419~deb12u1")
				// dpkg --compare-versions: 20250419~deb12u1 < 20250419~deb12u2
				r.AddError("dpkg --compare-versions 20250419~deb12u1 ge 20250419~deb12u2", 1, "")
			},
			expectedLen:       1,
			expectedTool:      "ca-certificates (dpkg)",
			expectedVersion:   "20250419~deb12u1",
			expectedStatus:    kinds.StatusLikelyAffected,
			expectedFixed:     "20250419~deb12u2",
			expectedGuidance:  true,
			expectedNoteCheck: "fixed in",
		},
		{
			name: "debian 13 protected with plus",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyDebian,
				Distro: platform.Distro{
					ID:      "debian",
					Version: "13",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddSuccess("dpkg-query -W ca-certificates", "")
				r.AddSuccess("dpkg-query -W -f=${Version} ca-certificates", "20250419+deb13u1")
				r.AddSuccess("dpkg --compare-versions 20250419+deb13u1 ge 20250419+deb13u1", "")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (dpkg)",
			expectedVersion:  "20250419+deb13u1",
			expectedStatus:   kinds.StatusLikelyOK,
			expectedFixed:    "20250419+deb13u1",
			expectedGuidance: false,
		},
		{
			name: "debian other version",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyDebian,
				Distro: platform.Distro{
					ID:      "debian",
					Version: "11",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddSuccess("dpkg-query -W ca-certificates", "")
				r.AddSuccess("dpkg-query -W -f=${Version} ca-certificates", "20250419")
				r.AddError("dpkg --compare-versions 20250419 ge 20260816+nmu1", 1, "")
			},
			expectedLen:       1,
			expectedTool:      "ca-certificates (dpkg)",
			expectedVersion:   "20250419",
			expectedStatus:    kinds.StatusLikelyAffected,
			expectedFixed:     "20260816+nmu1",
			expectedGuidance:  true,
			expectedNoteCheck: "fixed in",
		},
		{
			name: "debian with epoch (epoch wins)",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyDebian,
				Distro: platform.Distro{
					ID:      "debian",
					Version: "12",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddSuccess("dpkg-query -W ca-certificates", "")
				r.AddSuccess("dpkg-query -W -f=${Version} ca-certificates", "1:20250419~deb12u1")
				// epoch 1 > no epoch, so dpkg returns true (exit code 0)
				r.AddSuccess("dpkg --compare-versions 1:20250419~deb12u1 ge 20250419~deb12u2", "")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (dpkg)",
			expectedVersion:  "1:20250419~deb12u1",
			expectedStatus:   kinds.StatusLikelyOK,
			expectedFixed:    "20250419~deb12u2",
			expectedGuidance: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := New()
			env := testutil.NewTestEnvWithHost(tt.host)
			tt.runnerSetup(env.Run.(*exec.FakeRunner))

			findings, err := k.Audit(context.Background(), env)
			require.NoError(t, err)
			assert.Len(t, findings, tt.expectedLen)

			if tt.expectedLen > 0 {
				f := findings[0]
				assert.Equal(t, tt.expectedTool, f.Tool)
				assert.Equal(t, tt.expectedVersion, f.Version)
				assert.Equal(t, tt.expectedStatus, f.Status())
				assert.Equal(t, tt.expectedFixed, f.FixedVersion)
				assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult)

				if tt.expectedNoteCheck != "" {
					assert.Contains(t, f.VersionNote, tt.expectedNoteCheck)
				}

				if tt.expectedGuidance {
					assert.NotEmpty(t, f.GuidanceCompact)
					assert.NotEmpty(t, f.GuidanceFull)
				} else {
					assert.Empty(t, f.GuidanceCompact)
					assert.Empty(t, f.GuidanceFull)
				}
			}
		})
	}
}

func TestAudit_DPKG_FallbackToGo(t *testing.T) {
	// Test the pure-Go fallback when dpkg --compare-versions is not available
	tests := []struct {
		name           string
		ver            string
		fixed          string
		expectedStatus kinds.Status
	}{
		{
			name:           "tilde version ordering",
			ver:            "20250419~deb12u1",
			fixed:          "20250419~deb12u2",
			expectedStatus: kinds.StatusLikelyAffected,
		},
		{
			name:           "plus version ordering",
			ver:            "20250419+deb13u1",
			fixed:          "20250419+deb13u1",
			expectedStatus: kinds.StatusLikelyOK,
		},
		{
			name:           "epoch ordering",
			ver:            "1:20250419",
			fixed:          "20260816",
			expectedStatus: kinds.StatusLikelyOK, // epoch 1 > no epoch
		},
		{
			name:           "same date different revision",
			ver:            "20250419~deb12u1",
			fixed:          "20250419~deb12u2",
			expectedStatus: kinds.StatusLikelyAffected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := New()
			env := testutil.NewTestEnvWithHost(platform.Host{
				OS:     "linux",
				Family: platform.FamilyDebian,
				Distro: platform.Distro{ID: "debian", Version: "12"},
			})
			r := env.Run.(*exec.FakeRunner)

			r.AddSuccess("dpkg-query -W ca-certificates", "")
			r.AddSuccess("dpkg-query -W -f=${Version} ca-certificates", tt.ver)
			// Make dpkg --compare-versions fail to test fallback
			r.AddError("dpkg --compare-versions "+tt.ver+" ge "+tt.fixed, -1, "dpkg: command not found")

			findings, err := k.Audit(context.Background(), env)
			require.NoError(t, err)
			require.Len(t, findings, 1)

			f := findings[0]
			assert.Equal(t, tt.expectedStatus, f.Status())
		})
	}
}

func TestAudit_APK(t *testing.T) {
	tests := []struct {
		name             string
		host             platform.Host
		runnerSetup      func(*exec.FakeRunner)
		expectedLen      int
		expectedTool     string
		expectedVersion  string
		expectedStatus   kinds.Status
		expectedGuidance bool
	}{
		{
			name: "alpine behind",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyAlpine,
				Distro: platform.Distro{
					ID: "alpine",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddSuccess("apk info -e ca-certificates", "")
				r.AddSuccess("apk list -I ca-certificates", "ca-certificates-20251020-r0 x86_64 {alpine}")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (apk)",
			expectedVersion:  "20251020-r0",
			expectedStatus:   kinds.StatusLikelyAffected,
			expectedGuidance: true,
		},
		{
			name: "alpine protected",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyAlpine,
				Distro: platform.Distro{
					ID: "alpine",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddSuccess("apk info -e ca-certificates", "")
				r.AddSuccess("apk list -I ca-certificates", "ca-certificates-20261020-r0 x86_64 {alpine}")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (apk)",
			expectedVersion:  "20261020-r0",
			expectedStatus:   kinds.StatusLikelyOK,
			expectedGuidance: false,
		},
		{
			name: "alpine newer version",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyAlpine,
				Distro: platform.Distro{
					ID: "alpine",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddSuccess("apk info -e ca-certificates", "")
				r.AddSuccess("apk list -I ca-certificates", "ca-certificates-20261120-r1 x86_64 {alpine}")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (apk)",
			expectedVersion:  "20261120-r1",
			expectedStatus:   kinds.StatusLikelyOK,
			expectedGuidance: false,
		},
		{
			name: "alpine unknown version format",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyAlpine,
				Distro: platform.Distro{
					ID: "alpine",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddSuccess("apk info -e ca-certificates", "")
				r.AddSuccess("apk list -I ca-certificates", "ca-certificates-invalid x86_64 {alpine}")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (apk)",
			expectedVersion:  "invalid",
			expectedStatus:   kinds.StatusUnknown,
			expectedGuidance: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := New()
			env := testutil.NewTestEnvWithHost(tt.host)
			tt.runnerSetup(env.Run.(*exec.FakeRunner))

			findings, err := k.Audit(context.Background(), env)
			require.NoError(t, err)
			assert.Len(t, findings, tt.expectedLen)

			if tt.expectedLen > 0 {
				f := findings[0]
				assert.Equal(t, tt.expectedTool, f.Tool)
				assert.Equal(t, tt.expectedVersion, f.Version)
				assert.Equal(t, tt.expectedStatus, f.Status())
				assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult)

				if tt.expectedGuidance {
					assert.NotEmpty(t, f.GuidanceCompact)
					assert.NotEmpty(t, f.GuidanceFull)
				} else {
					assert.Empty(t, f.GuidanceCompact)
					assert.Empty(t, f.GuidanceFull)
				}
			}
		})
	}
}

func TestAudit_Pacman(t *testing.T) {
	tests := []struct {
		name             string
		host             platform.Host
		runnerSetup      func(*exec.FakeRunner)
		expectedLen      int
		expectedTool     string
		expectedVersion  string
		expectedStatus   kinds.Status
		expectedGuidance bool
	}{
		{
			name: "arch behind",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyArch,
				Distro: platform.Distro{
					ID: "arch",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddError("apk info -e ca-certificates", 1, "apk: not found")
				r.AddSuccess("pacman -Q ca-certificates-mozilla", "")
				r.AddSuccess("pacman -Q ca-certificates-mozilla", "ca-certificates-mozilla 3.130.0-1")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (pacman)",
			expectedVersion:  "3.130.0-1",
			expectedStatus:   kinds.StatusLikelyAffected,
			expectedGuidance: true,
		},
		{
			name: "arch protected exact match",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyArch,
				Distro: platform.Distro{
					ID: "arch",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddError("apk info -e ca-certificates", 1, "apk: not found")
				r.AddSuccess("pacman -Q ca-certificates-mozilla", "")
				r.AddSuccess("pacman -Q ca-certificates-mozilla", "ca-certificates-mozilla 3.131.1-1")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (pacman)",
			expectedVersion:  "3.131.1-1",
			expectedStatus:   kinds.StatusLikelyOK,
			expectedGuidance: false,
		},
		{
			name: "arch protected newer",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyArch,
				Distro: platform.Distro{
					ID: "arch",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddError("apk info -e ca-certificates", 1, "apk: not found")
				r.AddSuccess("pacman -Q ca-certificates-mozilla", "")
				r.AddSuccess("pacman -Q ca-certificates-mozilla", "ca-certificates-mozilla 3.132.0-2")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (pacman)",
			expectedVersion:  "3.132.0-2",
			expectedStatus:   kinds.StatusLikelyOK,
			expectedGuidance: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := New()
			env := testutil.NewTestEnvWithHost(tt.host)
			tt.runnerSetup(env.Run.(*exec.FakeRunner))

			findings, err := k.Audit(context.Background(), env)
			require.NoError(t, err)
			assert.Len(t, findings, tt.expectedLen)

			if tt.expectedLen > 0 {
				f := findings[0]
				assert.Equal(t, tt.expectedTool, f.Tool)
				assert.Equal(t, tt.expectedVersion, f.Version)
				assert.Equal(t, tt.expectedStatus, f.Status())
				assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult)

				if tt.expectedGuidance {
					assert.NotEmpty(t, f.GuidanceCompact)
					assert.NotEmpty(t, f.GuidanceFull)
				} else {
					assert.Empty(t, f.GuidanceCompact)
					assert.Empty(t, f.GuidanceFull)
				}
			}
		})
	}
}

func TestAudit_RPM(t *testing.T) {
	tests := []struct {
		name             string
		host             platform.Host
		runnerSetup      func(*exec.FakeRunner)
		expectedLen      int
		expectedTool     string
		expectedVersion  string
		expectedStatus   kinds.Status
		expectedFixed    string
		expectedNote     string
		expectedGuidance bool
	}{
		{
			name: "fedora behind",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyRedHat,
				Distro: platform.Distro{
					ID:      "fedora",
					Version: "40",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddError("apk info -e ca-certificates", 1, "apk: not found")
				r.AddError("pacman -Q ca-certificates-mozilla", 1, "pacman: not found")
				r.AddSuccess("rpm -q ca-certificates", "")
				r.AddSuccess("rpm -q --qf=%{VERSION} ca-certificates", "2025.2.92_v9.0.319")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (rpm)",
			expectedVersion:  "2025.2.92_v9.0.319",
			expectedStatus:   kinds.StatusLikelyAffected,
			expectedFixed:    "2026.2.92_v9.0.319",
			expectedGuidance: true,
		},
		{
			name: "fedora protected exact match",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyRedHat,
				Distro: platform.Distro{
					ID:      "fedora",
					Version: "40",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddError("apk info -e ca-certificates", 1, "apk: not found")
				r.AddError("pacman -Q ca-certificates-mozilla", 1, "pacman: not found")
				r.AddSuccess("rpm -q ca-certificates", "")
				r.AddSuccess("rpm -q --qf=%{VERSION} ca-certificates", "2026.2.92_v9.0.319")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (rpm)",
			expectedVersion:  "2026.2.92_v9.0.319",
			expectedStatus:   kinds.StatusLikelyOK,
			expectedFixed:    "2026.2.92_v9.0.319",
			expectedGuidance: false,
		},
		{
			name: "fedora protected newer build",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyRedHat,
				Distro: platform.Distro{
					ID:      "fedora",
					Version: "40",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddError("apk info -e ca-certificates", 1, "apk: not found")
				r.AddError("pacman -Q ca-certificates-mozilla", 1, "pacman: not found")
				r.AddSuccess("rpm -q ca-certificates", "")
				r.AddSuccess("rpm -q --qf=%{VERSION} ca-certificates", "2026.2.92_v9.0.320")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (rpm)",
			expectedVersion:  "2026.2.92_v9.0.320",
			expectedStatus:   kinds.StatusLikelyOK,
			expectedFixed:    "2026.2.92_v9.0.319",
			expectedGuidance: false,
		},
		{
			name: "fedora same base newer build",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyRedHat,
				Distro: platform.Distro{
					ID:      "fedora",
					Version: "40",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddError("apk info -e ca-certificates", 1, "apk: not found")
				r.AddError("pacman -Q ca-certificates-mozilla", 1, "pacman: not found")
				r.AddSuccess("rpm -q ca-certificates", "")
				r.AddSuccess("rpm -q --qf=%{VERSION} ca-certificates", "2026.2.92_v9.0.400")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (rpm)",
			expectedVersion:  "2026.2.92_v9.0.400",
			expectedStatus:   kinds.StatusLikelyOK,
			expectedFixed:    "2026.2.92_v9.0.319",
			expectedGuidance: false,
		},
		{
			name: "rhel no fixed version",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyRedHat,
				Distro: platform.Distro{
					ID:      "rhel",
					Version: "9",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddError("apk info -e ca-certificates", 1, "apk: not found")
				r.AddError("pacman -Q ca-certificates-mozilla", 1, "pacman: not found")
				r.AddSuccess("rpm -q ca-certificates", "")
				r.AddSuccess("rpm -q --qf=%{VERSION} ca-certificates", "2023.2.12")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (rpm)",
			expectedVersion:  "2023.2.12",
			expectedStatus:   kinds.StatusUnknown,
			expectedNote:     "the page lists no fixed package for this distribution",
			expectedGuidance: false,
		},
		{
			name: "centos no fixed version",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyRedHat,
				Distro: platform.Distro{
					ID:      "centos",
					Version: "9",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddError("apk info -e ca-certificates", 1, "apk: not found")
				r.AddError("pacman -Q ca-certificates-mozilla", 1, "pacman: not found")
				r.AddSuccess("rpm -q ca-certificates", "")
				r.AddSuccess("rpm -q --qf=%{VERSION} ca-certificates", "2023.2.12")
			},
			expectedLen:      1,
			expectedTool:     "ca-certificates (rpm)",
			expectedVersion:  "2023.2.12",
			expectedStatus:   kinds.StatusUnknown,
			expectedNote:     "the page lists no fixed package for this distribution",
			expectedGuidance: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := New()
			env := testutil.NewTestEnvWithHost(tt.host)
			tt.runnerSetup(env.Run.(*exec.FakeRunner))

			findings, err := k.Audit(context.Background(), env)
			require.NoError(t, err)
			assert.Len(t, findings, tt.expectedLen)

			if tt.expectedLen > 0 {
				f := findings[0]
				assert.Equal(t, tt.expectedTool, f.Tool)
				assert.Equal(t, tt.expectedVersion, f.Version)
				assert.Equal(t, tt.expectedStatus, f.Status())
				assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult)

				if tt.expectedFixed != "" {
					assert.Equal(t, tt.expectedFixed, f.FixedVersion)
				}

				if tt.expectedNote != "" {
					assert.Equal(t, tt.expectedNote, f.VersionNote)
				}

				if tt.expectedGuidance {
					assert.NotEmpty(t, f.GuidanceCompact)
					assert.NotEmpty(t, f.GuidanceFull)
				} else {
					assert.Empty(t, f.GuidanceCompact)
					assert.Empty(t, f.GuidanceFull)
				}
			}
		})
	}
}

func TestAudit_NotInstalled(t *testing.T) {
	tests := []struct {
		name        string
		host        platform.Host
		runnerSetup func(*exec.FakeRunner)
		expectedLen int
	}{
		{
			name: "dpkg not available",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyDebian,
				Distro: platform.Distro{
					ID:      "ubuntu",
					Version: "22.04",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: package 'ca-certificates' not installed")
				r.AddError("apk info -e ca-certificates", 1, "apk: not found")
				r.AddError("pacman -Q ca-certificates-mozilla", 1, "pacman: not found")
				r.AddError("rpm -q ca-certificates", 1, "rpm: not found")
			},
			expectedLen: 0,
		},
		{
			name: "apk not available",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyAlpine,
				Distro: platform.Distro{
					ID: "alpine",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddError("apk info -e ca-certificates", 1, "apk: not found")
				r.AddError("pacman -Q ca-certificates-mozilla", 1, "pacman: not found")
				r.AddError("rpm -q ca-certificates", 1, "rpm: not found")
			},
			expectedLen: 0,
		},
		{
			name: "pacman not available",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyArch,
				Distro: platform.Distro{
					ID: "arch",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddError("apk info -e ca-certificates", 1, "apk: not found")
				r.AddError("pacman -Q ca-certificates-mozilla", 1, "pacman: not found")
				r.AddError("rpm -q ca-certificates", 1, "rpm: not found")
			},
			expectedLen: 0,
		},
		{
			name: "rpm not available",
			host: platform.Host{
				OS:     "linux",
				Family: platform.FamilyRedHat,
				Distro: platform.Distro{
					ID:      "fedora",
					Version: "40",
				},
			},
			runnerSetup: func(r *exec.FakeRunner) {
				r.AddError("dpkg-query -W ca-certificates", 1, "dpkg-query: not found")
				r.AddError("apk info -e ca-certificates", 1, "apk: not found")
				r.AddError("pacman -Q ca-certificates-mozilla", 1, "pacman: not found")
				r.AddError("rpm -q ca-certificates", 1, "rpm: not found")
			},
			expectedLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := New()
			env := testutil.NewTestEnvWithHost(tt.host)
			tt.runnerSetup(env.Run.(*exec.FakeRunner))

			findings, err := k.Audit(context.Background(), env)
			require.NoError(t, err)
			assert.Len(t, findings, tt.expectedLen)
		})
	}
}

func TestAudit_Offline(t *testing.T) {
	// Verify that Offline mode still works (no network needed for package queries)
	k := New()
	env := testutil.NewTestEnvWithHost(platform.Host{
		OS:     "linux",
		Family: platform.FamilyDebian,
		Distro: platform.Distro{
			ID:      "ubuntu",
			Version: "22.04",
		},
	})
	env.Offline = true

	r := env.Run.(*exec.FakeRunner)
	r.AddSuccess("dpkg-query -W ca-certificates", "")
	r.AddSuccess("dpkg-query -W -f=${Version} ca-certificates", "20230101")
	r.AddError("dpkg --compare-versions 20230101 ge 20260816ubuntu0.22.04.1", 1, "")

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, kinds.ProbeSkipped, findings[0].ProbeResult)
}

func TestAudit_Hermetic(t *testing.T) {
	// Verify tests are hermetic: they don't depend on host environment
	// Run with HOME and PATH set to garbage values
	k := New()
	env := testutil.NewTestEnvWithHost(platform.Host{
		OS:     "linux",
		Family: platform.FamilyDebian,
		Distro: platform.Distro{
			ID:      "ubuntu",
			Version: "22.04",
		},
	})
	env.Environ["HOME"] = "/nonexistent/home"
	env.Environ["PATH"] = "/nonexistent/path"

	r := env.Run.(*exec.FakeRunner)
	r.AddSuccess("dpkg-query -W ca-certificates", "")
	r.AddSuccess("dpkg-query -W -f=${Version} ca-certificates", "20260816ubuntu0.22.04.1")
	r.AddSuccess("dpkg --compare-versions 20260816ubuntu0.22.04.1 ge 20260816ubuntu0.22.04.1", "")

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	assert.Len(t, findings, 1)
}

func TestDPKGCompareVersionsGo(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected int // -1: a < b, 0: a == b, 1: a > b
	}{
		{"simple numeric", "20230101", "20260816", -1},
		{"equal versions", "20260816", "20260816", 0},
		{"tilde ordering", "20250419~deb12u1", "20250419~deb12u2", -1},
		{"tilde before empty", "1~rc1", "1", -1},
		{"plus ordering", "20250419+deb13u1", "20250419+deb13u1", 0},
		{"epoch", "1:20250419", "20260816", 1},
		{"epoch higher", "2:1.0", "1:2.0", 1},
		{"revision ordering", "1.0-1", "1.0-2", -1},
		{"same date different revision", "20250419-1", "20250419-2", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareDebianVersions(tt.a, tt.b)
			assert.Equal(t, tt.expected, result, "compareDebianVersions(%s, %s)", tt.a, tt.b)

			// Test both directions
			if tt.expected == 0 {
				assert.Equal(t, 0, compareDebianVersions(tt.b, tt.a))
			} else {
				assert.Equal(t, -tt.expected, compareDebianVersions(tt.b, tt.a))
			}
		})
	}
}

func TestDPKGCompareVersionsGo_Operators(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		op       string
		b        string
		expected bool
	}{
		{"ge equal", "20260816", "ge", "20260816", true},
		{"ge greater", "20260817", "ge", "20260816", true},
		{"ge less", "20260815", "ge", "20260816", false},
		{"gt equal", "20260816", "gt", "20260816", false},
		{"gt greater", "20260817", "gt", "20260816", true},
		{"le equal", "20260816", "le", "20260816", true},
		{"le less", "20260815", "le", "20260816", true},
		{"lt equal", "20260816", "lt", "20260816", false},
		{"lt less", "20260815", "lt", "20260816", true},
		{"eq equal", "20260816", "eq", "20260816", true},
		{"eq not equal", "20260817", "eq", "20260816", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dpkgCompareVersionsGo(tt.a, tt.op, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGuidanceText(t *testing.T) {
	// Test that guidance text matches the script exactly
	k := New()
	env := testutil.NewTestEnvWithHost(platform.Host{
		OS:     "linux",
		Family: platform.FamilyDebian,
		Distro: platform.Distro{
			ID:      "ubuntu",
			Version: "22.04",
		},
	})

	r := env.Run.(*exec.FakeRunner)
	r.AddSuccess("dpkg-query -W ca-certificates", "")
	r.AddSuccess("dpkg-query -W -f=${Version} ca-certificates", "20230101")
	r.AddError("dpkg --compare-versions 20230101 ge 20260816ubuntu0.22.04.1", 1, "")

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	// Check guidance is exact from script
	assert.Equal(t, "sudo apt-get update && sudo apt-get install --only-upgrade ca-certificates", f.GuidanceCompact)
	require.Len(t, f.GuidanceFull, 2)
	assert.Equal(t, "sudo apt-get update && sudo apt-get install --only-upgrade ca-certificates", f.GuidanceFull[0])
	assert.Equal(t, "If your distribution has not shipped the fix yet, use the workaround in System trust store (below).", f.GuidanceFull[1])
}

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

package electron

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

func TestKind_ID(t *testing.T) {
	k := New()
	assert.Equal(t, "electron", k.ID())
}

func TestKind_Describe(t *testing.T) {
	k := New()
	assert.Contains(t, k.Describe(), "Electron")
}

func TestKind_Applicable(t *testing.T) {
	tests := []struct {
		name     string
		host     platform.Host
		expected bool
		reason   string
	}{
		{
			name:     "darwin applies",
			host:     testutil.NewDarwinHost(),
			expected: true,
		},
		{
			name:     "linux does not apply",
			host:     testutil.NewLinuxHost(),
			expected: false,
			reason:   "macOS apps only",
		},
		{
			name: "alpine does not apply",
			host: platform.Host{
				OS:      "linux",
				Family:  platform.FamilyAlpine,
				HasTTY:  true,
				HasSudo: true,
			},
			expected: false,
			reason:   "macOS apps only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := New()
			result := k.Applicable(tt.host)
			assert.Equal(t, tt.expected, result.Applies)
			if !tt.expected {
				assert.Contains(t, result.Reason, tt.reason)
			}
		})
	}
}

func TestCheckElectronVersion(t *testing.T) {
	tests := []struct {
		name           string
		version        string
		expectedStatus versionStatus
		expectedFixed  string
		expectedNotes  string
	}{
		{
			name:           "empty version is unknown",
			version:        "",
			expectedStatus: statusUnknown,
			expectedNotes:  "version not found",
		},
		{
			name:           "version 42.11.15 is behind (just below fixed)",
			version:        "42.11.15",
			expectedStatus: statusBehind,
			expectedFixed:  "42.11.16",
		},
		{
			name:           "version 42.11.16 is OK (at fixed)",
			version:        "42.11.16",
			expectedStatus: statusOK,
		},
		{
			name:           "version 42.12.0 is OK (above fixed)",
			version:        "42.12.0",
			expectedStatus: statusOK,
		},
		{
			name:           "version 43.8.0 is behind (just below fixed)",
			version:        "43.8.0",
			expectedStatus: statusBehind,
			expectedFixed:  "43.8.1",
		},
		{
			name:           "version 43.8.1 is OK (at fixed)",
			version:        "43.8.1",
			expectedStatus: statusOK,
		},
		{
			name:           "version 44.9.0 is behind (just below fixed)",
			version:        "44.9.0",
			expectedStatus: statusBehind,
			expectedFixed:  "44.9.1",
		},
		{
			name:           "version 44.9.1 is OK (at fixed)",
			version:        "44.9.1",
			expectedStatus: statusOK,
		},
		{
			name:           "version 45.0.0 is OK (newer generation)",
			version:        "45.0.0",
			expectedStatus: statusOK,
			expectedNotes:  "newer than the fixed lines",
		},
		{
			name:           "version 46.0.0 is OK (even newer)",
			version:        "46.0.0",
			expectedStatus: statusOK,
		},
		{
			name:           "version 41.0.0 is nofix (no published fix)",
			version:        "41.0.0",
			expectedStatus: statusNoFix,
			expectedFixed:  "42.11.16, 43.8.1 or 44.9.1",
		},
		{
			name:           "version 40.0.0 is nofix (no published fix)",
			version:        "40.0.0",
			expectedStatus: statusNoFix,
		},
		{
			name:           "version 42.0.0 is behind (well below fixed)",
			version:        "42.0.0",
			expectedStatus: statusBehind,
			expectedFixed:  "42.11.16",
		},
		{
			name:           "version 42.10.0 is behind (below fixed)",
			version:        "42.10.0",
			expectedStatus: statusBehind,
			expectedFixed:  "42.11.16",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkElectronVersion(tt.version)
			assert.Equal(t, tt.expectedStatus, result.status)
			if tt.expectedFixed != "" {
				assert.Contains(t, result.fixedVersion, tt.expectedFixed)
			}
			if tt.expectedNotes != "" {
				assert.Contains(t, result.notes, tt.expectedNotes)
			}
		})
	}
}

func TestExtractAppPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid app path",
			input:    "/Applications/MyApp.app/Contents/Frameworks/Electron Framework.framework/Resources/Info.plist",
			expected: "/Applications/MyApp.app",
		},
		{
			name:     "valid app path with tilde expansion",
			input:    "/Users/test/Applications/MyApp.app/Contents/Frameworks/Electron Framework.framework/Resources/Info.plist",
			expected: "/Users/test/Applications/MyApp.app",
		},
		{
			name:     "invalid path without .app",
			input:    "/Some/Other/Path/Info.plist",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractAppPath(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKind_Audit_NoElectronApps(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "electron-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create empty Applications directories (no Electron apps)
	appDir := filepath.Join(tmpDir, "Applications")
	require.NoError(t, os.MkdirAll(appDir, 0755))

	env := testutil.NewTestEnv()
	env.Host = platform.Host{
		OS:   "darwin",
		Home: tmpDir,
	}
	// Set HOME in hermetic environment
	env.Environ = map[string]string{
		"HOME": tmpDir,
	}

	k := New()
	findings, err := k.Audit(context.Background(), env)
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestKind_Audit_WithElectronApps(t *testing.T) {
	// Create temp directory structure for test
	tmpDir, err := os.MkdirTemp("", "electron-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create fake Electron app structure
	appPath := filepath.Join(tmpDir, "Applications", "TestApp.app")
	frameworkPath := filepath.Join(appPath, "Contents", "Frameworks", "Electron Framework.framework", "Resources")
	require.NoError(t, os.MkdirAll(frameworkPath, 0755))

	plistPath := filepath.Join(frameworkPath, "Info.plist")

	// Create a minimal plist file (just for existence check, version read uses PlistBuddy)
	require.NoError(t, os.WriteFile(plistPath, []byte(`<?xml version="1.0"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleVersion</key>
	<string>42.11.15</string>
</dict>
</plist>`), 0644))

	env := testutil.NewTestEnv()
	env.Host = platform.Host{
		OS:   "darwin",
		Home: tmpDir,
	}
	env.Environ = map[string]string{
		"HOME": tmpDir,
	}

	// Mock PlistBuddy to return version
	fakeRunner := exec.NewFakeRunner()
	fakeRunner.AddSuccess("/usr/libexec/PlistBuddy", "42.11.15")
	env.Run = fakeRunner

	k := New()
	findings, err := k.Audit(context.Background(), env)

	assert.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "electron", f.Kind)
	assert.Equal(t, "Electron app: TestApp", f.Tool)
	assert.Equal(t, "Electron 42.11.15", f.Version)
	assert.Equal(t, kinds.StatusLikelyAffected, f.Status())
	assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult)
	assert.Contains(t, f.Evidence, "cannot probe")
	assert.Contains(t, f.GuidanceCompact, "update the app")
	assert.Equal(t, "42.11.16", f.FixedVersion)
}

func TestKind_Audit_MultipleApps(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "electron-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	appDir := filepath.Join(tmpDir, "Applications")
	require.NoError(t, os.MkdirAll(appDir, 0755))

	// Create two Electron apps
	for _, app := range []struct {
		name    string
		version string
	}{
		{"App1", "42.11.15"}, // behind
		{"App2", "43.8.1"},   // OK
	} {
		appPath := filepath.Join(appDir, app.name+".app")
		frameworkPath := filepath.Join(appPath, "Contents", "Frameworks", "Electron Framework.framework", "Resources")
		require.NoError(t, os.MkdirAll(frameworkPath, 0755))

		plistPath := filepath.Join(frameworkPath, "Info.plist")
		require.NoError(t, os.WriteFile(plistPath, []byte(`<plist><dict><key>CFBundleVersion</key><string>`+app.version+`</string></dict></plist>`), 0644))
	}

	env := testutil.NewTestEnv()
	env.Host = platform.Host{
		OS:   "darwin",
		Home: tmpDir,
	}
	env.Environ = map[string]string{
		"HOME": tmpDir,
	}

	fakeRunner := exec.NewFakeRunner()
	// Use OnCall to return different versions for different calls
	callCount := 0
	fakeRunner.OnCall = func(name string, args ...string) exec.CommandResult {
		if name == "/usr/libexec/PlistBuddy" {
			callCount++
			if callCount == 1 {
				return exec.CommandResult{Stdout: "42.11.15", ExitCode: 0}
			}
			return exec.CommandResult{Stdout: "43.8.1", ExitCode: 0}
		}
		return exec.CommandResult{}
	}
	env.Run = fakeRunner

	k := New()
	findings, err := k.Audit(context.Background(), env)

	assert.NoError(t, err)
	require.Len(t, findings, 2)

	// First app is behind (LIKELY-AFFECTED)
	assert.Equal(t, kinds.StatusLikelyAffected, findings[0].Status())
	assert.Contains(t, findings[0].GuidanceCompact, "update the app")

	// Second app is OK (LIKELY-OK)
	assert.Equal(t, kinds.StatusLikelyOK, findings[1].Status())
}

func TestKind_Audit_NofixVersion(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "electron-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	appPath := filepath.Join(tmpDir, "Applications", "OldApp.app")
	frameworkPath := filepath.Join(appPath, "Contents", "Frameworks", "Electron Framework.framework", "Resources")
	require.NoError(t, os.MkdirAll(frameworkPath, 0755))

	plistPath := filepath.Join(frameworkPath, "Info.plist")
	require.NoError(t, os.WriteFile(plistPath, []byte(`<plist><dict><key>CFBundleVersion</key><string>41.0.0</string></dict></plist>`), 0644))

	env := testutil.NewTestEnv()
	env.Host = platform.Host{
		OS:   "darwin",
		Home: tmpDir,
	}
	env.Environ = map[string]string{
		"HOME": tmpDir,
	}

	fakeRunner := exec.NewFakeRunner()
	fakeRunner.AddSuccess("/usr/libexec/PlistBuddy", "41.0.0") // No fix available
	env.Run = fakeRunner

	k := New()
	findings, err := k.Audit(context.Background(), env)

	assert.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	// nofix version should derive to LIKELY-AFFECTED per script's report()
	assert.Equal(t, kinds.StatusLikelyAffected, f.Status())
	assert.Contains(t, f.VersionNote, "fixes only published for")
	assert.Contains(t, f.GuidanceCompact, "update the app")
}

func TestKind_Audit_SymlinkDeduplication(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "electron-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	appDir := filepath.Join(tmpDir, "Applications")
	require.NoError(t, os.MkdirAll(appDir, 0755))

	// Create real app
	realAppPath := filepath.Join(appDir, "RealApp.app")
	frameworkPath := filepath.Join(realAppPath, "Contents", "Frameworks", "Electron Framework.framework", "Resources")
	require.NoError(t, os.MkdirAll(frameworkPath, 0755))
	plistPath := filepath.Join(frameworkPath, "Info.plist")
	require.NoError(t, os.WriteFile(plistPath, []byte(`<plist><dict><key>CFBundleVersion</key><string>42.11.16</string></dict></plist>`), 0644))

	// Create symlink to the same app
	linkPath := filepath.Join(appDir, "LinkedApp.app")
	require.NoError(t, os.Symlink(realAppPath, linkPath))

	env := testutil.NewTestEnv()
	env.Host = platform.Host{
		OS:   "darwin",
		Home: tmpDir,
	}
	env.Environ = map[string]string{
		"HOME": tmpDir,
	}

	fakeRunner := exec.NewFakeRunner()
	fakeRunner.AddSuccess("/usr/libexec/PlistBuddy", "42.11.16")
	env.Run = fakeRunner

	k := New()
	findings, err := k.Audit(context.Background(), env)

	assert.NoError(t, err)
	// Should only find one app (deduplicated by resolved path)
	assert.Len(t, findings, 1)
}

func TestKind_Audit_OfflineMode(t *testing.T) {
	// Offline mode doesn't affect Electron (no network probe anyway)
	tmpDir, err := os.MkdirTemp("", "electron-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	appPath := filepath.Join(tmpDir, "Applications", "TestApp.app")
	frameworkPath := filepath.Join(appPath, "Contents", "Frameworks", "Electron Framework.framework", "Resources")
	require.NoError(t, os.MkdirAll(frameworkPath, 0755))

	plistPath := filepath.Join(frameworkPath, "Info.plist")
	require.NoError(t, os.WriteFile(plistPath, []byte(`<plist><dict><key>CFBundleVersion</key><string>42.11.15</string></dict></plist>`), 0644))

	env := testutil.NewTestEnv()
	env.Host = platform.Host{
		OS:   "darwin",
		Home: tmpDir,
	}
	env.Environ = map[string]string{
		"HOME": tmpDir,
	}
	env.Offline = true

	fakeRunner := exec.NewFakeRunner()
	fakeRunner.AddSuccess("/usr/libexec/PlistBuddy", "42.11.15")
	env.Run = fakeRunner

	k := New()
	findings, err := k.Audit(context.Background(), env)

	assert.NoError(t, err)
	require.Len(t, findings, 1)
	// Probe is always skipped for Electron apps
	assert.Equal(t, kinds.ProbeSkipped, findings[0].ProbeResult)
}

func TestKind_Audit_GuidancePresent(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "electron-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	appPath := filepath.Join(tmpDir, "Applications", "TestApp.app")
	frameworkPath := filepath.Join(appPath, "Contents", "Frameworks", "Electron Framework.framework", "Resources")
	require.NoError(t, os.MkdirAll(frameworkPath, 0755))

	plistPath := filepath.Join(frameworkPath, "Info.plist")
	require.NoError(t, os.WriteFile(plistPath, []byte(`<plist><dict><key>CFBundleVersion</key><string>42.11.15</string></dict></plist>`), 0644))

	env := testutil.NewTestEnv()
	env.Host = platform.Host{
		OS:   "darwin",
		Home: tmpDir,
	}
	env.Environ = map[string]string{
		"HOME": tmpDir,
	}

	fakeRunner := exec.NewFakeRunner()
	fakeRunner.AddSuccess("/usr/libexec/PlistBuddy", "42.11.15")
	env.Run = fakeRunner

	k := New()
	findings, err := k.Audit(context.Background(), env)

	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	// Check compact guidance
	assert.NotEmpty(t, f.GuidanceCompact)
	assert.Contains(t, f.GuidanceCompact, "update the app")
	assert.Contains(t, f.GuidanceCompact, "in-app update")

	// Check full guidance
	assert.Len(t, f.GuidanceFull, 2)
	assert.Contains(t, f.GuidanceFull[0], "Update the app")
	assert.Contains(t, f.GuidanceFull[1], "vendor")
	assert.Contains(t, f.GuidanceFull[1], "cannot patch")
}

func TestKind_Audit_Hermeticity(t *testing.T) {
	// Test with garbage HOME and PATH to prove hermeticity
	tmpDir, err := os.MkdirTemp("", "electron-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	appPath := filepath.Join(tmpDir, "Applications", "TestApp.app")
	frameworkPath := filepath.Join(appPath, "Contents", "Frameworks", "Electron Framework.framework", "Resources")
	require.NoError(t, os.MkdirAll(frameworkPath, 0755))

	plistPath := filepath.Join(frameworkPath, "Info.plist")
	require.NoError(t, os.WriteFile(plistPath, []byte(`<plist><dict><key>CFBundleVersion</key><string>42.11.16</string></dict></plist>`), 0644))

	env := testutil.NewTestEnv()
	env.Host = platform.Host{
		OS:   "darwin",
		Home: tmpDir,
	}
	env.Environ = map[string]string{
		"HOME": tmpDir,
		"PATH": "/nonexistent/path",
	}

	fakeRunner := exec.NewFakeRunner()
	fakeRunner.AddSuccess("/usr/libexec/PlistBuddy", "42.11.16")
	env.Run = fakeRunner

	k := New()
	findings, err := k.Audit(context.Background(), env)

	assert.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "Electron app: TestApp", findings[0].Tool)
}

func TestKind_Audit_StatusDerivation(t *testing.T) {
	tests := []struct {
		name           string
		version        string
		expectedStatus kinds.Status
	}{
		{
			name:           "behind version derives to LIKELY-AFFECTED",
			version:        "42.11.15",
			expectedStatus: kinds.StatusLikelyAffected,
		},
		{
			name:           "fixed version derives to LIKELY-OK",
			version:        "42.11.16",
			expectedStatus: kinds.StatusLikelyOK,
		},
		{
			name:           "newer version derives to LIKELY-OK",
			version:        "45.0.0",
			expectedStatus: kinds.StatusLikelyOK,
		},
		{
			name:           "nofix version derives to LIKELY-AFFECTED",
			version:        "41.0.0",
			expectedStatus: kinds.StatusLikelyAffected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "electron-test-*")
			require.NoError(t, err)
			defer func() { _ = os.RemoveAll(tmpDir) }()

			appPath := filepath.Join(tmpDir, "Applications", "TestApp.app")
			frameworkPath := filepath.Join(appPath, "Contents", "Frameworks", "Electron Framework.framework", "Resources")
			require.NoError(t, os.MkdirAll(frameworkPath, 0755))

			plistPath := filepath.Join(frameworkPath, "Info.plist")
			require.NoError(t, os.WriteFile(plistPath, []byte(`<plist><dict><key>CFBundleVersion</key><string>`+tt.version+`</string></dict></plist>`), 0644))

			env := testutil.NewTestEnv()
			env.Host = platform.Host{
				OS:   "darwin",
				Home: tmpDir,
			}
			env.Environ = map[string]string{
				"HOME": tmpDir,
			}

			fakeRunner := exec.NewFakeRunner()
			fakeRunner.AddSuccess("/usr/libexec/PlistBuddy", tt.version)
			env.Run = fakeRunner

			k := New()
			findings, err := k.Audit(context.Background(), env)

			require.NoError(t, err)
			require.Len(t, findings, 1)
			assert.Equal(t, tt.expectedStatus, findings[0].Status())
		})
	}
}

// The script's glob lists apps ignoring case (balenaEtcher before Bitwarden), not by byte value.
func TestKind_Audit_AppsAreListedIgnoringCase(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	for _, name := range []string{"Zeta", "alpha", "Bravo", "charlie"} {
		fw := filepath.Join(root, "Applications", name+".app", "Contents", "Frameworks", "Electron Framework.framework", "Resources")
		require.NoError(t, os.MkdirAll(fw, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(fw, "Info.plist"), []byte("x"), 0o644))
	}
	env := testutil.NewTestEnv()
	env.Host = platform.Host{OS: "darwin", Home: root}
	env.Environ = map[string]string{"HOME": root}
	fake := exec.NewFakeRunner()
	fake.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{Stdout: "43.8.1"}
	}
	env.Run = fake

	findings, err := New().Audit(context.Background(), env)
	require.NoError(t, err)

	var names []string
	for _, f := range findings {
		if strings.HasPrefix(f.Path, root) {
			names = append(names, f.Tool)
		}
	}
	assert.Equal(t, []string{"Electron app: alpha", "Electron app: Bravo", "Electron app: charlie", "Electron app: Zeta"}, names)
}

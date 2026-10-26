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

package macpip

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/privilege"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/prompt"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

func TestMacPipKind_ID(t *testing.T) {
	k := New()
	assert.Equal(t, "macpip", k.ID())
}

func TestMacPipKind_Describe(t *testing.T) {
	k := New()
	assert.Equal(t, "macOS built-in pip (sitecustomize.py sets PIP_CERT)", k.Describe())
}

func TestMacPipKind_Applicable(t *testing.T) {
	tests := []struct {
		name       string
		host       platform.Host
		wantApply  bool
		wantReason string
	}{
		{"macOS", testutil.NewDarwinHost(), true, ""},
		{"Linux", testutil.NewLinuxHost(), false, "macOS only (Apple Python sitecustomize does not exist on Linux)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := New().Applicable(tt.host)
			assert.Equal(t, tt.wantApply, got.Applies)
			assert.Equal(t, tt.wantReason, got.Reason)
		})
	}
}

func TestMacPipKind_Audit(t *testing.T) {
	env := testutil.NewTestEnvT(t)
	findings, err := New().Audit(context.Background(), env)
	require.NoError(t, err)
	assert.Empty(t, findings, "macpip has no audit")
}

// python builds a Python finding the way the Python Kind does: facts only, the status derived.
func python(probe kinds.ProbeResult, vc kinds.VersionCheck, pipGuidance, hasFix bool) kinds.Finding {
	f := kinds.NewFinding("python", "Python")
	f.Path = "/usr/bin/python3"
	f.SetProbe(probe, "")
	f.VersionCheck = vc
	f.NeedsPipGuidance, f.HasFix = pipGuidance, hasFix
	return f
}

func TestMacPipKind_Plan(t *testing.T) {
	tests := []struct {
		name     string
		findings []kinds.Finding
		wantLen  int
	}{
		{"no findings", nil, 0},
		{"does not ask for pip guidance", []kinds.Finding{python(kinds.ProbeTrusted, kinds.VersionNA, false, true)}, 0},
		{"no automated fix", []kinds.Finding{python(kinds.ProbeTrusted, kinds.VersionNA, true, false)}, 0},
		{"pip trusts the chain: AFFECTED", []kinds.Finding{python(kinds.ProbeTrusted, kinds.VersionNA, true, true)}, 1},
		{"a --no-network run, pip behind: LIKELY-AFFECTED", []kinds.Finding{python(kinds.ProbeSkipped, kinds.VersionBehind, true, true)}, 1},
		// This machine's real case: Apple's Python rejects the chain (status OK) but its
		// pip is old, which sets the flags. The script plans the fix only inside the bad
		// branch of report(), so it plans nothing here. Planning it anyway offered a
		// sitecustomize.py edit for a Python that was not affected.
		{"protected but old pip: OK, not planned", []kinds.Finding{python(kinds.ProbeRejected, kinds.VersionBehind, true, true)}, 0},
		{"unknown: not planned", []kinds.Finding{python(kinds.ProbeInconclusive, kinds.VersionUnknown, true, true)}, 0},
		{"two Python findings still make one fix", []kinds.Finding{
			python(kinds.ProbeTrusted, kinds.VersionNA, true, true), python(kinds.ProbeTrusted, kinds.VersionNA, true, true)}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testutil.NewTestEnvT(t)
			fixes, err := New().(kinds.Fixer).Plan(context.Background(), env, tt.findings)
			require.NoError(t, err)
			assert.Len(t, fixes, tt.wantLen)
		})
	}
}

// newTestSession creates a fixrun.Session with fakes for testing.
func newTestSession(t *testing.T) (*fixrun.Session, *bytes.Buffer, *privilege.FakeEscalator, *prompt.FakePrompter, *exec.FakeRunner) {
	t.Helper()
	var out bytes.Buffer
	priv := privilege.NewFakeEscalator()
	priv.HasSudoVal = true
	pr := prompt.NewFakePrompter()
	runner := exec.NewFakeRunner()
	return &fixrun.Session{
		Run: runner, Prompt: pr, Priv: priv,
		Out: &out, Stamp: "20261023120000", TempDir: t.TempDir(),
	}, &out, priv, pr, runner
}

func TestFix_Run_PythonNotFound(t *testing.T) {
	s, out, _, _, runner := newTestSession(t)
	runner.AddError("/usr/bin/python3", 1, "not found")

	f := &fix{}
	result := f.Run(context.Background(), s)

	assert.Equal(t, fixrun.Skipped, result)
	assert.Contains(t, out.String(), "not found")
}

func TestFix_Run_StdlibNotFound(t *testing.T) {
	s, out, _, _, runner := newTestSession(t)
	runner.AddSuccess("/usr/bin/python3", "")

	f := &fix{}
	result := f.Run(context.Background(), s)

	assert.Equal(t, fixrun.Skipped, result)
	assert.Contains(t, out.String(), "could not locate the stdlib directory")
}

func TestFix_Run_AlreadyConfigured(t *testing.T) {
	s, out, _, _, runner := newTestSession(t)

	// Create temp stdlib directory
	tmpDir := t.TempDir()
	stdlib := filepath.Join(tmpDir, "lib", "python3.11")
	require.NoError(t, os.MkdirAll(stdlib, 0755))

	siteFile := filepath.Join(stdlib, "sitecustomize.py")
	line := `import os; os.environ.setdefault("PIP_CERT", "/etc/ssl/cert.pem")`
	require.NoError(t, os.WriteFile(siteFile, []byte(line+"\n"), 0644))

	runner.AddSuccess("/usr/bin/python3", stdlib)

	f := &fix{}
	result := f.Run(context.Background(), s)

	assert.Equal(t, fixrun.Skipped, result)
	assert.Contains(t, out.String(), "already configured")
}

func TestFix_Run_DryRun(t *testing.T) {
	s, out, _, _, runner := newTestSession(t)
	s.DryRun = true

	// Create temp stdlib directory
	tmpDir := t.TempDir()
	stdlib := filepath.Join(tmpDir, "lib", "python3.11")
	require.NoError(t, os.MkdirAll(stdlib, 0755))

	runner.AddSuccess("/usr/bin/python3", stdlib)

	f := &fix{}
	result := f.Run(context.Background(), s)

	assert.Equal(t, fixrun.Skipped, result)
	assert.Contains(t, out.String(), "would append one line")
	assert.Contains(t, out.String(), "echo 'import os; os.environ.setdefault")
	assert.NotContains(t, out.String(), "applied")
}

func TestFix_Run_Declined(t *testing.T) {
	s, out, _, pr, runner := newTestSession(t)
	pr.AddConfirm(false)

	// Create temp stdlib directory
	tmpDir := t.TempDir()
	stdlib := filepath.Join(tmpDir, "lib", "python3.11")
	require.NoError(t, os.MkdirAll(stdlib, 0755))

	runner.AddSuccess("/usr/bin/python3", stdlib)

	f := &fix{}
	result := f.Run(context.Background(), s)

	assert.Equal(t, fixrun.Skipped, result)
	assert.Contains(t, out.String(), "skipped")
}

func TestFix_Run_Success(t *testing.T) {
	s, out, _, pr, runner := newTestSession(t)
	pr.AddConfirm(true)

	// Create temp stdlib directory
	tmpDir := t.TempDir()
	stdlib := filepath.Join(tmpDir, "lib", "python3.11")
	require.NoError(t, os.MkdirAll(stdlib, 0755))

	runner.AddSuccess("/usr/bin/python3", stdlib)
	runner.AddSuccess("/usr/bin/python3 -I -c import sys", "")

	f := &fix{}
	result := f.Run(context.Background(), s)

	assert.Equal(t, fixrun.Changed, result)
	assert.Contains(t, out.String(), "applied")
	assert.Contains(t, out.String(), "still starts")

	// Verify note was recorded
	notes := s.Notes()
	assert.Len(t, notes, 1)
	assert.Contains(t, notes[0], "created (delete the line to undo)")
}

func TestFix_Run_WithBackup(t *testing.T) {
	s, _, priv, pr, runner := newTestSession(t)
	pr.AddConfirm(true)

	// Create temp stdlib directory
	tmpDir := t.TempDir()
	stdlib := filepath.Join(tmpDir, "lib", "python3.11")
	require.NoError(t, os.MkdirAll(stdlib, 0755))

	siteFile := filepath.Join(stdlib, "sitecustomize.py")
	existingContent := "# existing content\n"
	require.NoError(t, os.WriteFile(siteFile, []byte(existingContent), 0644))

	runner.AddSuccess("/usr/bin/python3", stdlib)
	runner.AddSuccess("/usr/bin/python3 -I -c import sys", "")

	f := &fix{}
	result := f.Run(context.Background(), s)

	assert.Equal(t, fixrun.Changed, result)

	// Verify backup command was issued
	backupPath := siteFile + ".pre-emudhra-20261023120000"
	assert.Contains(t, priv.Commands[0], "cp -p "+siteFile+" "+backupPath)

	// Verify note was recorded (backup adds one note automatically)
	notes := s.Notes()
	assert.Len(t, notes, 1)
	assert.Contains(t, notes[0], "pre-emudhra", "note should mention the backup file")
}

func TestFix_Run_VerifyFails_Rollback(t *testing.T) {
	s, out, _, pr, runner := newTestSession(t)
	pr.AddConfirm(true)

	// Create temp stdlib directory
	tmpDir := t.TempDir()
	stdlib := filepath.Join(tmpDir, "lib", "python3.11")
	require.NoError(t, os.MkdirAll(stdlib, 0755))

	siteFile := filepath.Join(stdlib, "sitecustomize.py")
	existingContent := "# existing content\n"
	require.NoError(t, os.WriteFile(siteFile, []byte(existingContent), 0644))

	runner.AddSuccess("/usr/bin/python3", stdlib)
	runner.AddError("/usr/bin/python3 -I -c import sys", 1, "python broken")

	f := &fix{}
	result := f.Run(context.Background(), s)

	assert.Equal(t, fixrun.Failed, result)
	assert.Contains(t, out.String(), "no longer starts - rolling back")

	// Verify file was restored
	contents, err := os.ReadFile(siteFile)
	require.NoError(t, err)
	assert.Equal(t, existingContent, string(contents))
}

func TestFix_Run_XcodeWarning(t *testing.T) {
	s, out, _, _, runner := newTestSession(t)
	s.DryRun = true

	// Create temp Xcode stdlib directory
	tmpDir := t.TempDir()
	stdlib := filepath.Join(tmpDir, "Xcode.app", "Contents", "Developer", "Library", "Framework", "Python3.framework", "Versions", "3.11", "lib", "python3.11")
	require.NoError(t, os.MkdirAll(stdlib, 0755))

	runner.AddSuccess("/usr/bin/python3", stdlib)

	f := &fix{}
	_ = f.Run(context.Background(), s)

	assert.Contains(t, out.String(), "inside Xcode")
}

func TestFix_Run_CommandLineToolsWarning(t *testing.T) {
	s, out, _, _, runner := newTestSession(t)
	s.DryRun = true

	// Create temp CommandLineTools stdlib directory
	tmpDir := t.TempDir()
	stdlib := filepath.Join(tmpDir, "Library", "Developer", "CommandLineTools", "Library", "Framework", "Python3.framework", "Versions", "3.11", "lib", "python3.11")
	require.NoError(t, os.MkdirAll(stdlib, 0755))

	runner.AddSuccess("/usr/bin/python3", stdlib)

	f := &fix{}
	_ = f.Run(context.Background(), s)

	assert.Contains(t, out.String(), "inside the Command Line Tools")
}

func TestUndo_NoBackup(t *testing.T) {
	s, out, _, _, _ := newTestSession(t)
	env := testutil.NewTestEnvT(t)

	k := New().(*Kind)
	err := k.Undo(context.Background(), env, s)
	assert.NoError(t, err)
	assert.NotContains(t, out.String(), "restore")
}

func TestUndo_WithBackup(t *testing.T) {
	env := testutil.NewTestEnvT(t)

	// Create temp stdlib directory
	tmpDir := t.TempDir()
	stdlib := filepath.Join(tmpDir, "lib", "python3.11")
	require.NoError(t, os.MkdirAll(stdlib, 0755))

	siteFile := filepath.Join(stdlib, "sitecustomize.py")
	backupContent := "# old content\n"
	backupFile := siteFile + ".pre-emudhra-20261023115900"
	require.NoError(t, os.WriteFile(backupFile, []byte(backupContent), 0644))

	// Create a newer backup too (should pick the newest)
	backupFile2 := siteFile + ".pre-emudhra-20261023120000"
	backupContent2 := "# newer content\n"
	require.NoError(t, os.WriteFile(backupFile2, []byte(backupContent2), 0644))

	env.Host.OS = "darwin"
	env.Run.(*exec.FakeRunner).AddSuccess("/usr/bin/python3", stdlib)

	s, out, _, _, _ := newTestSession(t)
	s.DryRun = true

	k := New().(*Kind)
	err := k.Undo(context.Background(), env, s)
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "restore from")
	assert.Contains(t, out.String(), "would restore")
}

func TestUndo_ConfirmDeclined(t *testing.T) {
	env := testutil.NewTestEnvT(t)

	// Create temp stdlib directory
	tmpDir := t.TempDir()
	stdlib := filepath.Join(tmpDir, "lib", "python3.11")
	require.NoError(t, os.MkdirAll(stdlib, 0755))

	siteFile := filepath.Join(stdlib, "sitecustomize.py")
	backupFile := siteFile + ".pre-emudhra-20261023120000"
	require.NoError(t, os.WriteFile(backupFile, []byte("old content\n"), 0644))

	env.Host.OS = "darwin"
	env.Run.(*exec.FakeRunner).AddSuccess("/usr/bin/python3", stdlib)

	s, out, _, pr, _ := newTestSession(t)
	pr.AddConfirm(false)

	k := New().(*Kind)
	err := k.Undo(context.Background(), env, s)
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "skipped")
}

func TestUndo_Success(t *testing.T) {
	env := testutil.NewTestEnvT(t)

	// Create temp stdlib directory
	tmpDir := t.TempDir()
	stdlib := filepath.Join(tmpDir, "lib", "python3.11")
	require.NoError(t, os.MkdirAll(stdlib, 0755))

	siteFile := filepath.Join(stdlib, "sitecustomize.py")
	backupContent := "# old content\n"
	backupFile := siteFile + ".pre-emudhra-20261023120000"
	require.NoError(t, os.WriteFile(backupFile, []byte(backupContent), 0644))

	env.Host.OS = "darwin"
	env.Run.(*exec.FakeRunner).AddSuccess("/usr/bin/python3", stdlib)

	s, out, priv, pr, _ := newTestSession(t)
	pr.AddConfirm(true)

	k := New().(*Kind)
	err := k.Undo(context.Background(), env, s)
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "restored")

	// Verify restore command was issued
	assert.Contains(t, priv.Commands[0], "cp -p "+backupFile+" "+siteFile)
}

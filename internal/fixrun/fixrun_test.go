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

package fixrun

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/privilege"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/prompt"
)

func newSession(t *testing.T) (*Session, *bytes.Buffer, *privilege.FakeEscalator, *prompt.FakePrompter) {
	t.Helper()
	var out bytes.Buffer
	priv := privilege.NewFakeEscalator()
	priv.HasSudoVal = true
	pr := prompt.NewFakePrompter()
	return &Session{
		Run: exec.NewFakeRunner(), Prompt: pr, Priv: priv,
		Out: &out, Stamp: "20261023120000", TempDir: t.TempDir(),
	}, &out, priv, pr
}

type fakeFix struct {
	kind, target string
	outcome      Outcome
	ran          *[]string
}

func (f fakeFix) Kind() string   { return f.kind }
func (f fakeFix) Target() string { return f.target }
func (f fakeFix) Run(context.Context, *Session) Outcome {
	*f.ran = append(*f.ran, f.kind+":"+f.target)
	return f.outcome
}

func TestExecuteCountsOutcomesAndContinuesAfterAFailure(t *testing.T) {
	s, out, _, _ := newSession(t)
	var ran []string
	Execute(context.Background(), s, []Fix{
		fakeFix{"a", "1", Changed, &ran},
		fakeFix{"b", "2", Failed, &ran},
		fakeFix{"c", "3", Skipped, &ran},
		fakeFix{"d", "4", Changed, &ran},
	}, nil)
	assert.Equal(t, []string{"a:1", "b:2", "c:3", "d:4"}, ran, "a failed fix must not stop the others")
	ch, fa, sk := s.Counts()
	assert.Equal(t, [3]int{2, 1, 1}, [3]int{ch, fa, sk})

	s.Summary("emudhra-audit-fix")
	assert.Contains(t, out.String(), "Changed: 2   Failed or refused: 1   Skipped: 1")
}

func TestExecuteHonoursOnly(t *testing.T) {
	s, _, _, _ := newSession(t)
	var ran []string
	Execute(context.Background(), s, []Fix{
		fakeFix{"java", "1", Changed, &ran}, fakeFix{"uv", "2", Changed, &ran}, fakeFix{"node", "3", Changed, &ran},
	}, map[string]bool{"uv": true})
	assert.Equal(t, []string{"uv:2"}, ran)
}

func TestExecuteStopsWhenInterrupted(t *testing.T) {
	s, out, _, _ := newSession(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var ran []string
	Execute(ctx, s, []Fix{fakeFix{"a", "1", Changed, &ran}}, nil)
	assert.Empty(t, ran)
	assert.Contains(t, out.String(), "interrupted")
}

func TestOutputHelpers(t *testing.T) {
	s, out, _, _ := newSession(t)
	s.Say("hello %s", "world")
	s.Warn("careful")
	s.OK("done")
	s.Bad("broken")
	s.Cmd("ls -l")
	assert.Equal(t, "  hello world\n  ! careful\n  ✓ done\n  ✗ broken\n  \x20 $ ls -l\n", out.String(), "no colour when Color is false")

	s2, out2, _, _ := newSession(t)
	s2.Color = true
	s2.OK("done")
	assert.Equal(t, "  \033[32m✓ done\033[0m\n", out2.String())
}

func TestConfirmHonoursYesAndDryRun(t *testing.T) {
	s, _, _, pr := newSession(t)
	pr.ConfirmResponses = []bool{true}
	assert.True(t, s.Confirm("go?"))

	s.DryRun = true
	assert.False(t, s.Confirm("go?"), "a dry run never confirms")
	assert.False(t, s.ConfirmAgree("really?"), "a dry run never confirms")
}

func TestNeedRoot(t *testing.T) {
	t.Run("writable by the user", func(t *testing.T) {
		s, _, _, _ := newSession(t)
		needs, err := s.NeedRoot("/home/me/file")
		assert.NoError(t, err)
		assert.False(t, needs)
	})
	t.Run("needs root and sudo exists", func(t *testing.T) {
		s, _, priv, _ := newSession(t)
		priv.NeedsMap["/etc/ssl/cert.pem"] = true
		needs, err := s.NeedRoot("/etc/ssl/cert.pem")
		assert.NoError(t, err)
		assert.True(t, needs)
	})
	t.Run("needs root and there is no sudo", func(t *testing.T) {
		s, out, priv, _ := newSession(t)
		priv.HasSudoVal = false
		priv.NeedsMap["/etc/ssl/cert.pem"] = true
		needs, err := s.NeedRoot("/etc/ssl/cert.pem")
		require.Error(t, err)
		assert.True(t, needs)
		assert.Contains(t, out.String(), "need root to write /etc/ssl/cert.pem but sudo is not available - run this program as root")
	})
	t.Run("already root", func(t *testing.T) {
		s, _, priv, _ := newSession(t)
		priv.IsRootVal = true
		priv.HasSudoVal = false
		priv.NeedsMap["/etc/ssl/cert.pem"] = true
		needs, err := s.NeedRoot("/etc/ssl/cert.pem")
		assert.NoError(t, err)
		assert.False(t, needs)
	})
}

func TestAsRootPrintsAndRuns(t *testing.T) {
	s, out, priv, _ := newSession(t)
	require.NoError(t, s.AsRoot(context.Background(), "cp", "-p", "a", "b"))
	assert.Contains(t, out.String(), "$ sudo cp -p a b")
	assert.Equal(t, []string{"cp -p a b"}, priv.Commands)

	s2, out2, priv2, _ := newSession(t)
	priv2.IsRootVal = true
	require.NoError(t, s2.AsRoot(context.Background(), "update-ca-trust"))
	assert.Contains(t, out2.String(), "$ update-ca-trust")
	assert.NotContains(t, out2.String(), "sudo")
}

func TestAsRootDryRunPrintsButDoesNotRun(t *testing.T) {
	s, out, priv, _ := newSession(t)
	s.DryRun = true
	require.NoError(t, s.AsRoot(context.Background(), "rm", "-rf", "/important"))
	assert.Contains(t, out.String(), "$ sudo rm -rf /important")
	assert.Empty(t, priv.Commands, "a dry run must not execute anything")
}

func TestBackupAndRestore(t *testing.T) {
	s, _, priv, _ := newSession(t)
	bak, err := s.Backup(context.Background(), "/etc/ssl/cert.pem")
	require.NoError(t, err)
	assert.Equal(t, "/etc/ssl/cert.pem.pre-emudhra-20261023120000", bak)
	assert.Equal(t, []string{"cp -p /etc/ssl/cert.pem /etc/ssl/cert.pem.pre-emudhra-20261023120000"}, priv.Commands)
	assert.Equal(t, []string{"/etc/ssl/cert.pem  ->  /etc/ssl/cert.pem.pre-emudhra-20261023120000"}, s.Notes())

	require.NoError(t, s.Restore(context.Background(), bak, "/etc/ssl/cert.pem"))
	assert.Equal(t, "cp -p /etc/ssl/cert.pem.pre-emudhra-20261023120000 /etc/ssl/cert.pem", priv.Commands[1])
}

func TestBackupDryRunRecordsNoNote(t *testing.T) {
	s, _, priv, _ := newSession(t)
	s.DryRun = true
	_, err := s.Backup(context.Background(), "/etc/ssl/cert.pem")
	require.NoError(t, err)
	assert.Empty(t, priv.Commands)
	assert.Empty(t, s.Notes(), "nothing was backed up, so there is nothing to undo")
}

func TestBackupFailureIsReported(t *testing.T) {
	s, _, priv, _ := newSession(t)
	priv.AsRootError = os.ErrPermission
	_, err := s.Backup(context.Background(), "/etc/ssl/cert.pem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "backup of /etc/ssl/cert.pem failed")
	assert.Empty(t, s.Notes(), "a failed backup is not an undo point")
}

func TestNewestBackup(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "cert.pem")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o644))
	assert.Equal(t, "", NewestBackup(f))

	for _, st := range []string{"20260101000000", "20261023120000", "20260601000000"} {
		require.NoError(t, os.WriteFile(f+".pre-emudhra-"+st, []byte(st), 0o644))
	}
	require.NoError(t, os.WriteFile(f+".other-20990101000000", []byte("no"), 0o644))
	assert.Equal(t, f+".pre-emudhra-20261023120000", NewestBackup(f), "newest by stamp, ignoring other tags")
}

func TestSummaryWithoutNotes(t *testing.T) {
	s, out, _, _ := newSession(t)
	s.Summary("emudhra-audit-fix")
	assert.Contains(t, out.String(), "Changed: 0   Failed or refused: 0   Skipped: 0")
	assert.NotContains(t, out.String(), "Backups and undo notes")
}

func TestSummaryWithNotes(t *testing.T) {
	s, out, _, _ := newSession(t)
	s.Note("a  ->  a.bak")
	s.Summary("emudhra-audit-fix")
	assert.Contains(t, out.String(), "  Backups and undo notes:\n    a  ->  a.bak\n")
	assert.Contains(t, out.String(), "Restore system files and JDK stores with: emudhra-audit-fix --undo")
}

// A Session with no Out must not panic; a fix run from a test or a caller that
// forgot to set it should be silent, not crash halfway through a change.
func TestSessionWithoutOutDoesNotPanic(t *testing.T) {
	s := &Session{Priv: privilege.NewFakeEscalator(), Prompt: prompt.NewFakePrompter()}
	assert.NotPanics(t, func() {
		s.Say("x")
		s.Warn("x")
		s.OK("x")
		s.Bad("x")
		s.Cmd("x")
		s.Summary("p")
	})
}

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"":                   "''",
		"/usr/bin/uv":        "/usr/bin/uv",
		"my tool":            `my\ tool`,
		"a;b":                `a\;b`,
		"$(x)":               `\$\(x\)`,
		"AZaz09_@%+=:,./-":   "AZaz09_@%+=:,./-",
		"it's":               `'it'\''s'`,
		"two\nlines":         "'two\nlines'",
		"/Users/a b/.local/": `/Users/a\ b/.local/`,
	} {
		assert.Equal(t, want, Quote(in), "%q", in)
	}
}

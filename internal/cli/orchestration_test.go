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

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/registry"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/report"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

// fakeKind is a Kind with scripted behaviour.
type fakeKind struct {
	id       string
	applies  bool
	reason   string
	findings []kinds.Finding
	err      error
	audited  *int
}

func (k *fakeKind) ID() string       { return k.id }
func (k *fakeKind) Describe() string { return "fake " + k.id }
func (k *fakeKind) Applicable(platform.Host) kinds.Applicability {
	return kinds.Applicability{Applies: k.applies, Reason: k.reason}
}
func (k *fakeKind) Audit(context.Context, *kinds.Env) ([]kinds.Finding, error) {
	if k.audited != nil {
		*k.audited++
	}
	return k.findings, k.err
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func affected(kind, tool string) kinds.Finding {
	f := kinds.NewFinding(kind, tool)
	f.SetProbe(kinds.ProbeTrusted, "")
	return f
}

func TestPerformAuditCollectsFindings(t *testing.T) {
	all := []kinds.Kind{
		&fakeKind{id: "a", applies: true, findings: []kinds.Finding{affected("a", "tool-a")}},
		&fakeKind{id: "b", applies: true, findings: []kinds.Finding{affected("b", "tool-b")}},
	}
	got, missing, err := performAudit(context.Background(), testutil.NewTestEnvT(t), quiet(), all, nil)
	require.NoError(t, err)
	assert.Len(t, got, 2)
	assert.Empty(t, missing)
}

func TestPerformAuditReportsNotApplicableAndEmptyAsMissing(t *testing.T) {
	all := []kinds.Kind{
		&fakeKind{id: "mac-only", applies: false, reason: "macOS only"},
		&fakeKind{id: "absent", applies: true},
		&fakeKind{id: "present", applies: true, findings: []kinds.Finding{affected("present", "p")}},
	}
	got, missing, err := performAudit(context.Background(), testutil.NewTestEnvT(t), quiet(), all, nil)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	assert.Equal(t, []string{"mac-only", "absent"}, missing)
}

// A Kind whose check broke must not look like a Kind whose check passed.
func TestPerformAuditSurfacesAFailedKindAsUnknown(t *testing.T) {
	all := []kinds.Kind{&fakeKind{id: "broken", applies: true, err: errors.New("boom")}}
	got, _, err := performAudit(context.Background(), testutil.NewTestEnvT(t), quiet(), all, nil)
	require.NoError(t, err)
	require.Len(t, got, 1, "the failure must be visible in the report")
	assert.Equal(t, kinds.StatusUnknown, got[0].Status())
	assert.Equal(t, "broken", got[0].Kind)
	assert.Contains(t, got[0].Evidence, "boom")
	assert.Equal(t, 0, report.ExitCode(got), "unknown does not set the exit code, as in the script")
}

func TestPerformAuditHonoursOnlyAndAliases(t *testing.T) {
	var a, b, c int
	all := []kinds.Kind{
		&fakeKind{id: "sysbundle", applies: true, audited: &a},
		&fakeKind{id: "ospkg", applies: true, audited: &b},
		&fakeKind{id: "python", applies: true, audited: &c},
	}
	_, _, err := performAudit(context.Background(), testutil.NewTestEnvT(t), quiet(), all, []string{"sys"})
	require.NoError(t, err)
	assert.Equal(t, [3]int{1, 1, 0}, [3]int{a, b, c}, "--only=sys expands to sysbundle and ospkg")

	a, b, c = 0, 0, 0
	_, _, err = performAudit(context.Background(), testutil.NewTestEnvT(t), quiet(), all, []string{"python"})
	require.NoError(t, err)
	assert.Equal(t, [3]int{0, 0, 1}, [3]int{a, b, c})
}

func TestPerformAuditBlankOnlyRunsEverything(t *testing.T) {
	var a int
	all := []kinds.Kind{&fakeKind{id: "x", applies: true, audited: &a}}
	_, _, err := performAudit(context.Background(), testutil.NewTestEnvT(t), quiet(), all, []string{""})
	require.NoError(t, err)
	assert.Equal(t, 1, a)
}

// The scratch directory is what stops a Kind writing its probe file into the
// user's current directory, so it must exist, be private, and be removed.
func TestScratchDir(t *testing.T) {
	dir, cleanup, err := scratchDir()
	require.NoError(t, err)
	require.NotEmpty(t, dir)

	fi, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, fi.IsDir())
	assert.Equal(t, os.FileMode(0o700), fi.Mode().Perm(), "scratch space must not be readable by others")
	assert.Contains(t, filepath.Base(dir), "emudhra-")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "probe.go"), []byte("x"), 0o600))
	cleanup()
	_, err = os.Stat(dir)
	assert.True(t, os.IsNotExist(err), "the scratch directory and its contents must be removed")
}

func TestBuildSectionsFollowTheScriptsAuditOrderWithItsWording(t *testing.T) {
	env := testutil.NewTestEnvT(t)
	env.Host = testutil.NewDarwinHost()
	env.Environ = map[string]string{"HOME": t.TempDir(), "PATH": t.TempDir()}

	secs := buildSections(env, registry.All(), nil, nil)

	var titles []string
	byID := map[string]report.Section{}
	for _, s := range secs {
		titles = append(titles, s.Title)
		byID[s.ID] = s
	}
	assert.Equal(t, []string{"curl", "git", "Go", "Python", "Java (JRE/JDK)", "Node.js", "Deno", "Bun", "rustup", "uv", "pixi", "mise",
		"Claude Code", "Homebrew ca-certificates", "System CA bundle files", "OS CA packages", "Electron apps"}, titles,
		"fix-only Kinds (uvpython, uvtools, macpip) have no section")
	assert.Equal(t, "not found", byID["deno"].None)
	assert.Equal(t, "Homebrew not found", byID["brew"].None)
	assert.Equal(t, "none found", byID["sysbundle"].None)
	assert.Equal(t, "no supported package manager / ca-certificates package found (not applicable here)", byID["ospkg"].None)
	assert.Equal(t, "no Electron apps found", byID["electron"].None)
	assert.Equal(t, "Note: macOS's own trust store (Keychain) carries Apple's block since 19 Oct; tools that use it are protected.", byID["sysbundle"].Note)
	assert.Empty(t, byID["curl"].Note)

	env.Host = testutil.NewLinuxHost()
	for _, s := range buildSections(env, registry.All(), nil, nil) {
		if s.ID == "electron" {
			assert.Equal(t, "(macOS apps only for now - not checked on this platform)", s.None)
		}
		if s.ID == "sysbundle" {
			assert.Empty(t, s.Note, "the Keychain note is macOS only")
		}
	}
}

func TestBuildSectionsHonourOnly(t *testing.T) {
	env := testutil.NewTestEnvT(t)
	secs := buildSections(env, registry.All(), []string{"node"}, nil)
	require.Len(t, secs, 1)
	assert.Equal(t, "Node.js", secs[0].Title)
}

func TestPrintHeaderAsksUnameAndShowsTheEnvironment(t *testing.T) {
	fake := exec.NewFakeRunner()
	fake.AddSuccess("uname -sm", "Linux x86_64\n")
	fake.AddSuccess("uname -srm", "Linux 6.1.0 x86_64\n")
	env := testutil.NewTestEnvT(t)
	env.Run = fake
	env.Host.HasTTY = false
	env.Environ = map[string]string{"SSL_CERT_FILE": "/ca.pem"}

	var compact, verbose bytes.Buffer
	printHeader(context.Background(), env, report.NewReporter(0, false), Options{NoNetwork: true}, &compact)
	printHeader(context.Background(), env, report.NewReporter(1, false), Options{Verbose: 1}, &verbose)

	assert.Contains(t, compact.String(), "eMudhra CA compromise audit v")
	assert.Contains(t, compact.String(), " - Linux x86_64 - ")
	assert.Contains(t, compact.String(), " - version checks only\n")
	assert.Contains(t, compact.String(), "CA-related environment (affects the results below):\n  SSL_CERT_FILE=/ca.pem\n")
	assert.Contains(t, verbose.String(), "Host: Linux 6.1.0 x86_64   Date: ")
	assert.Contains(t, verbose.String(), "Probe hosts: https://dv-g3b-emudhra.we-have-a-problem.com/ https://dv-g3b-aaa-emudhra.we-have-a-problem.com/ (control: https://github.com/)\n")
	assert.Contains(t, verbose.String(), "== CA-related environment ==\n  SSL_CERT_FILE=/ca.pem\n")

	var undo bytes.Buffer
	printHeader(context.Background(), env, report.NewReporter(0, false), Options{Undo: true}, &undo)
	assert.NotContains(t, undo.String(), "CA-related environment", "--undo prints the header only")
}

func TestMissingListsSectionTitlesNotKindIDs(t *testing.T) {
	secs := []report.Section{{ID: "curl", Title: "curl"}, {ID: "claudecode", Title: "Claude Code"}, {ID: "ospkg", Title: "OS CA packages"}}
	found := []kinds.Finding{kinds.NewFinding("curl", "curl")}
	assert.Equal(t, "Claude Code, OS CA packages", missingTitles(secs, found))
	assert.Empty(t, missingTitles(secs[:1], found))
}

func TestHeaderIsColouredOnlyOnATerminal(t *testing.T) {
	fake := exec.NewFakeRunner()
	fake.AddSuccess("uname -sm", "Linux x86_64\n")
	env := testutil.NewTestEnvT(t)
	env.Run = fake
	env.Host.HasTTY = true
	var out bytes.Buffer
	printHeader(context.Background(), env, report.NewReporter(0, false), Options{}, &out)
	assert.Contains(t, out.String(), "\x1b[1m")
}

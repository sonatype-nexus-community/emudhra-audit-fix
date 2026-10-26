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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

// recFix records when it runs.
type recFix struct {
	kind, target string
	out          fixrun.Outcome
	log          *[]string
}

func (f recFix) Kind() string   { return f.kind }
func (f recFix) Target() string { return f.target }
func (f recFix) Run(_ context.Context, s *fixrun.Session) fixrun.Outcome {
	*f.log = append(*f.log, f.kind+":"+f.target)
	s.Say("fixing %s", f.target)
	return f.out
}

// fixerKind is a Kind that can also fix and undo.
type fixerKind struct {
	fakeKind
	order   int
	plan    []fixrun.Fix
	planErr error
	undoErr error
	undone  *[]string
}

func (k *fixerKind) FixOrder() int { return k.order }

func (k *fixerKind) Plan(context.Context, *kinds.Env, []kinds.Finding) ([]fixrun.Fix, error) {
	return k.plan, k.planErr
}
func (k *fixerKind) Undo(_ context.Context, _ *kinds.Env, s *fixrun.Session) error {
	if k.undone != nil {
		*k.undone = append(*k.undone, k.id)
	}
	s.Say("undoing %s", k.id)
	return k.undoErr
}

func TestRunFixesRunsInRegistryOrderAndSummarises(t *testing.T) {
	var log []string
	all := []kinds.Kind{
		&fixerKind{fakeKind: fakeKind{id: "brew", applies: true}, plan: []fixrun.Fix{recFix{"brew", "ca-certificates", fixrun.Changed, &log}}},
		&fakeKind{id: "audit-only", applies: true},
		&fixerKind{fakeKind: fakeKind{id: "java", applies: true}, plan: []fixrun.Fix{
			recFix{"java", "jdk17", fixrun.Failed, &log}, recFix{"java", "jdk21", fixrun.Skipped, &log}}},
	}
	var out bytes.Buffer
	runFixes(context.Background(), testutil.NewTestEnvT(t), &out, false, all, nil, Options{})

	assert.Equal(t, []string{"brew:ca-certificates", "java:jdk17", "java:jdk21"}, log, "registry order, and a failure does not stop the rest")
	assert.Contains(t, out.String(), "== Fix ==")
	assert.Contains(t, out.String(), "Each change asks first, is tested on a copy, is backed up, verified after, and rolled back if it fails.")
	assert.Contains(t, out.String(), "Changed: 1   Failed or refused: 1   Skipped: 1")
}

func TestRunFixesDryRunBanner(t *testing.T) {
	var log []string
	all := []kinds.Kind{&fixerKind{fakeKind: fakeKind{id: "a", applies: true}, plan: []fixrun.Fix{recFix{"a", "x", fixrun.Skipped, &log}}}}
	env := testutil.NewTestEnvT(t)
	env.DryRun = true
	var out bytes.Buffer
	runFixes(context.Background(), env, &out, false, all, nil, Options{})
	assert.Contains(t, out.String(), "DRY RUN - nothing will be changed. Each step below is verified on a copy where possible.")
	assert.NotContains(t, out.String(), "Each change asks first")
}

func TestRunFixesNothingToFix(t *testing.T) {
	var out bytes.Buffer
	runFixes(context.Background(), testutil.NewTestEnvT(t), &out, false, []kinds.Kind{&fakeKind{id: "a", applies: true}}, nil, Options{})
	assert.Contains(t, out.String(), "Nothing to fix: no item has an automated upgrade or trust-store fix planned.")
	assert.Contains(t, out.String(), "Changed: 0   Failed or refused: 0   Skipped: 0")
}

func TestRunFixesOnly(t *testing.T) {
	var log []string
	all := []kinds.Kind{
		&fixerKind{fakeKind: fakeKind{id: "sysbundle", applies: true}, plan: []fixrun.Fix{recFix{"sysbundle", "s", fixrun.Changed, &log}}},
		&fixerKind{fakeKind: fakeKind{id: "ospkg", applies: true}, plan: []fixrun.Fix{recFix{"ospkg", "o", fixrun.Changed, &log}}},
		&fixerKind{fakeKind: fakeKind{id: "java", applies: true}, plan: []fixrun.Fix{recFix{"java", "j", fixrun.Changed, &log}}},
	}
	var out bytes.Buffer
	runFixes(context.Background(), testutil.NewTestEnvT(t), &out, false, all, nil, Options{Only: []string{"sys"}})
	assert.Equal(t, []string{"sysbundle:s", "ospkg:o"}, log, "--only=sys expands to its two Kinds")

	log = nil
	out.Reset()
	runFixes(context.Background(), testutil.NewTestEnvT(t), &out, false, all, nil, Options{Only: []string{"uv"}})
	assert.Empty(t, log)
	assert.Contains(t, out.String(), "Nothing matched --only uv.")
}

func TestRunFixesAPlanErrorDoesNotBlockOthers(t *testing.T) {
	var log []string
	all := []kinds.Kind{
		&fixerKind{fakeKind: fakeKind{id: "bad", applies: true}, planErr: errors.New("cannot plan")},
		&fixerKind{fakeKind: fakeKind{id: "good", applies: true}, plan: []fixrun.Fix{recFix{"good", "g", fixrun.Changed, &log}}},
	}
	var out bytes.Buffer
	runFixes(context.Background(), testutil.NewTestEnvT(t), &out, false, all, nil, Options{})
	assert.Equal(t, []string{"good:g"}, log)
	assert.Contains(t, out.String(), "could not plan the bad fix: cannot plan")
}

func TestRunFixesMDMWarning(t *testing.T) {
	var log []string
	all := []kinds.Kind{&fixerKind{fakeKind: fakeKind{id: "a", applies: true}, plan: []fixrun.Fix{recFix{"a", "x", fixrun.Changed, &log}}}}
	env := testutil.NewTestEnvT(t)
	env.Host = platform.Host{OS: "darwin", MDM: platform.MDMStatus{Enrolled: true, Source: "DEP"}}
	var out bytes.Buffer
	runFixes(context.Background(), env, &out, false, all, nil, Options{})
	assert.Contains(t, out.String(), "this Mac appears to be enrolled in MDM (DEP): IT may overwrite these changes, or want to make them centrally")

	env.Host = platform.Host{OS: "darwin"}
	out.Reset()
	runFixes(context.Background(), env, &out, false, all, nil, Options{})
	assert.NotContains(t, out.String(), "MDM")
}

func TestRunUndo(t *testing.T) {
	var undone []string
	all := []kinds.Kind{
		&fixerKind{fakeKind: fakeKind{id: "sysbundle", applies: true}, undone: &undone},
		&fakeKind{id: "no-undo", applies: true},
		&fixerKind{fakeKind: fakeKind{id: "java", applies: true}, undone: &undone},
	}
	var out bytes.Buffer
	rc := runUndo(context.Background(), testutil.NewTestEnvT(t), &out, false, all, Options{})
	assert.Equal(t, 0, rc)
	assert.Equal(t, []string{"sysbundle", "java"}, undone)
	assert.Contains(t, out.String(), "== Undo ==")
	assert.Contains(t, out.String(), "Homebrew and uv upgrades are not covered by --undo")
}

func TestRunUndoFailureStillRunsTheOthers(t *testing.T) {
	var undone []string
	all := []kinds.Kind{
		&fixerKind{fakeKind: fakeKind{id: "a", applies: true}, undone: &undone, undoErr: errors.New("restore failed")},
		&fixerKind{fakeKind: fakeKind{id: "b", applies: true}, undone: &undone},
	}
	var out bytes.Buffer
	rc := runUndo(context.Background(), testutil.NewTestEnvT(t), &out, false, all, Options{})
	assert.Equal(t, 2, rc)
	assert.Equal(t, []string{"a", "b"}, undone)
	assert.Contains(t, out.String(), "a: restore failed")
}

// Every Fixer sees every finding: one tool's audit can schedule another Kind's
// fix (a Python finding plans the macOS pip fix), so filtering by Kind would
// make such a fix unreachable.
func TestPlanFixesPassesEveryKindAllFindings(t *testing.T) {
	var got []kinds.Finding
	probe := &capturePlanKind{fakeKind: fakeKind{id: "k", applies: true}, got: &got}
	findings := []kinds.Finding{affected("k", "mine"), affected("other", "theirs")}
	var out bytes.Buffer
	s := newSession(testutil.NewTestEnvT(t), &out, false)
	planFixes(context.Background(), testutil.NewTestEnvT(t), s, []kinds.Kind{probe}, findings)
	require.Len(t, got, 2)
	assert.Equal(t, []string{"mine", "theirs"}, []string{got[0].Tool, got[1].Tool})
}

// pipFixKind plans its fix only from ANOTHER Kind's finding, as macpip does.
type pipFixKind struct {
	fakeKind
	ran *[]string
}

func (k *pipFixKind) FixOrder() int { return kinds.FixMacPip }

func (k *pipFixKind) Plan(_ context.Context, _ *kinds.Env, fs []kinds.Finding) ([]fixrun.Fix, error) {
	for _, f := range fs {
		if f.Kind == "python" && f.NeedsPipGuidance && f.HasFix {
			return []fixrun.Fix{recFix{k.id, f.Path, fixrun.Changed, k.ran}}, nil
		}
	}
	return nil, nil
}

func TestACrossKindFixIsReachableThroughTheRunner(t *testing.T) {
	py := affected("python", "Python")
	py.Path = "/usr/bin/python3"
	py.NeedsPipGuidance, py.HasFix = true, true

	var ran []string
	all := []kinds.Kind{
		&fakeKind{id: "python", applies: true, findings: []kinds.Finding{py}},
		&pipFixKind{fakeKind: fakeKind{id: "macpip", applies: true}, ran: &ran},
	}
	var out bytes.Buffer
	runFixes(context.Background(), testutil.NewTestEnvT(t), &out, false, all, []kinds.Finding{py}, Options{})
	assert.Equal(t, []string{"macpip:/usr/bin/python3"}, ran, "the macpip fix must be planned from Python's finding")

	ran = nil
	out.Reset()
	runFixes(context.Background(), testutil.NewTestEnvT(t), &out, false, all, nil, Options{})
	assert.Empty(t, ran, "no Python finding, no pip fix")
}

type capturePlanKind struct {
	fakeKind
	got *[]kinds.Finding
}

func (k *capturePlanKind) FixOrder() int { return 0 }

func (k *capturePlanKind) Plan(_ context.Context, _ *kinds.Env, f []kinds.Finding) ([]fixrun.Fix, error) {
	*k.got = f
	return nil, nil
}

// Fixes run in the script's run_fixes order (brew, sys, java, macpip, node, uv,
// uvpython, uvtools, rustup) whatever order the Kinds are registered in.
func TestFixesRunInTheScriptsOrderNotRegistryOrder(t *testing.T) {
	var log []string
	mk := func(id string, order int) *fixerKind {
		return &fixerKind{fakeKind: fakeKind{id: id, applies: true}, order: order,
			plan: []fixrun.Fix{recFix{id, id, fixrun.Changed, &log}}}
	}
	// registered in an order that differs from the fix order
	all := []kinds.Kind{
		mk("rustup", kinds.FixRustup), mk("uv", kinds.FixUV), mk("sysbundle", kinds.FixSys),
		mk("brew", kinds.FixBrew), mk("macpip", kinds.FixMacPip), mk("java", kinds.FixJava),
		mk("ospkg", kinds.FixSys), mk("node", kinds.FixNode),
	}
	var out bytes.Buffer
	runFixes(context.Background(), testutil.NewTestEnvT(t), &out, false, all, nil, Options{})
	assert.Equal(t, []string{"brew:brew", "sysbundle:sysbundle", "ospkg:ospkg", "java:java", "macpip:macpip", "node:node", "uv:uv", "rustup:rustup"}, log,
		"brew, then the system store (registry order within it), java, macpip, node, uv, rustup")
}

func TestFixOrderConstantsAreInTheScriptsOrder(t *testing.T) {
	order := []int{kinds.FixBrew, kinds.FixSys, kinds.FixJava, kinds.FixMacPip, kinds.FixNode,
		kinds.FixUV, kinds.FixUVPython, kinds.FixUVTools, kinds.FixRustup}
	assert.IsIncreasing(t, order)
}

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

package node

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/privilege"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

// makeFakeNvmEnv creates a fake nvm environment with a stub nvm.sh and fake node binaries.
// This mirrors the make_fake_node and new_env functions from test_fix_node.sh.
func makeFakeNvmEnv(t *testing.T, oldVersion, fixedVersion, fixedResult string, opts ...map[string]string) (nvmDir string) {
	t.Helper()

	tmpDir := t.TempDir()
	nvmDir = filepath.Join(tmpDir, "nvm")

	// Parse options
	optsMap := map[string]string{
		"REMOTE":     fixedVersion, // What nvm version-remote returns
		"DEFAULT":    oldVersion,   // What nvm version default returns
		"INSTALL":    "ok",         // Whether install succeeds
		"EXTRA":      "",           // Additional old versions
		"ALIASES":    "",           // Aliases (format: "name:vX.Y.Z name2:vA.B.C")
		"UNINSTALL":  "ok",         // Whether uninstall succeeds
		"ACTIVE":     "",           // Currently active version (set if any)
		"DEACTIVATE": "works",      // Whether deactivate works
	}
	for _, m := range opts {
		for k, v := range m {
			optsMap[k] = v
		}
	}

	// Create versions directory
	versionsDir := filepath.Join(nvmDir, "versions", "node")
	require.NoError(t, os.MkdirAll(versionsDir, 0755))

	// Make fake old version node
	makeFakeNode(t, filepath.Join(versionsDir, "v"+oldVersion), oldVersion, "trusted")

	// Make additional old versions
	if optsMap["EXTRA"] != "" {
		for _, extra := range strings.Fields(optsMap["EXTRA"]) {
			extraVer := strings.TrimPrefix(extra, "v")
			makeFakeNode(t, filepath.Join(versionsDir, extra), extraVer, "trusted")
		}
	}

	// Create nvm.sh stub
	nvmSh := filepath.Join(nvmDir, "nvm.sh")
	content := createNvmShContent(oldVersion, fixedVersion, fixedResult, optsMap)
	require.NoError(t, os.WriteFile(nvmSh, []byte(content), 0755))

	return nvmDir
}

// makeFakeNode creates a fake node binary that responds to --version and acts as probe target.
func makeFakeNode(t *testing.T, dir, version, verdict string) {
	t.Helper()

	binDir := filepath.Join(dir, "bin")
	require.NoError(t, os.MkdirAll(binDir, 0755))

	// Write version file
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "version"), []byte(version), 0644))

	// Write verdict file
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "verdict"), []byte(verdict), 0644))

	// Write node script
	nodeScript := `#!/bin/sh
here=$(cd "$(dirname "$0")" && pwd)
case "$1" in
  --version) echo "v$(cat "$here/version")"; exit 0 ;;
  -e) exit 0 ;;
esac
# probe invocation: node probe.js CONTROL BAD1 BAD2 -> one "<result> <url>" per URL
shift
verdict=$(cat "$here/verdict")
[ "$verdict" = rejected ] && verdict=certerr
[ "$verdict" = trusted ] && verdict=ok
for u in "$@"; do
  case "$u" in
    *we-have-a-problem*) echo "$verdict $u" ;;
    *) echo "ok $u" ;;
  esac
done
`

	require.NoError(t, os.WriteFile(filepath.Join(binDir, "node"), []byte(nodeScript), 0755))
}

// createNvmShContent creates the stub nvm.sh script content
func createNvmShContent(oldVersion, fixedVersion, fixedResult string, opts map[string]string) string {
	return fmt.Sprintf(`#!/bin/bash
# stub nvm: records calls in $NVM_DIR/calls.log
nvm() {
  echo "nvm $*" >> "$NVM_DIR/calls.log"
  case "$1" in
    version-remote) echo "v%s" ;;
    version)
      if [ "$2" = default ]; then
        if [ -s "$NVM_DIR/default.state" ]; then cat "$NVM_DIR/default.state"; else echo "v%s"; fi
      fi ;;
    install)
      [ "%s" = nothing ] && return 1
      v=${2#v}
      d="$NVM_DIR/versions/node/v$v"
      mkdir -p "$d/bin"
      cp "$NVM_DIR/versions/node/v%s/bin/node" "$d/bin/node"
      printf '%%s\n' "$v" > "$d/bin/version"
      printf '%%s\n' "%s" > "$d/bin/verdict" ;;
    alias)
      if [ -n "$2" ]; then
        echo "alias $2 $3" >> "$NVM_DIR/aliases.log"
        [ "$2" = default ] && echo "$3" > "$NVM_DIR/default.state"
      else
        for a in %s; do echo "${a%%:*} -> x (-> ${a#*:})"; done
      fi ;;
    deactivate)
      [ "%s" = works ] && ACTIVE_NOW=""
      return 0 ;;
    uninstall)
      if [ -n "${ACTIVE_NOW-%s}" ] && [ "${ACTIVE_NOW-%s}" = "$2" ]; then
        echo "nvm: Cannot uninstall currently-active node version, $2 (inferred from $2)." >&2
        return 1
      fi
      [ "%s" = fail ] && { echo "nvm: stub could not remove $2" >&2; return 1; }
      rm -rf "$NVM_DIR/versions/node/$2" ;;
  esac
}
`, opts["REMOTE"], opts["DEFAULT"], opts["INSTALL"], oldVersion, fixedResult, opts["ALIASES"],
		opts["DEACTIVATE"], opts["ACTIVE"], opts["ACTIVE"], opts["UNINSTALL"])
}

// testPrompt implements prompt.Prompter for testing.
type testPrompt struct {
	confirmAnswers      []bool
	confirmAgreeAnswers []bool
	confirmIndex        int
	confirmAgreeIndex   int
}

func (p *testPrompt) Confirm(question string, autoYes bool) bool {
	if p.confirmIndex < len(p.confirmAnswers) {
		answer := p.confirmAnswers[p.confirmIndex]
		p.confirmIndex++
		return answer
	}
	return autoYes
}

func (p *testPrompt) ConfirmAgree(warning string) bool {
	if p.confirmAgreeIndex < len(p.confirmAgreeAnswers) {
		answer := p.confirmAgreeAnswers[p.confirmAgreeIndex]
		p.confirmAgreeIndex++
		return answer
	}
	return false
}

// readNvmCalls reads the nvm calls log
func readNvmCalls(nvmDir string) []string {
	data, err := os.ReadFile(filepath.Join(nvmDir, "calls.log"))
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var result []string
	for _, line := range lines {
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

// nodeInstalled checks if a node version is installed
func nodeInstalled(nvmDir, version string) bool {
	nodePath := filepath.Join(nvmDir, "versions", "node", "v"+version, "bin", "node")
	_, err := os.Stat(nodePath)
	return err == nil
}

// setupNodeFixTest creates a complete test environment for Node fix scenarios
func setupNodeFixTest(t *testing.T, nvmDir string) *kinds.Env {
	t.Helper()

	env := testutil.NewTestEnvT(t)
	env.Environ = map[string]string{
		"NVM_DIR":           nvmDir,
		"EMUDHRA_NODE_BINS": filepath.Join(nvmDir, "versions", "node"),
	}
	// Use a real runner so the fake node scripts actually execute
	env.Run = exec.NewRealRunner()

	return env
}

// TestNodeFixScenarios tests the full fix flow for Node.js via nvm.
// This ports all scenarios from legacy/tests/test_fix_node.sh.
func TestNodeFixScenarios(t *testing.T) {
	ctx := context.Background()

	t.Run("happy path", func(t *testing.T) {
		// Scenario 1: 24.16.0 -> 24.22.1, default is the old version, answer y to both prompts
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected")
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)
		require.NotEmpty(t, findings, "expected at least one finding")

		// Plan fixes
		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)
		require.Len(t, fixes, 1, "expected one fix")

		// Run the fix with y answers
		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true, true}},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		// Check outcome
		assert.Equal(t, fixrun.Changed, result, "expected Changed, got %v. Output:\n%s", result, out.String())

		// Check nvm calls
		calls := readNvmCalls(nvmDir)
		assert.Contains(t, calls, "nvm install v24.22.1 --reinstall-packages-from=v24.16.0", "expected install command")

		// Check versions
		assert.True(t, nodeInstalled(nvmDir, "24.22.1"), "fixed version should be installed")
		assert.True(t, nodeInstalled(nvmDir, "24.16.0"), "old version should still be installed (removal is separate)")
		assert.FileExists(t, filepath.Join(nvmDir, "aliases.log"), "default alias should have been changed")

		// Check output mentions verification
		assert.Contains(t, out.String(), "verified:", "expected verification message")
	})

	t.Run("declined prompt", func(t *testing.T) {
		// Scenario 2: answering n at the install prompt changes nothing
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected")
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)
		require.Len(t, fixes, 1)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{false}}, // Decline install
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		assert.Equal(t, fixrun.Skipped, result)
		assert.False(t, nodeInstalled(nvmDir, "24.22.1"), "should not have installed fixed version")
		assert.NoFileExists(t, filepath.Join(nvmDir, "aliases.log"), "should not have touched aliases")
	})

	t.Run("install yes default no", func(t *testing.T) {
		// Scenario 3: install yes, default prompt no
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected")
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true, false}}, // Accept install, decline default change
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		assert.Equal(t, fixrun.Changed, result)
		assert.True(t, nodeInstalled(nvmDir, "24.22.1"), "fixed version should be installed")
		assert.NoFileExists(t, filepath.Join(nvmDir, "aliases.log"), "should not have changed default alias")
	})

	t.Run("failed install", func(t *testing.T) {
		// Scenario 4: an install that does nothing leaves everything as it was
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected", map[string]string{
			"INSTALL": "nothing",
		})
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true, true}},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		assert.Equal(t, fixrun.Failed, result, "expected Failed for failed install")
		assert.Contains(t, out.String(), "nvm did not install", "expected failure message")
		assert.True(t, nodeInstalled(nvmDir, "24.16.0"), "old version should still be there")
		assert.NoFileExists(t, filepath.Join(nvmDir, "aliases.log"), "should not have changed aliases")
	})

	t.Run("other default", func(t *testing.T) {
		// Scenario 5: a default that is not the old version is left alone
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected", map[string]string{
			"DEFAULT": "22.0.0",
		})
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true, true}},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		assert.Equal(t, fixrun.Changed, result)
		assert.True(t, nodeInstalled(nvmDir, "24.22.1"))
		assert.Contains(t, out.String(), "not changing it", "should say default was not changed")
		assert.NoFileExists(t, filepath.Join(nvmDir, "aliases.log"), "should not have changed aliases")
	})

	t.Run("failed verification", func(t *testing.T) {
		// Scenario 6: a verified-bad new install must not become the default
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "trusted") // Fixed version still trusts the chain
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true, true}},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		assert.Equal(t, fixrun.Failed, result, "expected Failed for verification failure")
		assert.Contains(t, out.String(), "does not reject the chain", "should report verification failure")
		assert.NoFileExists(t, filepath.Join(nvmDir, "aliases.log"), "should not have changed default")
	})

	t.Run("unpublished fix", func(t *testing.T) {
		// Scenario 7: fixed release nvm does not offer yet is refused
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected", map[string]string{
			"REMOTE": "24.20.0", // nvm reports older than fixed
		})
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true, true}},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		assert.Equal(t, fixrun.Skipped, result, "expected Skipped when fix not available")
		assert.Contains(t, out.String(), "not available yet", "should report unavailability")
	})

	t.Run("no fix for major", func(t *testing.T) {
		// Scenario 8: a major line with no published fix (v25)
		nvmDir := makeFakeNvmEnv(t, "25.1.0", "25.9.0", "rejected", map[string]string{
			"REMOTE": "25.9.0",
		})
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		// Should not have fix scheduled because there's no fix for major 25
		// This is handled in Audit by setting HasFix only for nvm + behind versions with known fixes
		// Check that no fix is scheduled
		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		// Should not create a fix for v25 because there's no fixed version for that major
		assert.Empty(t, fixes, "should not schedule a fix for major line with no published fix")

		// Also verify NodeLineCheck returns no fix for major 25
		vc, fixed, _ := NodeLineCheck("25.1.0")
		assert.Equal(t, kinds.VersionNoFix, vc)
		assert.Contains(t, fixed, "22.23.4, 24.22.1 or 26.12.1")
	})

	t.Run("dry run", func(t *testing.T) {
		// Scenario 18: dry run prints the commands, changes nothing
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected")
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true, true}},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  true, // Dry run mode
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		assert.Equal(t, fixrun.Skipped, result, "dry run should return Skipped")

		output := out.String()
		assert.Contains(t, output, "nvm install v24.22.1", "should print install command")
		assert.Contains(t, output, "type-I-AGREE", "should mention removal gate")
		assert.False(t, nodeInstalled(nvmDir, "24.22.1"), "dry run should not install anything")

		// Verify no nvm commands were run
		calls := readNvmCalls(nvmDir)
		for _, call := range calls {
			assert.NotContains(t, call, "nvm install", "dry run should not run nvm install")
			assert.NotContains(t, call, "nvm uninstall", "dry run should not run nvm uninstall")
		}
	})

	t.Run("removal I AGREE", func(t *testing.T) {
		// Scenario 10: typing exactly I AGREE removes the old version
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected", map[string]string{
			"ALIASES": "default:v24.22.1", // Default already points to new version
		})
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true, true}, confirmAgreeAnswers: []bool{true}},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		assert.Equal(t, fixrun.Changed, result)

		calls := readNvmCalls(nvmDir)
		assert.Contains(t, calls, "nvm uninstall v24.16.0", "should run uninstall")

		assert.False(t, nodeInstalled(nvmDir, "24.16.0"), "old version should be removed")
		assert.True(t, nodeInstalled(nvmDir, "24.22.1"), "fixed version should remain")

		// Check the output shows the removal happened
		assert.Contains(t, out.String(), "removed v24.16.0", "should report removal")
	})

	t.Run("removal rejects non I AGREE", func(t *testing.T) {
		// Scenario 11: anything other than exactly I AGREE keeps it
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected", map[string]string{
			"ALIASES": "default:v24.22.1",
		})
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true, true}, confirmAgreeAnswers: []bool{false}},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		assert.Equal(t, fixrun.Changed, result) // Still changed because install succeeded
		assert.True(t, nodeInstalled(nvmDir, "24.16.0"), "old version should still be there")

		calls := readNvmCalls(nvmDir)
		for _, call := range calls {
			assert.NotContains(t, call, "nvm uninstall", "should not run uninstall")
		}
	})

	t.Run("removal --yes never removes", func(t *testing.T) {
		// Scenario 12: --yes alone must never remove anything
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected", map[string]string{
			"ALIASES": "default:v24.22.1",
		})
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true, true}}, // --yes auto-answers these
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     true, // --yes flag
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		assert.Equal(t, fixrun.Changed, result)
		assert.True(t, nodeInstalled(nvmDir, "24.22.1"), "--yes should install the fixed version")
		assert.True(t, nodeInstalled(nvmDir, "24.16.0"), "--yes should not remove the old version")

		calls := readNvmCalls(nvmDir)
		for _, call := range calls {
			assert.NotContains(t, call, "nvm uninstall", "should not run uninstall")
		}
	})

	t.Run("kept default and aliased versions", func(t *testing.T) {
		// Scenario 14: the default and aliased versions are kept, with the reason
		t.Run("kept as default", func(t *testing.T) {
			nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected", map[string]string{
				"DEFAULT": "24.16.0", // Old version is the default
				"ALIASES": "work:v24.16.0",
			})
			env := setupNodeFixTest(t, nvmDir)

			k := New()
			findings, err := k.Audit(ctx, env)
			require.NoError(t, err)

			fixer := k.(kinds.Fixer)
			fixes, err := fixer.Plan(ctx, env, findings)
			require.NoError(t, err)

			var out bytes.Buffer
			runner := exec.NewRealRunner()
			fakePriv := privilege.NewFakeEscalator()
			fakePriv.IsRootVal = true

			s := &fixrun.Session{
				Run:     runner,
				Prompt:  &testPrompt{confirmAnswers: []bool{true, false}}, // Install, decline default change
				Priv:    fakePriv,
				Host:    platform.Host{OS: "darwin"},
				DryRun:  false,
				Yes:     false,
				Color:   false,
				Out:     &out,
				Stamp:   "20260101120000",
				TempDir: env.TempDir,
			}

			result := fixes[0].Run(ctx, s)

			assert.Equal(t, fixrun.Changed, result)
			output := out.String()
			assert.Contains(t, output, "keeping v24.16.0: it is your nvm default", "should explain why kept")
			assert.Contains(t, output, "aliases point at it", "should mention aliases")
			assert.True(t, nodeInstalled(nvmDir, "24.16.0"), "old version should be kept")
			assert.NotContains(t, output, "Type I AGREE", "should not show removal prompt")
		})

		t.Run("kept as aliased", func(t *testing.T) {
			nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected", map[string]string{
				"DEFAULT": "22.0.0",
				"ALIASES": "work:v24.16.0", // Alias points to old version
			})
			env := setupNodeFixTest(t, nvmDir)

			k := New()
			findings, err := k.Audit(ctx, env)
			require.NoError(t, err)

			fixer := k.(kinds.Fixer)
			fixes, err := fixer.Plan(ctx, env, findings)
			require.NoError(t, err)

			var out bytes.Buffer
			runner := exec.NewRealRunner()
			fakePriv := privilege.NewFakeEscalator()
			fakePriv.IsRootVal = true

			s := &fixrun.Session{
				Run:     runner,
				Prompt:  &testPrompt{confirmAnswers: []bool{true}},
				Priv:    fakePriv,
				Host:    platform.Host{OS: "darwin"},
				DryRun:  false,
				Yes:     false,
				Color:   false,
				Out:     &out,
				Stamp:   "20260101120000",
				TempDir: env.TempDir,
			}

			result := fixes[0].Run(ctx, s)

			assert.Equal(t, fixrun.Changed, result)
			output := out.String()
			assert.Contains(t, output, "aliases point at it: work", "should name the alias")
			assert.True(t, nodeInstalled(nvmDir, "24.16.0"), "old version should be kept")
		})
	})

	t.Run("failed uninstall", func(t *testing.T) {
		// Scenario 16: a failed uninstall is reported, not claimed
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected", map[string]string{
			"ALIASES":   "default:v24.22.1",
			"UNINSTALL": "fail",
		})
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true, true}, confirmAgreeAnswers: []bool{true}},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		assert.Equal(t, fixrun.Changed, result) // Still changed because install succeeded
		output := out.String()
		assert.Contains(t, output, "could not remove v24.16.0", "should report failure")
		assert.NotContains(t, output, "removed v24.16.0", "should not claim success")
	})

	t.Run("active version uninstall", func(t *testing.T) {
		// Scenario 19: nvm refuses to uninstall the currently-active version
		t.Run("deactivate helps", func(t *testing.T) {
			nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected", map[string]string{
				"ALIASES":    "default:v24.22.1",
				"ACTIVE":     "v24.16.0",
				"DEACTIVATE": "works",
			})
			env := setupNodeFixTest(t, nvmDir)

			k := New()
			findings, err := k.Audit(ctx, env)
			require.NoError(t, err)

			fixer := k.(kinds.Fixer)
			fixes, err := fixer.Plan(ctx, env, findings)
			require.NoError(t, err)

			var out bytes.Buffer
			runner := exec.NewRealRunner()
			fakePriv := privilege.NewFakeEscalator()
			fakePriv.IsRootVal = true

			s := &fixrun.Session{
				Run:     runner,
				Prompt:  &testPrompt{confirmAnswers: []bool{true, true}, confirmAgreeAnswers: []bool{true}},
				Priv:    fakePriv,
				Host:    platform.Host{OS: "darwin"},
				DryRun:  false,
				Yes:     false,
				Color:   false,
				Out:     &out,
				Stamp:   "20260101120000",
				TempDir: env.TempDir,
			}

			result := fixes[0].Run(ctx, s)

			assert.Equal(t, fixrun.Changed, result)
			assert.False(t, nodeInstalled(nvmDir, "24.16.0"), "old version should be removed")

			calls := readNvmCalls(nvmDir)
			assert.Contains(t, calls, "nvm deactivate", "should run deactivate before uninstall")

			// Verify deactivate comes before uninstall
			var deactIdx, uninstallIdx int
			for i, call := range calls {
				if strings.Contains(call, "deactivate") {
					deactIdx = i
				}
				if strings.Contains(call, "uninstall") {
					uninstallIdx = i
				}
			}
			assert.Less(t, deactIdx, uninstallIdx, "deactivate should run before uninstall")

			output := out.String()
			assert.Contains(t, output, "removed v24.16.0", "should report success")
		})

		t.Run("deactivate broken", func(t *testing.T) {
			nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected", map[string]string{
				"ALIASES":    "default:v24.22.1",
				"ACTIVE":     "v24.16.0",
				"DEACTIVATE": "broken", // Deactivate doesn't help
			})
			env := setupNodeFixTest(t, nvmDir)

			k := New()
			findings, err := k.Audit(ctx, env)
			require.NoError(t, err)

			fixer := k.(kinds.Fixer)
			fixes, err := fixer.Plan(ctx, env, findings)
			require.NoError(t, err)

			var out bytes.Buffer
			runner := exec.NewRealRunner()
			fakePriv := privilege.NewFakeEscalator()
			fakePriv.IsRootVal = true

			s := &fixrun.Session{
				Run:     runner,
				Prompt:  &testPrompt{confirmAnswers: []bool{true, true}, confirmAgreeAnswers: []bool{true}},
				Priv:    fakePriv,
				Host:    platform.Host{OS: "darwin"},
				DryRun:  false,
				Yes:     false,
				Color:   false,
				Out:     &out,
				Stamp:   "20260101120000",
				TempDir: env.TempDir,
			}

			result := fixes[0].Run(ctx, s)

			assert.Equal(t, fixrun.Changed, result) // Install succeeded
			assert.True(t, nodeInstalled(nvmDir, "24.16.0"), "old version should still be there")

			output := out.String()
			assert.Contains(t, output, "Cannot uninstall currently-active", "should show nvm's message")
			assert.Contains(t, output, "open a NEW shell", "should tell user how to finish")
			assert.NotContains(t, output, "removed v24.16.0", "should not claim success")
		})
	})

	t.Run("several old versions", func(t *testing.T) {
		// Scenario 15: two old versions on one major line: ONE upgrade, separate prompt for each old version
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected", map[string]string{
			"DEFAULT": "22.0.0",
			"ALIASES": "default:v22.0.0",
			"EXTRA":   "v24.10.0", // Another old 24.x version
		})
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)
		require.Len(t, fixes, 1, "should plan exactly one fix for the 24.x line")

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true}, confirmAgreeAnswers: []bool{true, false}},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		assert.Equal(t, fixrun.Changed, result)

		calls := readNvmCalls(nvmDir)
		installCount := 0
		for _, call := range calls {
			if strings.Contains(call, "nvm install") {
				installCount++
			}
		}
		assert.Equal(t, 1, installCount, "should install once, not once per old version")

		// Check that the fixed version is installed
		assert.True(t, nodeInstalled(nvmDir, "24.22.1"), "fixed version should be installed")

		// Check that exactly one old version was removed (the test answers true to first prompt, false to second)
		uninstallCount := 0
		for _, call := range calls {
			if strings.Contains(call, "nvm uninstall") {
				uninstallCount++
			}
		}
		assert.Equal(t, 1, uninstallCount, "should uninstall exactly one old version")

		// One version should remain (we only uninstalled one of the two old versions)
		// Count how many 24.x versions are still installed
		remaining := 0
		versionsDir := filepath.Join(nvmDir, "versions", "node")
		entries, _ := os.ReadDir(versionsDir)
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "v24.") && nodeInstalled(nvmDir, strings.TrimPrefix(entry.Name(), "v")) {
				remaining++
			}
		}
		assert.Equal(t, 2, remaining, "should have 2 v24.x versions remaining: the fixed one + one unremoved old one")
	})
}

// TestNodeFixSafety tests the safety properties of the Node fix.
func TestNodeFixSafety(t *testing.T) {
	ctx := context.Background()

	t.Run("dry-run runs no nvm command", func(t *testing.T) {
		// Mutation (c): make s.DryRun still apply
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected")
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true, true}},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  true,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		// Must be Skipped, not Changed
		assert.Equal(t, fixrun.Skipped, result, "dry run must return Skipped, not Changed")

		// Verify no nvm calls happened
		calls := readNvmCalls(nvmDir)
		assert.Empty(t, calls, "dry run should not execute any nvm commands")
	})

	t.Run("failed probe verification returns Failed", func(t *testing.T) {
		// Failed verification after install
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "trusted")
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true, true}},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		assert.Equal(t, fixrun.Failed, result, "failed verification must return Failed")
		assert.Contains(t, out.String(), "does not reject the chain")
	})

	t.Run("uninstall without deactivate", func(t *testing.T) {
		// Mutation (g): uninstall without deactivate should fail when active
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected", map[string]string{
			"ALIASES":    "default:v24.22.1",
			"ACTIVE":     "v24.16.0",
			"DEACTIVATE": "broken", // Simulate deactivate not working
		})
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true, true}, confirmAgreeAnswers: []bool{true}},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		// Install succeeded but removal failed
		assert.Equal(t, fixrun.Changed, result)
		assert.True(t, nodeInstalled(nvmDir, "24.16.0"), "version should still be there when deactive broken")

		// nvm deactivate should have been called
		calls := readNvmCalls(nvmDir)
		assert.Contains(t, calls, "nvm deactivate", "should attempt deactivate before uninstall")
	})

	t.Run("remove a version that is the default", func(t *testing.T) {
		// Mutation (h): remove a version that is the default
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected", map[string]string{
			"DEFAULT": "24.16.0", // Old version is still default
			"ALIASES": "default:v24.16.0",
		})
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		// Decline changing the default, so old stays default
		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true, false}},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		assert.Equal(t, fixrun.Changed, result)
		assert.True(t, nodeInstalled(nvmDir, "24.16.0"), "default version should be kept")
		assert.Contains(t, out.String(), "keeping v24.16.0: it is your nvm default")
	})

	t.Run("remove a version that has an alias", func(t *testing.T) {
		// Mutation (h): remove a version that has an alias pointing to it
		nvmDir := makeFakeNvmEnv(t, "24.16.0", "24.22.1", "rejected", map[string]string{
			"DEFAULT": "22.0.0",
			"ALIASES": "work:v24.16.0", // Alias points to old version
		})
		env := setupNodeFixTest(t, nvmDir)

		k := New()
		findings, err := k.Audit(ctx, env)
		require.NoError(t, err)

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(ctx, env, findings)
		require.NoError(t, err)

		var out bytes.Buffer
		runner := exec.NewRealRunner()
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true

		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{confirmAnswers: []bool{true}},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(ctx, s)

		assert.Equal(t, fixrun.Changed, result)
		assert.True(t, nodeInstalled(nvmDir, "24.16.0"), "aliased version should be kept")
		assert.Contains(t, out.String(), "aliases point at it: work")
	})
}

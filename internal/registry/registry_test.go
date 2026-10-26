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

package registry

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

// hosts covers macOS, every Linux family the Kinds branch on, and BSD.
func hosts() []platform.Host {
	var hs []platform.Host
	hs = append(hs, testutil.NewDarwinHost(), testutil.NewLinuxHost(),
		platform.Host{OS: "freebsd"}, platform.Host{OS: "netbsd"})
	for _, f := range []platform.Family{platform.FamilyDebian, platform.FamilyRedHat, platform.FamilyAlpine, platform.FamilyArch, platform.FamilySUSE, platform.FamilyOther} {
		hs = append(hs, platform.Host{OS: "linux", Arch: "amd64", Family: f})
	}
	return hs
}

// TestKindContract holds every registered Kind to the same rules.
func TestKindContract(t *testing.T) {
	all := All()
	require.NotEmpty(t, all, "the registry must not be empty")

	seen := map[string]bool{}
	for _, k := range all {
		t.Run(k.ID(), func(t *testing.T) {
			assert.NotEmpty(t, k.ID())
			assert.NotEmpty(t, k.Describe())
			assert.False(t, seen[k.ID()], "duplicate Kind ID %q", k.ID())
			seen[k.ID()] = true

			for _, h := range hosts() {
				app := k.Applicable(h)
				if !app.Applies {
					assert.NotEmpty(t, app.Reason, "%s on %s/%s must say why it does not apply", k.ID(), h.OS, h.Family)
				}
			}
		})
	}
}

// absolutePathKinds probe fixed absolute locations (for example
// /usr/local/go, /opt/homebrew, /etc/ssl, /Applications) as the script does.
// Those are real-filesystem reads that an empty PATH and HOME cannot hide, so
// these Kinds are exempt from the "finds nothing" check below. A filesystem
// root that tests can redirect would remove the exemption; until then it is a
// known gap, listed here so it stays visible.
var absolutePathKinds = map[string]bool{
	"golang": true, "brew": true, "sysbundle": true, "ospkg": true, "electron": true,
	"curl": true, "git": true, // /usr/bin/curl and /usr/bin/git, as the script lists them
}

// TestAuditIsHermetic runs every Kind's Audit against an empty environment.
// With no PATH and no HOME nothing reachable through them can be discovered,
// so a Kind outside absolutePathKinds that reports a finding is reading the
// real machine.
func TestAuditIsHermetic(t *testing.T) {
	for _, k := range All() {
		for _, h := range hosts() {
			if !k.Applicable(h).Applies {
				continue
			}
			t.Run(k.ID()+"/"+h.OS+"/"+string(h.Family), func(t *testing.T) {
				env := testutil.NewTestEnvWithHost(h)
				env.Environ = map[string]string{"PATH": t.TempDir(), "HOME": t.TempDir()}
				env.Offline = true
				findings, err := k.Audit(testutil.Context(), env)
				require.NoError(t, err)
				for _, f := range findings {
					if absolutePathKinds[k.ID()] {
						continue
					}
					t.Errorf("%s found %q at %q with an empty environment: it is reading the real machine", k.ID(), f.Tool, f.Path)
				}
			})
		}
	}
}

func TestByIDAndIDs(t *testing.T) {
	assert.Nil(t, ByID("nonexistent"))
	for _, id := range IDs() {
		k := ByID(id)
		require.NotNil(t, k, id)
		assert.Equal(t, id, k.ID())
	}
}

func TestValidateOnly(t *testing.T) {
	assert.NoError(t, ValidateOnly(nil))
	assert.NoError(t, ValidateOnly([]string{"sys", "python", "ospkg"}))
	err := ValidateOnly([]string{"python", "bogus"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--only must be one of")
	assert.Contains(t, err.Error(), "sys")
}

func TestExpandAliases(t *testing.T) {
	assert.Equal(t, []string{}, ExpandAliases(nil))
	assert.Equal(t, []string{"sysbundle", "ospkg"}, ExpandAliases([]string{"sys"}))
	assert.Equal(t, []string{"python", "sysbundle", "ospkg", "brew"}, ExpandAliases([]string{"python", "sys", "brew"}))
}

func TestValidOnlyValuesSortedAndIncludesAlias(t *testing.T) {
	v := ValidOnlyValues()
	assert.Contains(t, v, "sys")
	assert.IsIncreasing(t, v)
}

// A Kind that has a Plan method but is missing another method of kinds.Fixer
// (here FixOrder, added after some Kinds were written) is silently NOT a Fixer:
// the runner skips it and its fix never runs, and nothing else fails. Catch it.
func TestAKindWithAPlanIsAFixer(t *testing.T) {
	type planner interface {
		Plan(ctx context.Context, env *kinds.Env, findings []kinds.Finding) ([]fixrun.Fix, error)
	}
	for _, k := range All() {
		if _, hasPlan := k.(planner); !hasPlan {
			continue
		}
		_, isFixer := k.(kinds.Fixer)
		assert.True(t, isFixer, "%s has Plan but is not a kinds.Fixer: its fix would never run", k.ID())
	}
}

// Every Kind that can fix must be ordered by one of the script's Fix* constants.
func TestEveryFixerHasAKnownFixOrder(t *testing.T) {
	known := map[int]bool{
		kinds.FixBrew: true, kinds.FixSys: true, kinds.FixJava: true, kinds.FixMacPip: true, kinds.FixNode: true,
		kinds.FixUV: true, kinds.FixUVPython: true, kinds.FixUVTools: true, kinds.FixRustup: true,
	}
	for _, k := range All() {
		if f, ok := k.(kinds.Fixer); ok {
			assert.True(t, known[f.FixOrder()], "%s has FixOrder %d, which is not one of the kinds.Fix* constants", k.ID(), f.FixOrder())
		}
	}
}

// Plan receives the findings of EVERY Kind. A Fixer that acts on any finding with
// HasFix set would plan a fix for another tool's finding: uv would try to
// "self update" /usr/bin/python3, and Homebrew would upgrade on the strength of
// Python's version. Only the fixers that are cross-Kind by design may react to a
// foreign finding, and only through the flag the script uses for that:
//
//	macpip  — a Python finding with NeedsPipGuidance (the script's FIXPIP)
//	sys     — sysbundle (macOS) and ospkg (Linux) on NeedsSystemGuidance (FIXSYS)
//
// Every other Fixer must plan nothing from findings that are not its own.
func TestFixersIgnoreOtherKindsFindings(t *testing.T) {
	// A foreign finding shaped to be as acceptable as possible to each fixer: a path
	// that looks like an nvm node, a standalone uv (with the receipt that makes it
	// one), and a Homebrew ca-certificates, all under a temp HOME. If a fixer does
	// not check whose finding it is, one of these will get through its other guards.
	home := t.TempDir()
	nvmNode := filepath.Join(home, ".nvm", "versions", "node", "v22.0.0", "bin", "node")
	uvBin := filepath.Join(home, ".local", "bin", "uv")
	receipt := filepath.Join(home, ".config", "uv", "uv-receipt.json")
	for _, p := range []string{nvmNode, uvBin} {
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755))
	}
	require.NoError(t, os.MkdirAll(filepath.Dir(receipt), 0o755))
	require.NoError(t, os.WriteFile(receipt, []byte(`{"install_prefix": "`+filepath.Dir(uvBin)+`"} "`+filepath.Dir(uvBin)+`"`), 0o644))
	brewOpt := filepath.Join(home, "homebrew", "opt", "ca-certificates")

	var foreign []kinds.Finding
	for _, path := range []string{nvmNode, uvBin, brewOpt, "/usr/bin/python3"} {
		f := kinds.NewFinding("some-other-kind", "Some Tool")
		f.Path = path
		f.Version = "22.0.0"
		f.HasFix = true
		f.SetProbe(kinds.ProbeTrusted, "")
		f.SetVersion("22.0.0", "99.0.0", kinds.VersionBehind, "fixed in 99.0.0")
		// deliberately NOT NeedsSystemGuidance / NeedsPipGuidance: those are the sanctioned triggers
		foreign = append(foreign, f)
	}

	for _, k := range All() {
		fx, ok := k.(kinds.Fixer)
		if !ok {
			continue
		}
		for _, h := range hosts() {
			env := testutil.NewTestEnvWithHost(h)
			env.Environ = map[string]string{"HOME": home, "PATH": filepath.Dir(uvBin), "XDG_CONFIG_HOME": filepath.Join(home, ".config"), "NVM_DIR": filepath.Join(home, ".nvm")}
			fixes, err := fx.Plan(context.Background(), env, foreign)
			require.NoError(t, err)
			assert.Empty(t, fixes, "%s planned a fix from another Kind's finding on %s/%s", k.ID(), h.OS, h.Family)
		}
	}
}

// The sanctioned cross-Kind triggers still work, and only for the right host.
func TestSanctionedCrossKindTriggers(t *testing.T) {
	ask := kinds.NewFinding("curl", "curl")
	ask.SetProbe(kinds.ProbeTrusted, "")
	ask.NeedsSystemGuidance = true

	planned := func(h platform.Host) (ids []string) {
		for _, k := range All() {
			if fx, ok := k.(kinds.Fixer); ok {
				fixes, err := fx.Plan(context.Background(), testutil.NewTestEnvWithHost(h), []kinds.Finding{ask})
				require.NoError(t, err)
				if len(fixes) > 0 {
					ids = append(ids, k.ID())
				}
			}
		}
		return ids
	}
	assert.Equal(t, []string{"sysbundle"}, planned(testutil.NewDarwinHost()), "macOS: sysbundle patches /etc/ssl/cert.pem")
	assert.Equal(t, []string{"ospkg"}, planned(testutil.NewLinuxHost()), "Debian-family Linux: ospkg edits ca-certificates.conf")
	assert.Empty(t, planned(platform.Host{OS: "freebsd"}), "no automated fix for other platforms")
}

// Every Kind that audits has a report section; the ones that only fix have none.
func TestSectionTitlesCoverExactlyTheAuditingKinds(t *testing.T) {
	fixOnly := map[string]bool{"uvpython": true, "uvtools": true, "macpip": true}
	for _, k := range All() {
		if fixOnly[k.ID()] {
			assert.Empty(t, SectionTitle(k.ID()), "%s only fixes, so it has no section", k.ID())
		} else {
			assert.NotEmpty(t, SectionTitle(k.ID()), "%s audits, so it needs a section title", k.ID())
		}
	}
	for id := range titles {
		assert.NotNil(t, ByID(id), "title for unknown Kind %s", id)
	}
}

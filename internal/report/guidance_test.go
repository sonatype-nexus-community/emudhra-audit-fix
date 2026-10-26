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

package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
)

func linux(id, like string) platform.Host {
	return platform.Host{OS: "linux", Distro: platform.Distro{ID: id, IDLike: like}}
}

// TestSystemGuidanceRecipes pins the per-OS recipe each host gets, checked
// against the script's print_sys_guidance().
func TestSystemGuidanceRecipes(t *testing.T) {
	tests := []struct {
		name string
		host platform.Host
		want []string
		not  []string
	}{
		{"macOS", platform.Host{OS: "darwin"}, []string{"    macOS - /etc/ssl/cert.pem", "sudo cp -p /etc/ssl/cert.pem /etc/ssl/cert.pem.bak"}, []string{"Debian"}},
		{"Debian", linux("debian", ""), []string{"    Debian / Ubuntu (run as root):", "/etc/ca-certificates.conf && update-ca-certificates"}, []string{"macOS"}},
		{"Ubuntu via ID_LIKE", linux("pop", "ubuntu debian"), []string{"    Debian / Ubuntu (run as root):"}, nil},
		{"Fedora", linux("fedora", ""), []string{"    Fedora / RHEL / CentOS", "update-ca-trust"}, nil},
		{"Amazon Linux", linux("amzn", "fedora"), []string{"    Fedora / RHEL / CentOS"}, nil},
		{"openSUSE", linux("opensuse-leap", "suse opensuse"), []string{"    openSUSE / SLES (run as root):", "update-ca-certificates"}, nil},
		{"Arch", linux("arch", ""), []string{"    Arch Linux (run as root):", "trust-source/blocklist/emSign_ECC_Root_CA_-_G3.pem"}, nil},
		{"Alpine", linux("alpine", ""), []string{"    Alpine:", "apk add ca-certificates"}, nil},
		{"NixOS", linux("nixos", ""), []string{"    NixOS (configuration.nix):", `"Comodo AAA Services root"`}, nil},
		{"FreeBSD", platform.Host{OS: "freebsd"}, []string{"    FreeBSD 14+ (run as root):", "certctl rehash"}, nil},
		{"NetBSD", platform.Host{OS: "netbsd"}, []string{"    NetBSD 10+ (run as root):", "certctl untrust"}, nil},
		{"unknown", linux("plan9", ""), []string{"    No recipe for this platform here - see https://emudhra.we-have-a-problem.com/ ."}, []string{"Debian"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := strings.Join(SystemGuidance(tt.host), "\n")
			assert.Contains(t, out, "  System trust store (for tools that read the OS CA bundle)", "header")
			assert.Contains(t, out, "'AAA Certificate")
			for _, w := range tt.want {
				assert.Contains(t, out, w)
			}
			for _, n := range tt.not {
				assert.NotContains(t, out, n)
			}
		})
	}
}

func TestSystemGuidanceRecipeIsExact(t *testing.T) {
	got := SystemGuidance(linux("debian", ""))
	assert.Equal(t, []string{
		"    Debian / Ubuntu (run as root):",
		"      sed -i \\",
		"        -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \\",
		"        -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' \\",
		"        /etc/ca-certificates.conf && update-ca-certificates",
		"",
	}, got[6:], "the Debian recipe must be the script's text, byte for byte")
}

func TestPipGuidance(t *testing.T) {
	out := strings.Join(PipGuidance(), "\n")
	assert.Contains(t, out, "  Built-in pip (macOS)")
	assert.Contains(t, out, `os.environ.setdefault("PIP_CERT", "/etc/ssl/cert.pem")`)
	assert.Contains(t, out, "use Homebrew Python or a virtualenv with pip >= 26.2.2.")
}

func affectedWith(tool, ver, compact string, full ...string) kinds.Finding {
	f := kinds.NewFinding("k", tool)
	f.Path = "/p/" + tool
	f.SetProbe(kinds.ProbeTrusted, "")
	f.SetVersion(ver, "", kinds.VersionBehind, "fixed in 9")
	f.AddGuidance(compact, full...)
	return f
}

func behindProtected(tool, ver, compact string) kinds.Finding {
	f := kinds.NewFinding("k", tool)
	f.Path = "/p/" + tool
	f.SetProbe(kinds.ProbeRejected, "")
	f.SetVersion(ver, "", kinds.VersionBehind, "fixed in 9")
	f.AddGuidance(compact, compact)
	return f
}

func render(t *testing.T, r *Reporter, fs []kinds.Finding) string {
	t.Helper()
	var buf bytes.Buffer
	r.Output = &buf
	require.NoError(t, r.Report(fs))
	return buf.String()
}

func TestCompactGuidance(t *testing.T) {
	a := affectedWith("node", "22.0.0", "nvm install 22.23.4", "nvm install 22.23.4")
	a.HasFix = true
	b := behindProtected("uv", "0.13.0", "uv self update")
	ok := kinds.NewFinding("k", "curl")
	ok.SetProbe(kinds.ProbeRejected, "")

	out := render(t, &Reporter{}, []kinds.Finding{a, b, ok})
	assert.Contains(t, out, "Fix first (nothing has been run; -v shows full commands)\n  - node 22.0.0: nvm install 22.23.4\n")
	assert.Contains(t, out, "Protected, but older than the fixed release\n  - uv 0.13.0: uv self update\n")
	assert.Contains(t, out, "Apply fixes: emudhra-audit-fix --fix --dry-run   (shows every step, changes nothing), then --fix\n")
	guidance := out[strings.Index(out, "Fix first"):]
	assert.NotContains(t, guidance, "curl", "a protected, current tool needs no guidance")
}

func TestCompactGuidanceFirstLineOfSeveral(t *testing.T) {
	a := kinds.NewFinding("k", "go")
	a.SetProbe(kinds.ProbeTrusted, "")
	a.GuidanceFull = []string{"  first step", "  second step"}
	out := render(t, &Reporter{}, []kinds.Finding{a})
	assert.Contains(t, out, "  - go : first step ... (-v for the rest)\n")
}

func TestCompactSystemLineOnlyWhenRequested(t *testing.T) {
	a := affectedWith("curl", "8.7.1", "patch the system CA bundle")
	without := render(t, &Reporter{}, []kinds.Finding{a})
	assert.NotContains(t, without, "System CA bundle: upgrade your OS CA package")

	a.NeedsSystemGuidance = true
	with := render(t, &Reporter{}, []kinds.Finding{a})
	assert.Contains(t, with, "  - System CA bundle: upgrade your OS CA package, or distrust the two roots (recipe for this platform with -v)\n")
}

func TestVerboseGuidanceStructure(t *testing.T) {
	a := affectedWith("curl", "8.7.1", "patch", "    patch the system CA bundle")
	a.NeedsSystemGuidance = true
	a.NeedsPipGuidance = true
	b := behindProtected("uv", "0.13.0", "uv self update")
	c := affectedWith("git", "2.50.1", "patch", "    patch the system CA bundle")
	c.NeedsSystemGuidance = true

	out := render(t, &Reporter{Verbose: 1, Host: linux("debian", "")}, []kinds.Finding{a, b, c})
	assert.Contains(t, out, "== Remediation guidance ==")
	assert.Contains(t, out, "  This is guidance only; nothing below has been run. Commands that edit system trust\n")
	assert.Contains(t, out, "Affected - fix these first")
	assert.Contains(t, out, "Protected today, but older than the fixed release - upgrade when convenient")
	assert.Contains(t, out, "  After changing anything, re-run this script to confirm.\n")
	// the shared blocks print once even though two findings asked for the system block
	assert.Equal(t, 1, strings.Count(out, "  System trust store (for tools that read the OS CA bundle)"))
	assert.Equal(t, 1, strings.Count(out, "  Built-in pip (macOS)"))
	assert.Less(t, strings.Index(out, "Affected - fix these first"), strings.Index(out, "System trust store"))
	assert.Less(t, strings.Index(out, "Built-in pip"), strings.Index(out, "Protected today"))
}

func TestFixModeWording(t *testing.T) {
	a := affectedWith("curl", "8.7.1", "patch", "    patch")
	a.HasFix = true
	out := render(t, &Reporter{Verbose: 1, FixMode: true}, []kinds.Finding{a})
	assert.Contains(t, out, "nothing below has been run yet.")
	assert.NotContains(t, out, "--fix --dry-run", "no 'apply fixes' hint once --fix is already given")

	out = render(t, &Reporter{Verbose: 1}, []kinds.Finding{a})
	assert.Contains(t, out, "This script can apply some of these for you")
}

func TestNoGuidanceFlagSuppressesEverything(t *testing.T) {
	a := affectedWith("curl", "8.7.1", "patch", "    patch")
	a.NeedsSystemGuidance = true
	for _, v := range []int{0, 1} {
		out := render(t, &Reporter{Verbose: v, NoGuidance: true}, []kinds.Finding{a})
		assert.NotContains(t, out, "Fix first")
		assert.NotContains(t, out, "Remediation guidance")
		assert.NotContains(t, out, "System trust store")
	}
}

func TestNoGuidanceBlockWhenNothingToFix(t *testing.T) {
	ok := kinds.NewFinding("k", "curl")
	ok.SetProbe(kinds.ProbeRejected, "")
	unknown := kinds.NewFinding("k", "py")
	out := render(t, &Reporter{Verbose: 1}, []kinds.Finding{ok, unknown})
	assert.NotContains(t, out, "Remediation guidance")
}

func TestLikelyAffectedGetsGuidance(t *testing.T) {
	f := kinds.NewFinding("k", "go")
	f.SetProbe(kinds.ProbeSkipped, "--no-network")
	f.SetVersion("1.26.4", "1.26.10", kinds.VersionBehind, "fixed in 1.26.10")
	f.AddGuidance("upgrade Go to 1.26.10", "  upgrade Go")
	out := render(t, &Reporter{}, []kinds.Finding{f})
	assert.Contains(t, out, "Fix first")
	assert.Contains(t, out, "go 1.26.4: upgrade Go to 1.26.10")
}

// The script prints each guidance line indented 6 spaces and a blank line after each entry;
// Kinds supply bare text, so the layout is the report's job.
func TestVerboseGuidanceLinesAreIndentedAndEntriesSeparated(t *testing.T) {
	a := kinds.NewFinding("k", "go")
	a.Version = "1.26.4"
	a.Path = "/usr/local/go/bin/go"
	a.SetProbe(kinds.ProbeTrusted, "")
	a.GuidanceFull = []string{"Upgrade Go", "  already indented"}
	b := kinds.NewFinding("k", "node")
	b.Version = "22.0.0"
	b.Path = "/n"
	b.SetProbe(kinds.ProbeTrusted, "")
	b.GuidanceFull = []string{"nvm install 22"}

	out := render(t, &Reporter{Verbose: 1}, []kinds.Finding{a, b})

	assert.Contains(t, out, "  - go 1.26.4\n    /usr/local/go/bin/go\n      Upgrade Go\n      already indented\n\n  - node 22.0.0\n    /n\n      nvm install 22\n\n")
}

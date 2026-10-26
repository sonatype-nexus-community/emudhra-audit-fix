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

// Package python implements the audit logic for Python installations.
// It checks the default trust store, certifi bundle (if installed), and pip download behavior.
// This ports audit_python, python_candidates, pip_probe_all, fix_python, and print_pip_guidance
// from the legacy bash script.
package python

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/advisory"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/uvenv"
)

// SectionTitle is the audit_start title for Python, shown in verbose mode.
const SectionTitle = "Python"

// Kind implements kinds.Kind for Python installations.
type Kind struct{}

// New creates a new Python Kind.
func New() kinds.Kind {
	return &Kind{}
}

// ID returns the Kind identifier.
func (k *Kind) ID() string {
	return "python"
}

// Describe returns a one-line description.
func (k *Kind) Describe() string {
	return "Python interpreters and their trust stores (default, certifi, pip)"
}

// Applicable reports whether this Kind applies to the host.
// Python applies to both macOS and Linux.
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	return kinds.Applicability{
		Applies: true,
		Reason:  "",
	}
}

// PythonInfo holds extracted information from a Python interpreter.
type PythonInfo struct {
	Version        string
	BasePrefix     string
	Implementation string
	Certifi        string
	Pip            string
	CAFile         string
	OpenSSL        string
}

// Audit discovers and audits Python installations.
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	var findings []kinds.Finding
	seen := &discover.Seen{}

	// Ask uv where it keeps its managed Pythons and tools (uv_environment_dirs). The
	// script's UV_PYTHON_DIR and UV_TOOLS_DIR are internal shell variables set from uv's
	// answer, not variables a user sets; reading them from the environment meant no uv
	// managed Python was ever found.
	uvBinary, uvPythonDir, uvToolsDir := k.uvDirs(ctx, env, &findings)

	// Build a uvenv.Env for uv-managed Python inspection if uv is available.
	var uvEnv *uvenv.Env
	if uvBinary != "" {
		uvEnv = uvenv.NewEnv(env, uvBinary)
		uvEnv.WorkDir = env.TempDir
		// The directories uv reported, not the $HOME defaults NewEnv guesses: they differ whenever
		// uv is configured, and the sibling-install scan must look where the installs are.
		if uvPythonDir != "" {
			uvEnv.PythonDir = uvPythonDir
		}
		if uvToolsDir != "" {
			uvEnv.ToolDir = uvToolsDir
		}
	}

	// How many uv Pythons and uv tool environments were audited.
	uvPythonCount := 0
	uvToolCount := 0

	// Get candidate Python executables
	candidates := k.candidates(env, uvPythonDir, uvToolsDir)

	for _, p := range candidates {
		// Skip macOS /usr/bin/python3 if Xcode CLI tools not installed
		if p == "/usr/bin/python3" && env.Host.OS == "darwin" {
			// Check if xcode-select exists and works
			result := env.Run.Run(ctx, "/usr/bin/xcode-select", "-p")
			if result.ExitCode != 0 {
				// xcode-select not available, skip stub
				continue
			}
		}

		// Resolve symlinks
		resolved := discover.Resolve(p)
		envDir := filepath.Dir(filepath.Dir(resolved))

		// Determine deduplication key
		// Virtual environments and uv tool environments are deduped by environment directory
		// Regular Python installations are deduped by resolved path
		var key string
		isVenv := k.isVenv(envDir)
		isUVTool := uvToolsDir != "" && k.isUVToolEnv(envDir, uvToolsDir)

		if isVenv || isUVTool {
			key = "python-env:" + envDir
		} else {
			key = "python:" + resolved
		}

		if !seen.First(key) {
			continue
		}

		// Extract Python information
		info, err := k.extractPythonInfo(ctx, env, p)
		if err != nil {
			// Python 3.8+ required for probe script
			finding := kinds.NewFinding(k.ID(), "Python")
			finding.Path = p
			finding.SetProbe(kinds.ProbeInconclusive, "inconclusive:interpreter could not run the probe (Python 3.8+ needed)")
			findings = append(findings, finding)
			continue
		}

		// Determine tool name (use "Python" or "uv Python" or "uv tool: <name> Python")
		toolName := "Python"
		toolEnvName := ""
		if uvPythonDir != "" && strings.HasPrefix(resolved, uvPythonDir) {
			toolName = "uv Python"
			uvPythonCount++
		}
		if isUVTool {
			toolEnvName = filepath.Base(envDir)
			toolName = "uv tool: " + toolEnvName + " Python"
			uvToolCount++
		}

		// Check tool name safety for uv tool environments
		if toolEnvName != "" && !uvToolNameSafe(toolEnvName) {
			finding := kinds.NewFinding(k.ID(), toolName)
			finding.Path = p
			finding.Version = info.Version
			finding.SetProbe(kinds.ProbeInconclusive, "inconclusive:unsupported tool name; cannot safely plan an upgrade")
			findings = append(findings, finding)
			continue
		}

		// Create finding
		finding := kinds.NewFinding(k.ID(), toolName)
		finding.Path = p

		// Resolve baseprefix for uv-managed Python checks
		baseprefix := info.BasePrefix
		if baseprefix != "" {
			if resolvedDir, err := filepath.EvalSymlinks(baseprefix); err == nil {
				baseprefix = resolvedDir
			}
		}

		// For uv-managed Pythons and uv tool environments, compute patch availability
		var minor, newestInstalled, latestPatch string
		var isSelected, patchAvailable bool
		isUVPython := toolName == "uv Python"
		isUVToolEnv := toolEnvName != ""

		if uvEnv != nil && (isUVPython || isUVToolEnv) && info.Implementation == "cpython" {
			m := uvEnv.ManagedMinor(baseprefix, info.Version, info.Implementation)
			if m != "" {
				minor = m
				// Get newest installed patch for this minor
				new, err := uvEnv.PythonNewestInstalled(ctx, baseprefix, info.Version)
				if err == nil && new != "" {
					newestInstalled = new
				} else {
					newestInstalled = info.Version
				}

				if isUVPython {
					// Check if this is the selected/preferred Python for this minor
					// Only an older patch can be "still selected" (script: ! ver_ge pv newest && ...).
					isSelected = !k.versionGE(info.Version, newestInstalled) &&
						uvEnv.PythonIsSelected(ctx, baseprefix, info.Version)

					// Get latest available patch from catalogue
					latest, err := uvEnv.PythonLatest(ctx, baseprefix, info.Version)
					if err == nil {
						latestPatch = latest
					}

					// Determine if patch is available
					if latestPatch != "" && latestPatch != "unknown" && newestInstalled != "" {
						patchAvailable = compareVersions(latestPatch, newestInstalled) > 0
					}
				}
			}
		}

		// Build version notes for patch availability (uv Python only)
		var uvNotes []string

		// Version checks for certifi and pip
		var certifiCheck, pipCheck kinds.VersionCheck
		var certifiNote, pipNote string
		var versionNotes []string

		// Check certifi version
		if info.Certifi != "" {
			if advisory.IsFixed("certifi", info.Certifi) {
				certifiCheck = kinds.VersionOK
				certifiNote = fmt.Sprintf("certifi %s ok", info.Certifi)
			} else {
				certifiCheck = kinds.VersionBehind
				certifiNote = fmt.Sprintf("certifi %s < 2026.10.19", info.Certifi)
			}
			versionNotes = append(versionNotes, certifiNote)
		}

		// Check pip version
		if info.Pip != "" {
			if advisory.IsFixed("pip", info.Pip) {
				pipCheck = kinds.VersionOK
				pipNote = fmt.Sprintf("pip %s ok", info.Pip)
			} else {
				pipCheck = kinds.VersionBehind
				pipNote = fmt.Sprintf("pip %s < 26.2.2", info.Pip)
			}
			versionNotes = append(versionNotes, pipNote)
		}

		// Set version info - use the worst of certifi/pip
		overallCheck := kinds.VersionNA
		if certifiCheck == kinds.VersionBehind || pipCheck == kinds.VersionBehind {
			overallCheck = kinds.VersionBehind
		} else if certifiCheck == kinds.VersionOK || pipCheck == kinds.VersionOK {
			overallCheck = kinds.VersionOK
		}

		fixedVersion := ""
		if overallCheck == kinds.VersionBehind {
			fixedVersion = "certifi>=2026.10.19, pip>=26.2.2"
		}

		finding.SetVersion(info.Version, fixedVersion, overallCheck, strings.Join(versionNotes, "; "))

		// Run probes (unless offline)
		var res1, res2, res3 probe.Verdict
		var evidence []string

		if env.Offline {
			res1 = probe.VerdictSkipped
			res2 = probe.VerdictSkipped
			res3 = probe.VerdictSkipped
		} else {
			// Probe default trust store
			res1 = k.probeDefaultStore(ctx, env, p)

			// Probe certifi bundle (if installed)
			if info.Certifi != "" {
				res2 = k.probeCertifi(ctx, env, p)
			} else {
				res2 = probe.VerdictSkipped
			}

			// Probe pip download (if pip is installed)
			if info.Pip != "" {
				res3 = k.probePip(ctx, env, p)
			} else {
				res3 = probe.VerdictSkipped
			}
		}

		// The detail block of the script's report(): one line per trust path, then the OpenSSL
		// cafile; labels are padded to line the values up.
		evidence = append(evidence, fmt.Sprintf("default trust store: %s", probe.DescribeProbe(res1)))
		if res2 != probe.VerdictSkipped {
			evidence = append(evidence, fmt.Sprintf("certifi bundle:      %s", probe.DescribeProbe(res2)))
		}
		if res3 != probe.VerdictSkipped {
			evidence = append(evidence, fmt.Sprintf("pip download:        %s", probe.DescribeProbe(res3)))
		}

		cafileDisplay := info.CAFile
		if cafileDisplay == "" || cafileDisplay == "None" {
			cafileDisplay = "none"
		}
		evidence = append(evidence, fmt.Sprintf("OpenSSL cafile:      %s  (%s)", cafileDisplay, info.OpenSSL))

		// Combine probe results (probe wins over version)
		// The logic from the script combines all three probe results:
		// - Any trusted → affected
		// - All rejected → protected
		// - Any inconclusive → inconclusive
		// - Otherwise → skipped
		var res probe.Verdict
		if res1 == probe.VerdictTrusted || res2 == probe.VerdictTrusted || res3 == probe.VerdictTrusted {
			res = probe.VerdictTrusted
		} else if res1 == probe.VerdictRejected && (res2 == probe.VerdictRejected || res2 == probe.VerdictSkipped) && (res3 == probe.VerdictRejected || res3 == probe.VerdictSkipped) {
			res = probe.VerdictRejected
		} else if res1 == probe.VerdictInconclusive || res2 == probe.VerdictInconclusive || res3 == probe.VerdictInconclusive {
			res = probe.VerdictInconclusive
		} else {
			res = probe.VerdictSkipped
		}

		// For uv-managed Pythons and uv tool environments, use combine_uv_python_probe
		// which keeps an inconclusive component inconclusive unless something is trusted.
		if isUVPython || isUVToolEnv {
			res = k.combineUVPythonProbe(res1, res2, res3)
		}

		// Set probe result and evidence based on combined result
		var probeResult kinds.ProbeResult
		switch res {
		case probe.VerdictTrusted:
			probeResult = kinds.ProbeTrusted
		case probe.VerdictRejected:
			probeResult = kinds.ProbeRejected
		case probe.VerdictSkipped:
			probeResult = kinds.ProbeSkipped
		default:
			probeResult = kinds.ProbeInconclusive
		}

		finding.SetProbe(probeResult, probeReason(res))
		finding.Notes = detailBlock(env, evidence)

		// Add guidance based on probe results
		k.addGuidance(&finding, env.Host, p, info, res1, res2, res3, overallCheck)

		// Handle uv-managed Python and tool environment specifics
		needsUpdate := res == probe.VerdictTrusted || overallCheck == kinds.VersionBehind

		// uv tool environments
		if isUVToolEnv && toolEnvName != "" {
			// If there's a newer managed Python available, note it
			if minor != "" && !k.versionGE(info.Version, newestInstalled) {
				needsUpdate = true
				uvNotes = append(uvNotes, fmt.Sprintf("runtime: a newer managed Python %s is already installed; this tool can be rebuilt on that minor line", newestInstalled))
			}

			// Emit uvtools request if needs update
			if needsUpdate {
				finding.Requests = append(finding.Requests, kinds.FixRequest{
					Kind:   "uvtools",
					Target: toolEnvName,
				})
			}

			// If the default probe is trusted and we have a managed minor, also request uvpython upgrade
			if res1 == probe.VerdictTrusted && minor != "" && k.versionGE(info.Version, newestInstalled) {
				finding.Requests = append(finding.Requests, kinds.FixRequest{
					Kind:    "uvpython",
					Target:  minor,
					Minimum: latestPatch,
				})
			}

			// Add uv tool scope note
			uvNotes = append(uvNotes, "scope: Python TLS and installed certifi/pip only; application clients and native binaries are not probed")

			// Add guidance if needs update
			if needsUpdate {
				compact, full := uvToolUpgradeGuidance(toolEnvName)
				if finding.GuidanceCompact == "" {
					finding.GuidanceCompact = compact
				}
				finding.GuidanceFull = append(finding.GuidanceFull, full...)
			}
		} else if isUVPython && minor != "" {
			// uv-managed Python installations

			// Add update availability note
			uvNotes = append(uvNotes, uvUpdateNotes(latestPatch, newestInstalled))

			// Emit uvpython request if patch available, selected, or needs update with latest version
			if patchAvailable || isSelected || (needsUpdate && k.versionGE(info.Version, newestInstalled)) {
				// Set Minimum to the latest available patch
				minimum := latestPatch
				if isSelected {
					// For selected older patches, also request upgrade to newest installed
					finding.Requests = append(finding.Requests, kinds.FixRequest{
						Kind:    "uvpython",
						Target:  minor,
						Minimum: newestInstalled,
					})
					uvNotes = append(uvNotes, uvPreferredNote(newestInstalled))
				}
				finding.Requests = append(finding.Requests, kinds.FixRequest{
					Kind:    "uvpython",
					Target:  minor,
					Minimum: minimum,
				})

				// Add upgrade guidance
				compact, full := uvPythonUpgradeGuidance(minor)
				if finding.GuidanceCompact == "" {
					finding.GuidanceCompact = compact
				}
				finding.GuidanceFull = append(finding.GuidanceFull, full...)
			} else if !k.versionGE(info.Version, newestInstalled) {
				// Older retained patch
				uvNotes = append(uvNotes, uvRetainedNote(newestInstalled))
			}
		}

		// Add uv notes to finding
		if len(uvNotes) > 0 {
			if finding.Notes != "" {
				finding.Notes += "\n"
			}
			finding.Notes += noteIndent + strings.Join(uvNotes, "\n"+noteIndent)
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// candidates returns a list of candidate Python executables.
// This ports python_candidates from the bash script (lines 771-792).
func (k *Kind) candidates(env *kinds.Env, uvPythonDir, uvToolsDir string) []string {
	home := env.Home()

	// Build candidate patterns
	var patterns []string

	// PATH lookup
	pathEnv := env.Path()
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		patterns = append(patterns,
			filepath.Join(dir, "python"),
			filepath.Join(dir, "python[0-9]"),
			filepath.Join(dir, "python[0-9].[0-9]"),
			filepath.Join(dir, "python[0-9].[0-9][0-9]"),
		)
	}

	// System-wide directories - ONLY check in production mode (env.Environ == nil)
	// In hermetic mode (env.Environ set), we rely only on PATH and HOME env vars
	if env.Environ == nil {
		extraDirs := []string{
			"/opt/homebrew/bin",
			"/usr/local/bin",
		}

		// Add extra directories
		for _, dir := range extraDirs {
			patterns = append(patterns, filepath.Join(dir, "python*"))
		}

		// macOS Python framework
		patterns = append(patterns, filepath.Join("/Library/Frameworks/Python.framework", "Versions", "*", "bin", "python*"))
	}

	// User-specific directories - only if HOME is set
	if home != "" {
		// pyenv
		patterns = append(patterns, filepath.Join(home, ".pyenv", "versions", "*", "bin", "python*"))

		// asdf
		patterns = append(patterns, filepath.Join(home, ".asdf", "installs", "python", "*", "bin", "python*"))

		// mise
		patterns = append(patterns, filepath.Join(home, ".local", "share", "mise", "installs", "python", "*", "bin", "python*"))
	}

	// UV Python directory
	if uvPythonDir != "" {
		patterns = append(patterns, filepath.Join(uvPythonDir, "*", "bin", "python*"))
	}

	// Discover candidates
	var candidates []string
	for _, pattern := range patterns {
		matches := discover.Candidates(pattern)
		candidates = append(candidates, matches...)
	}

	// UV tools directory (special handling)
	var toolPython []string
	if uvToolsDir != "" {
		// Look for uv-receipt.toml in subdirectories
		// We need to use discover.Candidates or a file existence check
		receiptPattern := filepath.Join(uvToolsDir, "*", "uv-receipt.toml")
		receipts := discover.Candidates(receiptPattern)
		for _, receipt := range receipts {
			// Extract the tool directory from the receipt path
			toolDir := filepath.Dir(receipt)
			// A receipt marks an installed tool. The script lists its python even when the
			// executable is missing or broken, so the tool is reported as unknown rather
			// than silently skipped ("Include broken/missing Python executables").
			toolPython = append(toolPython, filepath.Join(toolDir, "bin", "python"))
		}
	}

	return append(interpreters(discover.Executables(candidates)), toolPython...)
}

// interpreters keeps only the files the script's python_candidates accepts:
//
//	python | python[0-9] | python[0-9].[0-9] | python[0-9].[0-9][0-9]
//
// The directories are globbed with python*, which also matches python3-config,
// python3.12-config and python3-intel64: helper scripts, not interpreters, that
// would each be reported as an unknown Python.
var interpreterName = regexp.MustCompile(`^python([0-9](\.[0-9]([0-9])?)?)?$`)

func interpreters(paths []string) []string {
	var out []string
	for _, p := range paths {
		if interpreterName.MatchString(filepath.Base(p)) {
			out = append(out, p)
		}
	}
	return out
}

// isVenv checks if a directory is a Python virtual environment.
func (k *Kind) isVenv(envDir string) bool {
	pyvenvCfg := filepath.Join(envDir, "pyvenv.cfg")
	return discover.IsExecutable(pyvenvCfg) || fileExists(pyvenvCfg)
}

// fileExists checks if a file exists (not necessarily executable).
func fileExists(path string) bool {
	// os.Stat, not filepath.Glob: Glob reports an error only for a malformed pattern, so
	// "err == nil" was true for every path, existing or not.
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// isUVToolEnv checks if an environment is a uv tool environment.
func (k *Kind) isUVToolEnv(envDir, uvToolsDir string) bool {
	if uvToolsDir == "" {
		return false
	}
	receiptPath := filepath.Join(envDir, "uv-receipt.toml")
	return fileExists(receiptPath)
}

// uvToolNameSafe checks if a uv tool name is safe for shell operations.
// This ports uv_tool_name_safe from the bash script.
func uvToolNameSafe(name string) bool {
	if name == "" {
		return false
	}
	// Check for invalid characters
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	// Check for leading dash or dot
	if name[0] == '-' || name[0] == '.' {
		return false
	}
	return true
}

// extractPythonInfo runs the Python probe script to extract interpreter information.
func (k *Kind) extractPythonInfo(ctx context.Context, env *kinds.Env, pythonPath string) (*PythonInfo, error) {
	// Create temporary probe script
	probeScript := k.pythonProbeScript()

	// Create temp directory
	tmpDir, err := os.MkdirTemp(env.TempDir, "emudhra-python-probe-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	probePath := filepath.Join(tmpDir, "probe.py")
	if err := os.WriteFile(probePath, []byte(probeScript), 0644); err != nil {
		return nil, err
	}

	// Run the probe script
	// The mode is passed as a command-line argument
	result := env.Run.Run(ctx, pythonPath, "-I", "-B", probePath, "info")
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("probe script failed: %s", result.Stderr)
	}

	// Parse output
	info := &PythonInfo{}
	lines := strings.Split(result.Stdout, "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]
		switch key {
		case "pyver":
			info.Version = value
		case "baseprefix":
			info.BasePrefix = value
		case "implementation":
			info.Implementation = value
		case "certifi":
			info.Certifi = value
		case "pip":
			info.Pip = value
		case "cafile":
			info.CAFile = value
		case "openssl":
			info.OpenSSL = value
		}
	}

	if info.Version == "" {
		return nil, fmt.Errorf("could not extract Python version")
	}

	return info, nil
}

// probeDefaultStore probes Python's default trust store.
func (k *Kind) probeDefaultStore(ctx context.Context, env *kinds.Env, pythonPath string) probe.Verdict {
	// Create temporary probe script
	probeScript := k.pythonProbeScript()

	tmpDir, err := os.MkdirTemp(env.TempDir, "emudhra-python-probe-*")
	if err != nil {
		return probe.VerdictInconclusive
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	probePath := filepath.Join(tmpDir, "probe.py")
	if err := os.WriteFile(probePath, []byte(probeScript), 0644); err != nil {
		return probe.VerdictInconclusive
	}

	// Run probe with URLs
	urls := append([]string{probe.CONTROL_URL}, probe.BAD_URLS...)
	args := []string{pythonPath, "-I", "-B", probePath, "default"}
	args = append(args, urls...)

	result := env.Run.Run(ctx, args[0], args[1:]...)

	// Parse output
	lines := strings.Split(result.Stdout, "\n")
	results := k.parseProbeResults(lines)

	return env.Probe.Judge(results)
}

// probeCertifi probes Python's certifi bundle.
func (k *Kind) probeCertifi(ctx context.Context, env *kinds.Env, pythonPath string) probe.Verdict {
	// Create temporary probe script
	probeScript := k.pythonProbeScript()

	tmpDir, err := os.MkdirTemp(env.TempDir, "emudhra-python-probe-*")
	if err != nil {
		return probe.VerdictInconclusive
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	probePath := filepath.Join(tmpDir, "probe.py")
	if err := os.WriteFile(probePath, []byte(probeScript), 0644); err != nil {
		return probe.VerdictInconclusive
	}

	// Run probe with certifi mode
	urls := append([]string{probe.CONTROL_URL}, probe.BAD_URLS...)
	args := []string{pythonPath, "-I", "-B", probePath, "certifi"}
	args = append(args, urls...)

	result := env.Run.Run(ctx, args[0], args[1:]...)

	// Parse output
	lines := strings.Split(result.Stdout, "\n")
	results := k.parseProbeResults(lines)

	return env.Probe.Judge(results)
}

// probePip probes pip's download behavior.
// This ports pip_probe_all from the bash script (lines 796-817).
func (k *Kind) probePip(ctx context.Context, env *kinds.Env, pythonPath string) probe.Verdict {
	// The bash script runs:
	//   python -I -B -m pip download --no-deps --no-input --disable-pip-version-check \
	//     --retries 0 --timeout 10 -d "$TMP/pipdl" --index-url "${u}simple/" emudhra-probe-does-not-exist
	//
	// We need to probe each index URL to check if pip accepts the certificate.
	// Any HTTP answer (even 404) means the TLS handshake was accepted.

	var results []probe.ProbeResult
	urls := append([]string{probe.CONTROL_URL}, probe.BAD_URLS...)

	for _, u := range urls {
		// Create temp directory for pip download
		tmpPipDir, err := os.MkdirTemp(env.TempDir, "pipdl-*")
		if err != nil {
			results = append(results, probe.ProbeResult{URL: u, Verdict: probe.VerdictInconclusive})
			continue
		}

		// Run pip download with the index URL
		indexURL := u + "simple/"
		args := []string{pythonPath, "-I", "-B", "-m", "pip", "download",
			"--no-deps", "--no-input", "--disable-pip-version-check",
			"--retries", "0", "--timeout", "10",
			"-d", tmpPipDir,
			"--index-url", indexURL,
			"emudhra-probe-does-not-exist"}

		result := env.Run.Run(ctx, args[0], args[1:]...)

		// Check for certificate errors
		stderr := result.Stderr + result.Stdout
		var verdict probe.Verdict
		if strings.Contains(stderr, "CERTIFICATE_VERIFY_FAILED") ||
			strings.Contains(stderr, "certificate verify failed") ||
			strings.Contains(stderr, "SSLCertVerificationError") ||
			strings.Contains(stderr, "problem confirming the ssl certificate") ||
			strings.Contains(stderr, "SSLError") {
			verdict = probe.VerdictRejected
		} else if result.ExitCode >= 128 ||
			strings.Contains(stderr, "NewConnectionError") ||
			strings.Contains(stderr, "Name or service not known") ||
			strings.Contains(stderr, "nodename nor servname") ||
			strings.Contains(stderr, "Temporary failure") ||
			strings.Contains(stderr, "ConnectTimeout") ||
			strings.Contains(stderr, "ReadTimeout") ||
			strings.Contains(stderr, "ProxyError") ||
			strings.Contains(stderr, "Connection refused") ||
			strings.Contains(stderr, "timed out") ||
			strings.Contains(stderr, "No module named") {
			verdict = probe.VerdictInconclusive
		} else {
			// Any HTTP answer (even 404) means the handshake was accepted
			verdict = probe.VerdictTrusted
		}

		results = append(results, probe.ProbeResult{URL: u, Verdict: verdict})

		// Clean up
		_ = os.RemoveAll(tmpPipDir)
	}

	return env.Probe.Judge(results)
}

// parseProbeResults parses probe output lines into ProbeResult slice.
func (k *Kind) parseProbeResults(lines []string) []probe.ProbeResult {
	var results []probe.ProbeResult
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		status, url := parts[0], parts[1]
		var verdict probe.Verdict
		switch status {
		case "ok":
			verdict = probe.VerdictTrusted
		case "certerr":
			verdict = probe.VerdictRejected
		default:
			verdict = probe.VerdictInconclusive
		}
		results = append(results, probe.ProbeResult{
			URL:     url,
			Verdict: verdict,
		})
	}
	return results
}

// addGuidance adds remediation guidance based on probe results.
// This ports fix_python from the bash script (lines 1162-1201).
func (k *Kind) addGuidance(finding *kinds.Finding, host platform.Host, p string, info *PythonInfo, res1, res2, res3 probe.Verdict, vc kinds.VersionCheck) {
	var compact []string
	var full []string

	// Default trust store affected - maps to FIXSYS
	if res1 == probe.VerdictTrusted {
		switch {
		case strings.Contains(info.CAFile, "/etc/ca-certificates/") ||
			strings.Contains(info.CAFile, "/etc/openssl") ||
			strings.Contains(info.CAFile, "/Cellar/"):
			compact = append(compact, "brew upgrade ca-certificates (this Python uses Homebrew's bundle)")
			full = append(full, "Uses Homebrew's CA bundle: brew update && brew upgrade ca-certificates")
		case info.CAFile == "" || info.CAFile == "None":
			full = append(full, "No default CA file is configured for this Python.")
		default:
			compact = append(compact, fmt.Sprintf("patch the system CA bundle (%s)", info.CAFile))
			full = append(full, fmt.Sprintf("Reads the OS CA bundle (%s): see System trust store below.", info.CAFile))
			// FIXSYS=1: when the guidance points at the system trust store
			// (script line 1182: "fix ... see System trust store below."; FIXSYS=1)
			finding.NeedsSystemGuidance = true
		}
	}

	// Certifi affected
	if res2 == probe.VerdictTrusted {
		compact = append(compact, "pip install --upgrade 'certifi>=2026.10.19'")
		full = append(full, "The certifi bundle trusts the compromised chain: python3 -m pip install --upgrade 'certifi>=2026.10.19'")
		full = append(full, "(use a virtualenv or pipx if the environment is externally managed)")
	}

	// Pip download affected
	if res3 == probe.VerdictTrusted {
		compact = append(compact, "upgrade pip to 26.2.2 or later")
		full = append(full, "pip itself accepts the compromised chain (it carries its own CA bundle): upgrade it to 26.2.2 or later.")
		full = append(full, "(PIP_CERT=/path/to/patched-bundle.pem is a stop-gap.)")
	}

	// Version behind
	if vc == kinds.VersionBehind {
		compact = append(compact, fmt.Sprintf("%s -m pip install --upgrade 'pip>=26.2.2' 'certifi>=2026.10.19'", p))
		full = append(full, fmt.Sprintf("Upgrade pip and certifi: %s -m pip install --upgrade 'pip>=26.2.2' 'certifi>=2026.10.19'", p))
	}

	// macOS built-in pip - maps to FIXPIP
	// Script lines 1196-1199: FIXPIP=1 when /usr/bin/python3 on darwin and affected
	if p == "/usr/bin/python3" && host.OS == "darwin" {
		if res1 == probe.VerdictTrusted || res3 == probe.VerdictTrusted || vc == kinds.VersionBehind {
			full = append(full, "Apple's built-in pip: see Built-in pip (macOS) below.")
			// FIXPIP=1: when macOS /usr/bin/python3 is affected (script line 1198)
			finding.NeedsPipGuidance = true
		}
	}

	// HasFix maps to plan_add in the script
	// Script sets HasFix when affected (status IsBad) and there's a known remediation path
	// Lines 350-351: plan_add sys/macpip when FIXSYS/FIXPIP are set
	// We set HasFix when we've set either shared guidance flag
	if finding.NeedsSystemGuidance || finding.NeedsPipGuidance {
		finding.HasFix = true
	}

	if len(compact) > 0 {
		finding.AddGuidance(compact[0], full...)
	} else if len(full) > 0 {
		finding.AddGuidance(full[0], full...)
	}
}

// pythonProbeScript returns the Python probe script.
// This ports the py_probe.py script from the bash script (lines 429-469).
func (k *Kind) pythonProbeScript() string {
	return `import os, sys, ssl

def meta(name):
    try:
        import importlib.metadata as m
        return m.version(name)
    except Exception:
        return ""

mode = sys.argv[1]
if mode == "info":
    print("pyver=%d.%d.%d" % sys.version_info[:3])
    print("baseprefix=" + os.path.realpath(sys.base_prefix))
    print("implementation=" + sys.implementation.name)
    print("certifi=" + meta("certifi"))
    print("pip=" + meta("pip"))
    print("cafile=" + str(ssl.get_default_verify_paths().cafile))
    print("openssl=" + ssl.OPENSSL_VERSION)
else:
    import urllib.request, urllib.error
    urls = sys.argv[2:]
    if mode == "certifi":
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    elif mode == "cafile":
        ctx = ssl.create_default_context(cafile=sys.argv[2])
        urls = sys.argv[3:]
    else:
        ctx = ssl.create_default_context()
    for u in urls:
        try:
            urllib.request.urlopen(u, timeout=10, context=ctx).read(1)
            r = "ok"
        except urllib.error.HTTPError:
            r = "ok"
        except Exception as e:
            r = "certerr" if "CERTIFICATE_VERIFY_FAILED" in str(e) else "err"
            sys.stderr.write("    error: %s\n" % e)
        print(r, u)
`
}

// uvDirs ports uv_environment_dirs: it asks uv for its Python and tool directories. When
// uv is installed but cannot answer, the script reports an inconclusive finding saying so
// rather than silently auditing nothing; so does this, appended to findings.
func (k *Kind) uvDirs(ctx context.Context, env *kinds.Env, findings *[]kinds.Finding) (uvBinary, pythonDir, toolsDir string) {
	uv := uvenv.FindUV(env)
	if uv == "" {
		return "", "", ""
	}
	ue := uvenv.NewEnv(env, uv)
	ue.WorkDir = env.TempDir
	for _, kind := range []string{"python", "tool"} {
		out, err := ue.Read(ctx, kind, "dir")
		if err != nil || out == "" || strings.Contains(out, "\n") {
			f := kinds.NewFinding(k.ID(), "uv "+kind+" discovery")
			f.Path = uv
			f.SetProbe(kinds.ProbeInconclusive, "uv could not report its "+kind+" directory; update uv or check its configuration")
			*findings = append(*findings, f)
			continue
		}
		dir, err := ue.AbsoluteDir(out)
		if err != nil {
			dir = out
		}
		if kind == "python" {
			pythonDir = dir
		} else {
			toolsDir = dir
		}
	}
	return uv, pythonDir, toolsDir
}

// Probes is what a Python interpreter reports about itself and how each of its trust paths
// behaves against the compromised chain.
type Probes struct {
	// Info is the interpreter's own metadata (version, implementation, certifi, pip ...).
	Info *PythonInfo
	// Default is the interpreter's default trust store.
	Default probe.Verdict
	// Certifi is the certifi bundle; empty when certifi is not installed.
	Certifi probe.Verdict
	// Pip is a pip download against each probe host; empty when pip is not installed.
	Pip probe.Verdict
}

// Interpret runs the same probes the audit runs on one interpreter, for the code that must
// verify a change (the uv Python fixer re-checks an interpreter after upgrading it). The
// error is non-nil when the interpreter cannot report its metadata at all. A trust path that
// does not apply (no certifi, no pip) is left empty and must not be counted against it.
func Interpret(ctx context.Context, env *kinds.Env, pythonPath string) (*Probes, error) {
	k := &Kind{}
	info, err := k.extractPythonInfo(ctx, env, pythonPath)
	if err != nil {
		return nil, err
	}
	p := &Probes{Info: info, Default: k.probeDefaultStore(ctx, env, pythonPath)}
	if info.Certifi != "" {
		p.Certifi = k.probeCertifi(ctx, env, pythonPath)
	}
	if info.Pip != "" {
		p.Pip = k.probePip(ctx, env, pythonPath)
	}
	return p, nil
}

// noteIndent lines a continuation of the report's detail block up under its first line.
const noteIndent = "             "

// probeReason is the text after "skipped" or "inconclusive" in the probe line.
func probeReason(v probe.Verdict) string {
	switch v {
	case probe.VerdictSkipped:
		return "--no-network"
	case probe.VerdictInconclusive:
		return "control host unreachable or network issue"
	}
	return ""
}

// detailBlock is the script's `extra`: the "detail:" lines, then a note for each CA-related
// variable that is set (env_notes).
func detailBlock(env *kinds.Env, evidence []string) string {
	out := "    detail:  " + strings.Join(evidence, "\n"+noteIndent)
	for _, v := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "PIP_CERT"} {
		if val := env.Getenv(v); val != "" {
			out += "\n    note:    " + v + "=" + val
		}
	}
	return out
}

// Info reads an interpreter's own metadata (version, base prefix, implementation ...) without
// probing any trust path: the script's `python -I -B py_probe.py info`.
func Info(ctx context.Context, env *kinds.Env, pythonPath string) (*PythonInfo, error) {
	return (&Kind{}).extractPythonInfo(ctx, env, pythonPath)
}

// combineUVPythonProbe combines probe results for uv-managed Python and uv tool environments.
// An inconclusive component keeps the result inconclusive unless something is trusted.
// Ports combine_uv_python_probe (lines 686-696).
func (k *Kind) combineUVPythonProbe(res1, res2, res3 probe.Verdict) probe.Verdict {
	// First check if any result is trusted
	if res1 == probe.VerdictTrusted || res2 == probe.VerdictTrusted || res3 == probe.VerdictTrusted {
		return probe.VerdictTrusted
	}

	// Check for rejected (all must be rejected or skipped)
	if res1 == probe.VerdictRejected &&
		(res2 == probe.VerdictRejected || res2 == probe.VerdictSkipped) &&
		(res3 == probe.VerdictRejected || res3 == probe.VerdictSkipped) {
		return probe.VerdictRejected
	}

	// Any inconclusive keeps it inconclusive
	if res1 == probe.VerdictInconclusive || res2 == probe.VerdictInconclusive || res3 == probe.VerdictInconclusive {
		return probe.VerdictInconclusive
	}

	return probe.VerdictSkipped
}

// versionGE reports whether v1 >= v2 using semantic version comparison.
func (k *Kind) versionGE(v1, v2 string) bool {
	return compareVersions(v1, v2) >= 0
}

// compareVersions compares two semantic versions and returns:
// -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	// Handle empty strings
	if v1 == "" && v2 == "" {
		return 0
	}
	if v1 == "" {
		return -1
	}
	if v2 == "" {
		return 1
	}

	p1 := strings.Split(v1, ".")
	p2 := strings.Split(v2, ".")

	// Pad to equal length
	maxLen := len(p1)
	if len(p2) > maxLen {
		maxLen = len(p2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(p1) {
			if _, err := fmt.Sscanf(p1[i], "%d", &n1); err != nil {
				continue
			}
		}
		if i < len(p2) {
			if _, err := fmt.Sscanf(p2[i], "%d", &n2); err != nil {
				continue
			}
		}

		if n1 < n2 {
			return -1
		} else if n1 > n2 {
			return 1
		}
	}

	return 0
}

// uvUpdateNotes returns the notes about patch availability for a uv Python.
func uvUpdateNotes(latest, newest string) string {
	switch latest {
	case "unknown":
		return "update: uv catalogue could not be read; patch availability is unknown"
	case "":
		return "update: uv reports no downloadable patch for this interpreter family"
	default:
		return fmt.Sprintf("update: available patch: %s; newest installed patch: %s; patch availability is not a vulnerability verdict", latest, newest)
	}
}

// uvPreferredNote returns the note for a selected older patch.
func uvPreferredNote(newest string) string {
	return fmt.Sprintf("preferred: still selects this older patch despite %s being installed; update remains scheduled", newest)
}

// uvRetainedNote returns the note for a retained older patch.
func uvRetainedNote(newest string) string {
	return fmt.Sprintf("retained: older patch kept beside %s; upgrading the preferred runtime cannot remove this retained installation", newest)
}

// uvToolUpgradeGuidance returns the guidance for upgrading a uv tool environment.
func uvToolUpgradeGuidance(name string) (compact string, full []string) {
	compact = fmt.Sprintf("uv tool upgrade %s; then re-audit this environment", name)
	full = []string{
		fmt.Sprintf("Upgrade through uv, preserving recorded requirements: uv tool upgrade %s", name),
		"Version pins and local/Git sources can prevent a dependency upgrade. Do not mutate a uv tool environment with pip.",
		"If its Python is outdated, rebuild with uv using a newer patch of the same Python minor version.",
	}
	return compact, full
}

// uvPythonUpgradeGuidance returns the guidance for upgrading a uv-managed Python.
func uvPythonUpgradeGuidance(minor string) (compact string, full []string) {
	compact = fmt.Sprintf("uv python upgrade %s; then re-audit linked environments", minor)
	full = []string{
		fmt.Sprintf("Upgrade the managed interpreter with uv: uv python upgrade %s", minor),
	}
	return compact, full
}

// UVCounts extracts the counts of uv Python installations and uv tool environments
// from a slice of findings. Each finding with Tool "uv Python" counts as a uv Python,
// and each finding with Tool starting with "uv tool: " counts as a uv tool.
// This is used by the CLI for the "No uv Python upgrade scheduled. Discovered N..."
// messages.
func UVCounts(findings []kinds.Finding) (pythonCount, toolCount int) {
	for _, f := range findings {
		if f.Tool == "uv Python" {
			pythonCount++
		} else if strings.HasPrefix(f.Tool, "uv tool: ") {
			toolCount++
		}
	}
	return
}

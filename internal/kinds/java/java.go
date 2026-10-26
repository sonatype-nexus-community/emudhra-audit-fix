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

// Package java implements the Kind for Java (JDK/JRE) installations.
// Ports check_java_version, java_candidates, audit_java, fix_java,
// fix_java_store, java_probe_with_store, and the Java undo from the
// legacy script (lines 997-1270, 2295-2365, 3139-3198).
package java

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/version"
)

// Kind implements kinds.Kind, kinds.Fixer, and kinds.Undoer for Java installations.
type Kind struct {
	probeOK    bool
	probeClass string
}

// New creates a new Java Kind.
func New() kinds.Kind {
	return &Kind{}
}

// ID returns the stable identifier "java".
func (k *Kind) ID() string {
	return "java"
}

// Describe returns a one-line description.
func (k *Kind) Describe() string {
	return "Java (JDK/JRE)"
}

// Applicable returns true for both macOS and Linux.
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	return kinds.Applicability{Applies: true}
}

// LineCheck ports check_java_version() from the legacy script (lines 997-1027).
// Java versions are fixed per release line: 8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1.
func LineCheck(ver string) (check kinds.VersionCheck, fixedVersion, note string) {
	if ver == "" {
		return kinds.VersionUnknown, "", ""
	}

	// Handle 1.8.0_XXX format
	if strings.HasPrefix(ver, "1.8.0_") {
		// Extract update number
		rest := strings.TrimPrefix(ver, "1.8.0_")
		rest = leadingDigits(rest)
		if rest == "" {
			return kinds.VersionUnknown, "", ""
		}
		upd, err := strconv.Atoi(rest)
		if err != nil {
			return kinds.VersionUnknown, "", ""
		}
		fixed := "8u511"
		if upd >= 511 {
			return kinds.VersionOK, fixed, "fixed in " + fixed
		}
		return kinds.VersionBehind, fixed, "fixed in " + fixed
	}

	// Handle modern version format: X.Y.Z
	// Extract major version
	majorStr := leadingDigits(ver)
	if majorStr == "" {
		return kinds.VersionUnknown, "", ""
	}
	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return kinds.VersionUnknown, "", ""
	}

	// Get the version prefix (X.Y.Z without trailing content)
	vPrefix := leadingVersion(ver)

	var fixed string
	switch major {
	case 8:
		fixed = "8u511"
	case 11:
		fixed = "11.0.33"
	case 17:
		fixed = "17.0.21"
	case 21:
		fixed = "21.0.13"
	case 25:
		fixed = "25.0.5"
	case 27:
		fixed = "27.0.1"
	default:
		if major > 27 {
			return kinds.VersionOK, "", "newer than the fixed lines"
		}
		return kinds.VersionNoFix, "a fixed release of a supported line (8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1)",
			"fixes only published for 8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1"
	}

	// Compare the version with the fixed version
	// The page lists e.g. 11.0.33.0.2; compare on the first three components
	v := version.Parse(vPrefix)
	fv := version.Parse(fixed)
	if v.GE(fv) {
		return kinds.VersionOK, fixed, "fixed in " + fixed + " (page lists " + fixed + ".0.2)"
	}
	return kinds.VersionBehind, fixed, "fixed in " + fixed + " (page lists " + fixed + ".0.2)"
}

// leadingDigits returns the leading run of digits.
func leadingDigits(s string) string {
	for i, r := range s {
		if r < '0' || r > '9' {
			return s[:i]
		}
	}
	return s
}

// leadingVersion keeps the leading run of digits and dots.
func leadingVersion(s string) string {
	for i, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return s[:i]
		}
	}
	return s
}

// Audit discovers Java installations and returns findings.
// Ports audit_java from the legacy script (lines 1051-1205).
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	var findings []kinds.Finding

	// Get Java home candidates
	candidates := k.candidates(env)

	// Deduplicate by resolved path
	seen := &discover.Seen{}

	var homes []string
	for _, home := range candidates {
		// Check that java executable exists
		javaPath := filepath.Join(home, "bin", "java")
		if _, err := os.Stat(javaPath); os.IsNotExist(err) {
			continue
		}

		// Resolve symlinks and deduplicate
		resolved, err := filepath.EvalSymlinks(home)
		if err != nil {
			resolved = home
		}
		key := "java:" + resolved
		if !seen.First(key) {
			continue
		}
		// The script keeps the resolved path (hp=$(cd -P "$h" && pwd)), so a symlink such
		// as SDKMAN's "current" is shown as the JDK it points at.
		homes = append(homes, resolved)
	}

	// Compile the probe once with any javac (targeting Java 8 so every JRE can run it)
	if !env.Offline {
		for _, home := range homes {
			javacPath := filepath.Join(home, "bin", "javac")
			if _, err := os.Stat(javacPath); os.IsNotExist(err) {
				continue
			}

			// Create probe source and class directories
			probeSrcDir := filepath.Join(env.TempDir, "java-src")
			probeClassDir := filepath.Join(env.TempDir, "java-cls")
			if err := os.MkdirAll(probeSrcDir, 0755); err != nil {
				continue
			}
			if err := os.MkdirAll(probeClassDir, 0755); err != nil {
				continue
			}

			// Write the Java probe source
			probeSrc := filepath.Join(probeSrcDir, "EmudhraProbe.java")
			if err := writeJavaProbe(probeSrc); err != nil {
				continue
			}

			// Try to compile with --release 8, falling back to -source 8 -target 8
			result := env.Run.Run(ctx, javacPath, "--release", "8", "-d", probeClassDir, probeSrc)
			if result.Error != nil || result.ExitCode != 0 {
				result = env.Run.Run(ctx, javacPath, "-source", "8", "-target", "8", "-d", probeClassDir, probeSrc)
			}
			if result.Error == nil && result.ExitCode == 0 {
				k.probeOK = true
				k.probeClass = probeClassDir
				break
			}
		}
	}

	// Audit each Java home
	for _, home := range homes {
		javaPath := filepath.Join(home, "bin", "java")

		// Get version
		result := env.Run.Run(ctx, javaPath, "-version")
		if result.Error != nil || result.ExitCode != 0 {
			// Cannot determine version
			f := kinds.NewFinding(k.ID(), "Java")
			f.Path = home
			f.SetProbe(kinds.ProbeSkipped, "version check failed")
			f.AddGuidance("(no specific guidance - see https://emudhra.we-have-a-problem.com/)")
			findings = append(findings, f)
			continue
		}

		// Extract version from output (combines stdout and stderr)
		ver := extractJavaVersion(result.Stdout + result.Stderr)
		if ver == "" {
			ver = "unknown"
		}

		// Get vendor from release file
		vendor := ""
		releasePath := filepath.Join(home, "release")
		if data, err := os.ReadFile(releasePath); err == nil {
			vendor = extractVendor(string(data))
		}

		// Check version against fixed releases
		check, fixedVersion, note := LineCheck(ver)

		// Run probe if possible
		var probeResult kinds.ProbeResult
		var evidence string

		if env.Offline {
			probeResult = kinds.ProbeSkipped
			evidence = "--no-network"
		} else if !k.probeOK {
			probeResult = kinds.ProbeSkipped
			evidence = "no javac found to build the probe - version check only"
		} else {
			// Run the probe
			probeResult, evidence = k.runProbe(ctx, env, home, "")
		}

		// Build finding
		f := kinds.NewFinding(k.ID(), "Java")
		f.Path = home
		f.SetVersion(ver, fixedVersion, check, note)
		f.SetProbe(probeResult, evidence)

		// Add vendor to version string if available
		if vendor != "" {
			f.Version = ver + " (" + vendor + ")"
		}

		// Add guidance
		k.addGuidance(&f, home, fixedVersion, probeResult)

		findings = append(findings, f)
	}

	return findings, nil
}

// candidates returns candidate Java home directories.
// Ports java_candidates from the legacy script (lines 1028-1050).
func (k *Kind) candidates(env *kinds.Env) []string {
	var candidates []string

	// JAVA_HOME
	if home := env.Getenv("JAVA_HOME"); home != "" {
		candidates = append(candidates, home)
	}

	// java on PATH
	if p := discover.Lookup("java", env.Path()); p != "" {
		// Get the home directory (parent of bin, parent of java executable)
		resolved := discover.Resolve(p)
		home := filepath.Dir(filepath.Dir(resolved))
		candidates = append(candidates, home)
	}

	// macOS: /usr/libexec/java_home -V
	// Check standard macOS and Linux Java directories
	switch env.Host.OS {
	case "darwin":
		// We would need to run /usr/libexec/java_home -V here
		// But we can't run commands at this stage
		// Instead, we'll check the standard macOS Java directories
		for _, d := range []string{
			env.Abs("/Library/Java/JavaVirtualMachines"),
			filepath.Join(env.Home(), "Library/Java/JavaVirtualMachines"),
		} {
			matches, _ := filepath.Glob(filepath.Join(d, "*", "Contents", "Home"))
			candidates = append(candidates, matches...)
		}
	case "linux":
		for _, pattern := range []string{
			"/usr/lib/jvm/*",
			"/usr/java/*",
			"/opt/java/*",
			"/opt/jdk*",
		} {
			matches, _ := filepath.Glob(env.Abs(pattern))
			candidates = append(candidates, matches...)
		}
	}

	// Version managers: SDKMAN, asdf, mise, ~/.jdks
	home := env.Home()
	for _, pattern := range []string{
		filepath.Join(home, ".sdkman", "candidates", "java", "*"),
		filepath.Join(home, ".asdf", "installs", "java", "*"),
		filepath.Join(home, ".local", "share", "mise", "installs", "java", "*"),
		filepath.Join(home, ".jdks", "*"),
	} {
		matches, _ := filepath.Glob(pattern)
		candidates = append(candidates, matches...)
	}

	// Homebrew Java installations
	switch env.Host.OS {
	case "darwin":
		for _, pattern := range []string{
			"/opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home",
			"/usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home",
		} {
			matches, _ := filepath.Glob(env.Abs(pattern))
			candidates = append(candidates, matches...)
		}
	case "linux":
		matches, _ := filepath.Glob(env.Abs("/home/linuxbrew/.linuxbrew/opt/openjdk*/libexec"))
		candidates = append(candidates, matches...)
	}

	return candidates
}

// extractJavaVersion extracts the version from java -version output.
func extractJavaVersion(output string) string {
	// Look for version "X.Y.Z" or "1.8.0_XXX" pattern
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Look for version "X.Y.Z" or "1.8.0_XXX"
		if strings.Contains(line, "version") {
			// Extract version between quotes
			start := strings.Index(line, `"`)
			if start == -1 {
				continue
			}
			end := strings.Index(line[start+1:], `"`)
			if end == -1 {
				continue
			}
			return line[start+1 : start+1+end]
		}
	}
	return ""
}

// extractVendor extracts the vendor from the release file content.
func extractVendor(content string) string {
	// Look for IMPLEMENTOR="..."
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "IMPLEMENTOR=") {
			// Extract value between quotes
			start := strings.Index(line, `"`)
			if start == -1 {
				continue
			}
			end := strings.Index(line[start+1:], `"`)
			if end == -1 {
				continue
			}
			return line[start+1 : start+1+end]
		}
	}
	return ""
}

// javaProbeSource is the script's EmudhraProbe, verbatim. For each URL it prints
// "ok URL" (the connection succeeded: the JDK trusts the chain), "certerr URL" (a
// certificate verification failure, found by walking the cause chain: it rejects the
// chain) or "err URL" (any other failure, which proves nothing). Calling every
// SSLHandshakeException a rejection would turn a proxy or a network fault into
// "protected".
const javaProbeSource = `import java.net.URL;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;

public class EmudhraProbe {
    public static void main(String[] args) {
        for (String u : args) {
            String r;
            try {
                HttpsURLConnection c = (HttpsURLConnection) new URL(u).openConnection();
                c.setConnectTimeout(10000);
                c.setReadTimeout(10000);
                c.getResponseCode();
                r = "ok";
            } catch (SSLException e) {
                boolean cert = false;
                for (Throwable t = e; t != null; t = t.getCause()) {
                    if (t instanceof java.security.cert.CertificateException
                            || t instanceof java.security.cert.CertPathValidatorException
                            || String.valueOf(t.getMessage()).contains("PKIX")) {
                        cert = true;
                    }
                }
                r = cert ? "certerr" : "err";
            } catch (Exception e) {
                r = "err";
            }
            System.out.println(r + " " + u);
        }
    }
}
`

// writeJavaProbe writes the EmudhraProbe.java source file.
func writeJavaProbe(path string) error {
	return os.WriteFile(path, []byte(javaProbeSource), 0o644)
}

// runProbe runs the Java probe with an optional alternative truststore.
func (k *Kind) runProbe(ctx context.Context, env *kinds.Env, home, store string) (kinds.ProbeResult, string) {
	if !k.probeOK {
		return kinds.ProbeInconclusive, "no javac available to build the probe"
	}

	javaPath := filepath.Join(home, "bin", "java")
	var args []string
	if store != "" {
		args = []string{
			"-Djavax.net.ssl.trustStore=" + store,
			"-Djavax.net.ssl.trustStorePassword=changeit",
			"-cp", k.probeClass, "EmudhraProbe",
		}
	} else {
		args = []string{"-cp", k.probeClass, "EmudhraProbe"}
	}

	// Add URLs
	args = append(args, probe.CONTROL_URL)
	args = append(args, probe.BAD_URLS...)

	result := env.Run.Run(ctx, javaPath, args...)
	if result.Error != nil {
		return kinds.ProbeInconclusive, result.Error.Error()
	}

	// Judge the output. The evidence is the judge's one-line reason, and only for an
	// inconclusive result (the report prints it after "inconclusive - "); the raw probe
	// output is not a reason and would print as several lines.
	output := strings.TrimSpace(result.Stdout)
	verdict := judgeProbe(output)
	if verdict == kinds.ProbeInconclusive {
		return verdict, probe.InconclusiveReason(output)
	}
	return verdict, ""
}

// judgeProbe turns the probe program's output into a result, with the script's judge().
func judgeProbe(output string) kinds.ProbeResult {
	switch probe.JudgeOutput(output) {
	case probe.VerdictTrusted:
		return kinds.ProbeTrusted
	case probe.VerdictRejected:
		return kinds.ProbeRejected
	}
	return kinds.ProbeInconclusive
}

// addGuidance adds remediation guidance based on the finding.
// Ports fix_java from the legacy script (lines 1226-1270).
func (k *Kind) addGuidance(f *kinds.Finding, home, fixedVersion string, probeResult kinds.ProbeResult) {
	// Determine install source
	source := discover.WhereFrom(home)

	// Upgrade hint (compact guidance)
	upgradeHint := "your JDK vendor"
	switch source {
	case discover.SourceSDKMAN:
		upgradeHint = "sdk list java"
	case discover.SourceBrew:
		upgradeHint = "brew upgrade openjdk"
	}

	// Set compact guidance
	if fixedVersion != "" {
		f.AddGuidance("upgrade to Java " + fixedVersion + " or later (" + upgradeHint + ")")
	} else {
		f.AddGuidance("upgrade to a fixed Java release (" + upgradeHint + ")")
	}

	// Add full guidance based on source
	switch source {
	case discover.SourceSDKMAN:
		f.GuidanceFull = append(f.GuidanceFull,
			"sdk list java   # pick a build at or above "+fixedVersion+", then:",
			"sdk install java <identifier> && sdk default java <identifier>",
			"sdk uninstall java "+filepath.Base(home)+"   # once nothing depends on it",
		)
	case discover.SourceBrew:
		f.GuidanceFull = append(f.GuidanceFull,
			"brew update && brew upgrade openjdk   # or: brew upgrade --cask temurin",
		)
	default:
		switch {
		case strings.HasPrefix(home, "/Library/Java/") || strings.Contains(home, "/Library/Java/"):
			f.GuidanceFull = append(f.GuidanceFull,
				"Install the vendor's latest update for this line ("+fixedVersion+" or later) and remove the old JDK.",
			)
		case strings.HasPrefix(home, "/usr/lib/jvm/") || strings.HasPrefix(home, "/usr/java/"):
			f.GuidanceFull = append(f.GuidanceFull,
				"Upgrade the distro's JDK/JRE package (apt/dnf/zypper) to "+fixedVersion+" or later.",
			)
		default:
			f.GuidanceFull = append(f.GuidanceFull,
				"Install "+fixedVersion+" or later from your JDK vendor and point JAVA_HOME at it.",
			)
		}
	}

	f.GuidanceFull = append(f.GuidanceFull,
		"Java uses its own cacerts/distrust list, so OS-level workarounds do not help; update the JDK.",
	)

	// Check if this cacerts has roots to distrust
	cacertsPath := k.findCacerts(home)
	keytoolPath := filepath.Join(home, "bin", "keytool")

	if cacertsPath != "" && fileExists(keytoolPath) {
		// A trusted probe means the roots are in effect, so the stop-gap applies; the fixer
		// itself checks which aliases are present before deleting anything.
		if probeResult == kinds.ProbeTrusted {
			f.HasFix = true
		}
	}
}

// findCacerts returns the path to the cacerts file for a Java home.
// Ports java_cacerts from the legacy script (lines 1206-1212).
func (k *Kind) findCacerts(home string) string {
	// Try lib/security/cacerts first (JDK 9+)
	path := filepath.Join(home, "lib", "security", "cacerts")
	if fileExists(path) {
		return path
	}

	// Try jre/lib/security/cacerts (JDK 8)
	path = filepath.Join(home, "jre", "lib", "security", "cacerts")
	if fileExists(path) {
		return path
	}

	return ""
}

// fileExists checks if a file exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// FixOrder implements kinds.Fixer: where this Kind's fix runs in --fix.
func (k *Kind) FixOrder() int { return kinds.FixJava }

// Plan returns fixes for Java installations that trust the compromised chain.
// Ports the Java part of plan_add from the legacy script.
func (k *Kind) Plan(ctx context.Context, env *kinds.Env, findings []kinds.Finding) ([]fixrun.Fix, error) {
	var fixes []fixrun.Fix

	for _, f := range findings {
		if f.Kind != k.ID() {
			continue
		}
		// Only schedule a fix if the probe was trusted
		if f.ProbeResult != kinds.ProbeTrusted {
			continue
		}
		if f.Path == "" {
			continue
		}

		// Check if this cacerts has roots to distrust
		cacertsPath := k.findCacerts(f.Path)
		if cacertsPath == "" {
			continue
		}

		keytoolPath := filepath.Join(f.Path, "bin", "keytool")
		if !fileExists(keytoolPath) {
			continue
		}

		fixes = append(fixes, &javaFix{
			home:        f.Path,
			version:     f.Version,
			cacertsPath: cacertsPath,
			keytoolPath: keytoolPath,
			probeOK:     k.probeOK,
			probeClass:  k.probeClass,
		})
	}

	return fixes, nil
}

// javaFix implements fixrun.Fix for Java cacerts patching.
type javaFix struct {
	home        string
	version     string
	cacertsPath string
	keytoolPath string
	probeOK     bool
	probeClass  string
}

// Kind returns the Kind ID.
func (f *javaFix) Kind() string { return "java" }

// Target returns the Java home being fixed.
func (f *javaFix) Target() string { return f.home }

// Run executes the Java cacerts fix.
// Ports fix_java_store from the legacy script (lines 2300-2360).
func (f *javaFix) Run(ctx context.Context, s *fixrun.Session) fixrun.Outcome {
	s.Say("%s  %s  (%s)", s.Bold("Java cacerts"), f.home, f.version)

	// Find affected aliases
	aliases := f.getAffectedAliases(ctx, s.Run)
	n := len(aliases)
	if n == 0 {
		s.OK("none of the roots are in %s", f.cacertsPath)
		return fixrun.Skipped
	}

	s.Say("this is a stop-gap: upgrading to a fixed JDK is better, and restores these roots")
	s.Say("would delete %d %s from the JDK trust store (%s):", n, plural(n, "entry", "entries"), f.cacertsPath)

	// Show aliases with their subjects
	for _, alias := range aliases {
		subject := f.getAliasSubject(ctx, s.Run, alias)
		s.Say("      %s   (%s)", alias, subject)
	}

	// Build patched copy in temp
	work := filepath.Join(s.TempDir, "cacerts-work")
	if err := copyFile(f.cacertsPath, work); err != nil {
		s.Bad("could not copy cacerts to temp: %v", err)
		return fixrun.Failed
	}

	// Delete aliases from the working copy and CHECK that each deletion succeeds
	for _, alias := range aliases {
		s.Cmd("%s -delete -alias %s -keystore %s -storepass changeit", f.keytoolPath, alias, work)
		result := s.Run.Run(ctx, f.keytoolPath, "-delete", "-alias", alias, "-keystore", work, "-storepass", "changeit")
		if result.Error != nil || result.ExitCode != 0 {
			s.Bad("keytool -delete for alias %q failed: %v - not applying", alias, result.Error)
			return fixrun.Failed
		}
	}

	// Count entries before and after
	pre := f.countEntries(ctx, s.Run, f.cacertsPath)
	post := f.countEntries(ctx, s.Run, work)

	// Verify that the roots are gone from the working copy
	testAliases := f.getAffectedAliasesWithStore(ctx, s.Run, work)
	if len(testAliases) != 0 {
		s.Bad("test on a copy: the roots are still present after deletion - not applying")
		return fixrun.Failed
	}

	if pre-post != n {
		s.Bad("test on a copy: removed a different number of entries than planned - not applying")
		return fixrun.Failed
	}

	// Test the patched store with the probe
	v := f.probeWithStore(ctx, s, work)
	switch v {
	case kinds.ProbeRejected:
		s.OK("test on a copy: this JDK rejects the compromised chain with the patched store")
	case kinds.ProbeTrusted:
		s.Bad("test on a copy: the JDK STILL accepts the chain with the patched store - not applying")
		s.Say("(the chain may be accepted through a different root; the fixed JDK build is the real answer)")
		return fixrun.Failed
	default:
		// Script continues with a warning but does NOT abort on inconclusive probe
		s.Warn("could not test the patched copy")
	}

	// Dry run check
	if s.DryRun {
		s.Say("[dry-run] would back up to %s.%s-%s and install the patched store", f.cacertsPath, fixrun.BackupTag, s.Stamp)
		s.Cmd("cp -p %s %s.%s-%s", f.cacertsPath, f.cacertsPath, fixrun.BackupTag, s.Stamp)
		s.Cmd("cp %s %s", work, f.cacertsPath)
		return fixrun.Skipped
	}

	// Confirm
	if !s.Confirm(fmt.Sprintf("Remove these %d entries from %s?", n, f.cacertsPath)) {
		s.Say("skipped")
		return fixrun.Skipped
	}

	// Need root?
	needsRoot, err := s.NeedRoot(f.cacertsPath)
	if err != nil {
		return fixrun.Failed
	}

	// Backup
	bak, err := s.Backup(ctx, f.cacertsPath)
	if err != nil {
		s.Bad("backup failed - nothing changed")
		return fixrun.Failed
	}

	// Install the patched store
	if needsRoot {
		if err := s.AsRoot(ctx, "cp", work, f.cacertsPath); err != nil {
			s.Bad("install failed - rolling back")
			_ = s.Restore(ctx, bak, f.cacertsPath)
			return fixrun.Failed
		}
	} else {
		if err := installAtomic(work, f.cacertsPath); err != nil {
			s.Bad("install failed - rolling back")
			_ = s.Restore(ctx, bak, f.cacertsPath)
			return fixrun.Failed
		}
	}

	// Verify with the live probe
	v = f.probeWithStore(ctx, s, "")
	switch v {
	case kinds.ProbeRejected:
		s.OK("verified: this JDK now rejects the compromised chain")
		s.Note("%s: backup at %s (a JDK upgrade also restores the roots)", f.cacertsPath, bak)
		return fixrun.Changed
	default:
		s.Bad("verification failed (%s) - rolling back", v)
		_ = s.Restore(ctx, bak, f.cacertsPath)
		return fixrun.Failed
	}
}

// getAffectedAliases returns the aliases that need to be deleted.
// Ports java_affected_aliases from the legacy script (lines 1213-1221).
func (f *javaFix) getAffectedAliases(ctx context.Context, runner exec.Runner) []string {
	return f.getAffectedAliasesWithStore(ctx, runner, f.cacertsPath)
}

// getAffectedAliasesWithStore returns affected aliases from a specific keystore.
func (f *javaFix) getAffectedAliasesWithStore(ctx context.Context, runner exec.Runner, store string) []string {
	result := runner.Run(ctx, f.keytoolPath,
		"-J-Duser.language=en", "-list", "-v",
		"-keystore", store, "-storepass", "changeit")

	// Parse output to find aliases with affected subjects
	var aliases []string
	lines := strings.Split(result.Stdout, "\n")

	var currentAlias string
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Look for "Alias name:"
		if strings.HasPrefix(line, "Alias name:") {
			currentAlias = strings.TrimSpace(strings.TrimPrefix(line, "Alias name:"))
			continue
		}

		// Look for "Owner:" line with one of the root subjects
		if strings.HasPrefix(line, "Owner:") && currentAlias != "" {
			if strings.Contains(line, "AAA Certificate Services") ||
				strings.Contains(line, "emSign ECC Root CA - G3") {
				aliases = append(aliases, currentAlias)
			}
			currentAlias = ""
		}
	}

	return aliases
}

// getAliasSubject returns the subject CN for an alias.
// Ports java_alias_subject from the legacy script (lines 2295-2299).
func (f *javaFix) getAliasSubject(ctx context.Context, runner exec.Runner, alias string) string {
	result := runner.Run(ctx, f.keytoolPath,
		"-J-Duser.language=en", "-list", "-v",
		"-keystore", f.cacertsPath, "-storepass", "changeit",
		"-alias", alias)

	// Find "Owner: CN=..., ..." and extract CN
	lines := strings.Split(result.Stdout, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Owner:") {
			// Extract CN from "Owner: CN=Name, ..."
			if idx := strings.Index(line, "CN="); idx != -1 {
				rest := line[idx+3:]
				if commaIdx := strings.Index(rest, ","); commaIdx != -1 {
					return rest[:commaIdx]
				}
				return rest
			}
		}
	}
	return ""
}

// countEntries counts the number of trustedCertEntry in a keystore.
func (f *javaFix) countEntries(ctx context.Context, runner exec.Runner, store string) int {
	result := runner.Run(ctx, f.keytoolPath,
		"-list", "-keystore", store, "-storepass", "changeit")

	return strings.Count(result.Stdout, "trustedCertEntry")
}

// probeWithStore runs the Java probe with an optional alternative truststore.
func (f *javaFix) probeWithStore(ctx context.Context, s *fixrun.Session, store string) kinds.ProbeResult {
	if !f.probeOK {
		return kinds.ProbeInconclusive
	}

	javaPath := filepath.Join(f.home, "bin", "java")
	var args []string
	if store != "" {
		args = []string{
			"-Djavax.net.ssl.trustStore=" + store,
			"-Djavax.net.ssl.trustStorePassword=changeit",
			"-cp", f.probeClass, "EmudhraProbe",
		}
	} else {
		args = []string{"-cp", f.probeClass, "EmudhraProbe"}
	}

	// Add URLs
	args = append(args, probe.CONTROL_URL)
	args = append(args, probe.BAD_URLS...)

	result := s.Run.Run(ctx, javaPath, args...)
	if result.Error != nil {
		return kinds.ProbeInconclusive
	}

	// Judge the output
	output := strings.TrimSpace(result.Stdout)
	return judgeProbe(output)
}

// copyFile copies a file preserving permissions.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// installAtomic replaces dst with the contents of src without ever writing to dst's own
// file: it builds the new store beside the original, gives it the original's mode, and
// renames it over. A crash part-way leaves either the old store or the new one. Writing
// in place (os.WriteFile) truncates first, so a crash would leave every Java program on
// the machine unable to validate any certificate. The script uses cp, which keeps the
// destination's owner and mode; for a store we own, a same-directory rename does too.
func installAtomic(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	fi, err := os.Stat(dst)
	if err != nil {
		return err
	}
	tmp := dst + ".emudhra-new"
	if err := os.WriteFile(tmp, data, fi.Mode().Perm()); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, fi.Mode().Perm()); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// plural returns the singular or plural form.
func plural(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

// Undo implements kinds.Undoer: restore newest cacerts backups.
// Ports the Java part of run_undo from the legacy script (lines 3139-3198).
func (k *Kind) Undo(ctx context.Context, env *kinds.Env, s *fixrun.Session) error {
	// Get all Java homes
	candidates := k.candidates(env)

	var backupsToRestore []struct {
		cacerts string
		backup  string
	}

	// Find newest backup for each Java home's cacerts. The same JDK is often reached
	// twice (JAVA_HOME and PATH); the script de-duplicates, and so must this, or the
	// user would be asked to restore one file twice.
	seen := map[string]bool{}
	for _, home := range candidates {
		cacerts := k.findCacerts(home)
		if cacerts == "" {
			continue
		}
		// The resolved path is only the de-duplication key: restore and display the
		// path as the JDK was found, as the script does.
		key := cacerts
		if real, err := filepath.EvalSymlinks(cacerts); err == nil {
			key = real
		}
		if seen[key] {
			continue
		}
		seen[key] = true

		backup := fixrun.NewestBackup(cacerts)
		if backup != "" {
			backupsToRestore = append(backupsToRestore, struct {
				cacerts string
				backup  string
			}{cacerts, backup})
		}
	}

	// Restore each backup
	for _, item := range backupsToRestore {
		s.Say("%s", s.Bold(item.cacerts))
		s.Say("restore from %s", item.backup)

		if s.DryRun {
			s.Say("[dry-run] would restore it")
			continue
		}

		if !s.Confirm(fmt.Sprintf("Restore %s from that backup?", item.cacerts)) {
			s.Say("skipped")
			continue
		}

		needsRoot, err := s.NeedRoot(item.cacerts)
		if err != nil {
			continue
		}

		if needsRoot {
			if err := s.AsRoot(ctx, "cp", "-p", item.backup, item.cacerts); err != nil {
				s.Bad("restore failed")
				continue
			}
		} else {
			if err := s.Restore(ctx, item.backup, item.cacerts); err != nil {
				s.Bad("restore failed")
				continue
			}
		}

		s.OK("restored")
	}

	return nil
}

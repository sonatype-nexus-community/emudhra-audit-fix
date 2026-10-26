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

// Package platform provides OS, architecture, and distro detection.
package platform

import (
	"bufio"
	"os"
	"runtime"
	"strings"
)

// Family represents a Linux distribution family.
type Family string

const (
	FamilyDebian Family = "debian"
	FamilyRedHat Family = "redhat"
	FamilyAlpine Family = "alpine"
	FamilyArch   Family = "arch"
	FamilySUSE   Family = "suse"
	FamilyOther  Family = "other"
)

// Distro holds Linux distribution information from /etc/os-release.
type Distro struct {
	ID      string
	IDLike  string
	Version string
}

// MDMStatus represents macOS MDM enrollment status.
type MDMStatus struct {
	Enrolled bool
	Source   string
}

// Host is a plain struct built once and passed in, so tests construct hosts
// for any OS without being on it.
type Host struct {
	OS      string // "darwin" | "linux"
	Arch    string // "amd64" | "arm64"
	Distro  Distro // id, id_like, version (from /etc/os-release)
	Family  Family // Debian, RedHat, Alpine, Arch, SUSE, Other
	IsRoot  bool
	HasSudo bool
	HasTTY  bool
	MDM     MDMStatus // macOS only
	Home    string
}

// Detect builds a Host struct by detecting the current system configuration.
func Detect() Host {
	host := Host{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	// Detect home directory
	if home := os.Getenv("HOME"); home != "" {
		host.Home = home
	}

	// Detect if running as root
	host.IsRoot = os.Geteuid() == 0

	// Detect if sudo is available
	if _, err := os.Stat("/usr/bin/sudo"); err == nil {
		host.HasSudo = true
	}

	// Detect if stdout is a TTY
	if fi, err := os.Stdout.Stat(); err == nil {
		host.HasTTY = (fi.Mode() & os.ModeCharDevice) != 0
	}

	// Linux-specific detection
	if host.OS == "linux" {
		host.Distro = detectDistro()
		host.Family = detectFamily(host.Distro)
	}

	// macOS-specific detection
	if host.OS == "darwin" {
		host.MDM = detectMDM()
	}

	return host
}

// detectDistro reads /etc/os-release to get distribution information.
func detectDistro() Distro {
	distro := Distro{}

	f, err := os.Open("/etc/os-release")
	if err != nil {
		return distro
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			distro.ID = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		} else if strings.HasPrefix(line, "ID_LIKE=") {
			distro.IDLike = strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), `"`)
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			distro.Version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}

	return distro
}

// detectFamily determines the distribution family from ID and ID_LIKE.
func detectFamily(distro Distro) Family {
	// Check ID_LIKE first (for derivatives)
	like := strings.ToLower(distro.IDLike)
	id := strings.ToLower(distro.ID)

	if strings.Contains(like, "debian") || id == "debian" || id == "ubuntu" {
		return FamilyDebian
	}
	if strings.Contains(like, "rhel") || strings.Contains(like, "fedora") || id == "rhel" || id == "fedora" || id == "centos" {
		return FamilyRedHat
	}
	if id == "alpine" {
		return FamilyAlpine
	}
	if id == "arch" {
		return FamilyArch
	}
	if strings.Contains(like, "suse") || id == "suse" || id == "opensuse" {
		return FamilySUSE
	}

	return FamilyOther
}

// detectMDM checks macOS MDM enrollment status via 'profiles status -type enrollment'.
// This function is implemented in mdm_detect.go to avoid import cycles with internal/exec.
var detectMDM = defaultDetectMDM

// defaultDetectMDM is the default implementation (returns not enrolled).
func defaultDetectMDM() MDMStatus {
	return MDMStatus{Enrolled: false, Source: ""}
}

// ParseOSRelease parses an os-release file content and returns a Distro.
func ParseOSRelease(content string) Distro {
	distro := Distro{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			distro.ID = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		} else if strings.HasPrefix(line, "ID_LIKE=") {
			distro.IDLike = strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), `"`)
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			distro.Version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}
	return distro
}

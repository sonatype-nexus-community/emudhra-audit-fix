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

// Package banner prints an ASCII art banner (TTY-only).
package banner

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// ttyChecker allows overriding TTY detection in tests.
var ttyChecker = defaultTTYChecker

// defaultTTYChecker is the production TTY checker.
func defaultTTYChecker() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// Print writes the ASCII banner to w if stdout is a TTY, otherwise does nothing.
func Print(w io.Writer, version string) {
	// Only print banner when stdout is a TTY
	if !ttyChecker() {
		return
	}

	// The Sonatype Community banner, as in nexus-repo-asset-lister.
	lines := []string{
		strings.Repeat("⬢⬡", 42),
		"",
		"  ███████╗ ██████╗ ███╗   ██╗ █████╗ ████████╗██╗   ██╗██████╗ ███████╗",
		"  ██╔════╝██╔═══██╗████╗  ██║██╔══██╗╚══██╔══╝╚██╗ ██╔╝██╔══██╗██╔════╝",
		"  ███████╗██║   ██║██╔██╗ ██║███████║   ██║    ╚████╔╝ ██████╔╝█████╗",
		"  ╚════██║██║   ██║██║╚██╗██║██╔══██║   ██║     ╚██╔╝  ██╔═══╝ ██╔══╝",
		"  ███████║╚██████╔╝██║ ╚████║██║  ██║   ██║      ██║   ██║     ███████╗",
		"  ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝     ╚══════╝",
		"",
		"  eMudhra CA compromise: developer tool audit and fixer",
		fmt.Sprintf("  Running on: %s/%s", runtime.GOOS, runtime.GOARCH),
	}
	if version != "" && version != "dev" {
		lines = append(lines, fmt.Sprintf("  Version: %s", version))
	}
	_, _ = fmt.Fprintln(w, strings.Join(lines, "\n")+"\n")
}

// isTTY checks if stdout is a terminal.
func isTTY() bool {
	return ttyChecker()
}

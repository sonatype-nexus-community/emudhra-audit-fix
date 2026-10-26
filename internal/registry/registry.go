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

// Package kinds defines the Kind interface, Env, Finding, and Action types.
// A Kind is one class of thing we audit and may fix. Each Kind owns its
// discovery, audit, fix plan, fix execution, and undo.
// Package registry holds the explicit list of Kinds. It sits above internal/kinds
// and every Kind package because each Kind imports kinds for its types, so kinds
// itself cannot import them back.
package registry

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/brew"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/bun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/claudecode"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/curl"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/deno"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/electron"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/git"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/golang"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/java"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/macpip"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/mise"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/node"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/ospkg"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/pixi"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/python"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/rustup"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/sysbundle"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/uv"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/uvpython"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/uvtools"
)

// All returns every registered Kind. Registration is explicit, not init()
// magic, so the set and order are visible and testable. The order is the
// script's audit order (its "want" sequence) and, for Kinds that fix, the fix
// order: package upgrades first, then the system store, then the stop-gaps
// that depend on it. Adding a Kind is one line here.
//
// uvpython and uvtools audit nothing: the python Kind finds uv Pythons and tool environments and
// asks them to fix through Finding.Requests, as the script's plan_add does.
func All() []kinds.Kind {
	return []kinds.Kind{
		curl.New(),
		git.New(),
		golang.New(),
		python.New(),
		java.New(),
		node.New(),
		deno.New(),
		bun.New(),
		rustup.New(),
		uv.New(),
		uvpython.New(),
		uvtools.New(),
		pixi.New(),
		mise.New(),
		claudecode.New(),
		brew.New(),
		sysbundle.New(),
		ospkg.New(),
		macpip.New(),
		electron.New(),
	}
}

// ByID returns the Kind with the given ID, or nil if there is none.
func ByID(id string) kinds.Kind {
	for _, k := range All() {
		if k.ID() == id {
			return k
		}
	}
	return nil
}

// IDs returns the IDs of all registered Kinds, in registry order.
func IDs() []string {
	ks := All()
	ids := make([]string, len(ks))
	for i, k := range ks {
		ids[i] = k.ID()
	}
	return ids
}

// aliases maps --only alias names to their expansion. "sys" is the script's
// kind for the system trust store: the CA bundle files and the OS packages.
var aliases = map[string][]string{
	"sys": {"sysbundle", "ospkg"},
}

// ValidOnlyValues returns every valid --only value (Kind IDs and aliases),
// sorted.
func ValidOnlyValues() []string {
	values := append([]string{}, IDs()...)
	for a := range aliases {
		values = append(values, a)
	}
	slices.Sort(values)
	return values
}

// ValidateOnly returns an error when any --only value is neither a Kind ID
// nor an alias.
func ValidateOnly(only []string) error {
	valid := ValidOnlyValues()
	for _, v := range only {
		if !slices.Contains(valid, v) {
			return fmt.Errorf("--only must be one of: %s", strings.Join(valid, ", "))
		}
	}
	return nil
}

// ExpandAliases replaces alias names with the Kind IDs they stand for.
func ExpandAliases(only []string) []string {
	result := []string{}
	for _, v := range only {
		if exp, ok := aliases[v]; ok {
			result = append(result, exp...)
			continue
		}
		result = append(result, v)
	}
	return result
}

// titles are the verbose report's section headers (the script's audit_start names). A Kind with
// no entry has no section: uvpython, uvtools and macpip only fix.
var titles = map[string]string{
	"curl": "curl", "git": "git", "golang": "Go", "python": "Python", "java": "Java (JRE/JDK)",
	"node": "Node.js", "deno": "Deno", "bun": "Bun", "rustup": "rustup", "uv": "uv", "pixi": "pixi",
	"mise": "mise", "claudecode": "Claude Code", "brew": "Homebrew ca-certificates",
	"sysbundle": "System CA bundle files", "ospkg": "OS CA packages", "electron": "Electron apps",
}

// SectionTitle returns the report section header for a Kind, or "" when it has none.
func SectionTitle(id string) string { return titles[id] }

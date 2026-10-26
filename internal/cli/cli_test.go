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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseFlags tests flag parsing for all flags.
func TestParseFlags(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectedOpts   Options
		expectErr      bool
		expectedErrMsg string
	}{
		// === Basic flags ===
		{
			name: "no flags",
			args: []string{},
			expectedOpts: Options{
				Verbose:    0,
				ShowBanner: true,
			},
		},
		{
			name: "--no-network",
			args: []string{"--no-network"},
			expectedOpts: Options{
				NoNetwork:  true,
				ShowBanner: true,
			},
		},
		{
			name: "--no-guidance",
			args: []string{"--no-guidance"},
			expectedOpts: Options{
				NoGuidance: true,
				ShowBanner: true,
			},
		},
		{
			name: "-v",
			args: []string{"-v"},
			expectedOpts: Options{
				Verbose:    1,
				ShowBanner: true,
			},
		},
		{
			name: "--verbose",
			args: []string{"--verbose"},
			expectedOpts: Options{
				Verbose:    1,
				ShowBanner: true,
			},
		},
		{
			name: "-vv",
			args: []string{"-vv"},
			expectedOpts: Options{
				Verbose:    2,
				ShowBanner: true,
			},
		},
		{
			name: "-v -v does not increase beyond 1",
			args: []string{"-v", "-v"},
			expectedOpts: Options{
				Verbose:    1,
				ShowBanner: true,
			},
		},
		{
			name: "-vv overrides -v",
			args: []string{"-v", "-vv"},
			expectedOpts: Options{
				Verbose:    2,
				ShowBanner: true,
			},
		},
		{
			name: "--fix",
			args: []string{"--fix"},
			expectedOpts: Options{
				Fix:        true,
				ShowBanner: true,
			},
		},
		{
			name: "--dry-run implies --fix",
			args: []string{"--dry-run"},
			expectedOpts: Options{
				Fix:        true,
				DryRun:     true,
				ShowBanner: true,
			},
		},
		{
			name: "--yes",
			args: []string{"--yes", "--fix"},
			expectedOpts: Options{
				Yes:        true,
				Fix:        true,
				ShowBanner: true,
			},
		},
		{
			name: "--undo",
			args: []string{"--undo"},
			expectedOpts: Options{
				Undo:       true,
				ShowBanner: true,
			},
		},
		{
			name: "--workaround-only",
			args: []string{"--workaround-only"},
			expectedOpts: Options{
				WorkaroundOnly: true,
				ShowBanner:     true,
			},
		},
		{
			name: "-h",
			args: []string{"-h"},
			expectedOpts: Options{
				ShowHelp: true,
			},
		},
		{
			name: "--help",
			args: []string{"--help"},
			expectedOpts: Options{
				ShowHelp: true,
			},
		},
		{
			name: "--version",
			args: []string{"--version"},
			expectedOpts: Options{
				ShowVersion: true,
			},
		},
		{
			name: "--list-kinds",
			args: []string{"--list-kinds"},
			expectedOpts: Options{
				ListKinds: true,
			},
		},
		// === --only flag variations ===
		{
			name: "--only=brew",
			args: []string{"--only=brew"},
			expectedOpts: Options{
				Only:       []string{"brew"},
				ShowBanner: true,
			},
		},
		{
			name: "--only sys",
			args: []string{"--only", "sys"},
			expectedOpts: Options{
				Only:       []string{"sys"},
				ShowBanner: true,
			},
		},
		{
			name: "--only=uv,java,node",
			args: []string{"--only=uv,java,node"},
			expectedOpts: Options{
				Only:       []string{"uv", "java", "node"},
				ShowBanner: true,
			},
		},
		// === Validation errors (exit code 2) ===
		{
			name:           "--undo with --fix is error",
			args:           []string{"--undo", "--fix"},
			expectErr:      true,
			expectedErrMsg: "--undo cannot be combined with --fix",
		},
		{
			name: "--undo --fix --dry-run is allowed",
			args: []string{"--undo", "--fix", "--dry-run"},
			expectedOpts: Options{
				Undo:       true,
				Fix:        true,
				DryRun:     true,
				ShowBanner: true,
			},
		},
		{
			name:           "--only without value is error",
			args:           []string{"--only"},
			expectErr:      true,
			expectedErrMsg: "--only requires a KIND argument",
		},
		{
			name:           "--only with invalid kind is error",
			args:           []string{"--only=invalid"},
			expectErr:      true,
			expectedErrMsg: "--only must be one of: brew, sys, java, macpip, node, uv, uvpython, uvtools, rustup",
		},
		{
			name:           "--yes without --fix or --undo is error",
			args:           []string{"--yes"},
			expectErr:      true,
			expectedErrMsg: "--yes only makes sense with --fix or --undo",
		},
		{
			name:           "--fix with --no-network is error",
			args:           []string{"--fix", "--no-network"},
			expectErr:      true,
			expectedErrMsg: "--fix needs the live probes to verify its changes; do not combine it with --no-network",
		},
		{
			name:           "unknown option is error",
			args:           []string{"--unknown"},
			expectErr:      true,
			expectedErrMsg: "unknown option: --unknown",
		},
		// === Banner display logic ===
		{
			name: "banner shown for audit",
			args: []string{},
			expectedOpts: Options{
				ShowBanner: true,
			},
		},
		{
			name: "banner not shown for --help",
			args: []string{"--help"},
			expectedOpts: Options{
				ShowHelp: true,
			},
		},
		{
			name: "banner not shown for --version",
			args: []string{"--version"},
			expectedOpts: Options{
				ShowVersion: true,
			},
		},
		{
			name: "banner not shown for --list-kinds",
			args: []string{"--list-kinds"},
			expectedOpts: Options{
				ListKinds: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := ParseFlags(tt.args, "test-version")

			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrMsg)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedOpts, opts)
		})
	}
}

// TestValidateOptions tests all validation rules from legacy script lines ~108-117.
func TestValidateOptions(t *testing.T) {
	tests := []struct {
		name      string
		opts      Options
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid audit options",
			opts: Options{
				NoNetwork: false,
				Verbose:   0,
			},
			expectErr: false,
		},
		{
			name: "valid fix options",
			opts: Options{
				Fix:    true,
				DryRun: false,
				Yes:    true,
			},
			expectErr: false,
		},
		{
			name: "valid undo options",
			opts: Options{
				Undo:   true,
				DryRun: true,
			},
			expectErr: false,
		},
		{
			name: "invalid: --undo with --fix (without --dry-run)",
			opts: Options{
				Undo: true,
				Fix:  true,
			},
			expectErr: true,
			errMsg:    "--undo cannot be combined with --fix",
		},
		{
			name: "valid: --undo with --fix with --dry-run",
			opts: Options{
				Undo:   true,
				Fix:    true,
				DryRun: true,
			},
			expectErr: false,
		},
		{
			name: "invalid: --only with unknown kind",
			opts: Options{
				Only: []string{"unknown-kind"},
			},
			expectErr: true,
			errMsg:    "--only must be one of: brew, sys, java, macpip, node, uv, uvpython, uvtools, rustup",
		},
		{
			name: "valid: --only with known kind",
			opts: Options{
				Only: []string{"brew"},
			},
			expectErr: false,
		},
		{
			name: "valid: --only with sys alias",
			opts: Options{
				Only: []string{"sys"},
			},
			expectErr: false,
		},
		{
			name: "valid: --only with multiple kinds",
			opts: Options{
				Only: []string{"brew", "java", "node"},
			},
			expectErr: false,
		},
		{
			name: "invalid: --yes without --fix or --undo",
			opts: Options{
				Yes: true,
			},
			expectErr: true,
			errMsg:    "--yes only makes sense with --fix or --undo",
		},
		{
			name: "valid: --yes with --fix",
			opts: Options{
				Yes: true,
				Fix: true,
			},
			expectErr: false,
		},
		{
			name: "valid: --yes with --undo",
			opts: Options{
				Yes:  true,
				Undo: true,
			},
			expectErr: false,
		},
		{
			name: "invalid: --fix with --no-network",
			opts: Options{
				Fix:       true,
				NoNetwork: true,
			},
			expectErr: true,
			errMsg:    "--fix needs the live probes to verify its changes; do not combine it with --no-network",
		},
		{
			name: "valid: --fix without --no-network",
			opts: Options{
				Fix:       true,
				NoNetwork: false,
			},
			expectErr: false,
		},
		{
			name: "valid: --dry-run with --fix with --no-network",
			opts: Options{
				Fix:       true,
				DryRun:    true,
				NoNetwork: true,
			},
			expectErr: true, // --fix + --no-network is still invalid
			errMsg:    "--fix needs the live probes to verify its changes; do not combine it with --no-network",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOptions(&tt.opts)

			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestVersion tests version string generation.
func TestVersion(t *testing.T) {
	tests := []struct {
		name            string
		version         string
		commit          string
		expectedVersion string
	}{
		{
			name:            "dev version without commit",
			version:         "dev",
			commit:          "none",
			expectedVersion: "dev",
		},
		{
			name:            "version with commit",
			version:         "1.2.3",
			commit:          "abc123",
			expectedVersion: "1.2.3 (commit: abc123)",
		},
		{
			name:            "version without commit",
			version:         "1.0.0",
			commit:          "none",
			expectedVersion: "1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetVersion(tt.version, tt.commit)
			assert.Equal(t, tt.expectedVersion, getVersion())
		})
	}
}

// TestValidOnlyValues tests that all valid --only values are accepted.
func TestValidOnlyValues(t *testing.T) {
	validKinds := []string{"brew", "sys", "java", "macpip", "node", "uv", "uvpython", "uvtools", "rustup"}

	for _, kind := range validKinds {
		t.Run(kind, func(t *testing.T) {
			opts, err := ParseFlags([]string{"--only=" + kind}, "test")
			require.NoError(t, err)
			assert.Equal(t, []string{kind}, opts.Only)
		})
	}
}

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

package java

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/privilege"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/prompt"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

func TestLineCheck(t *testing.T) {
	tests := []struct {
		name             string
		version          string
		wantCheck        kinds.VersionCheck
		wantFixedVersion string
		wantNote         string
	}{
		{
			name:             "Java 8 update 511 - fixed",
			version:          "1.8.0_511",
			wantCheck:        kinds.VersionOK,
			wantFixedVersion: "8u511",
			wantNote:         "fixed in 8u511",
		},
		{
			name:             "Java 8 update 500 - behind",
			version:          "1.8.0_500",
			wantCheck:        kinds.VersionBehind,
			wantFixedVersion: "8u511",
			wantNote:         "fixed in 8u511",
		},
		{
			name:             "Java 11.0.33 - fixed",
			version:          "11.0.33",
			wantCheck:        kinds.VersionOK,
			wantFixedVersion: "11.0.33",
			wantNote:         "fixed in 11.0.33 (page lists 11.0.33.0.2)",
		},
		{
			name:             "Java 11.0.32 - behind",
			version:          "11.0.32",
			wantCheck:        kinds.VersionBehind,
			wantFixedVersion: "11.0.33",
			wantNote:         "fixed in 11.0.33 (page lists 11.0.33.0.2)",
		},
		{
			name:             "Java 17.0.21 - fixed",
			version:          "17.0.21",
			wantCheck:        kinds.VersionOK,
			wantFixedVersion: "17.0.21",
			wantNote:         "fixed in 17.0.21 (page lists 17.0.21.0.2)",
		},
		{
			name:             "Java 17.0.20 - behind",
			version:          "17.0.20",
			wantCheck:        kinds.VersionBehind,
			wantFixedVersion: "17.0.21",
			wantNote:         "fixed in 17.0.21 (page lists 17.0.21.0.2)",
		},
		{
			name:             "Java 21.0.13 - fixed",
			version:          "21.0.13",
			wantCheck:        kinds.VersionOK,
			wantFixedVersion: "21.0.13",
			wantNote:         "fixed in 21.0.13 (page lists 21.0.13.0.2)",
		},
		{
			name:             "Java 21.0.12 - behind",
			version:          "21.0.12",
			wantCheck:        kinds.VersionBehind,
			wantFixedVersion: "21.0.13",
			wantNote:         "fixed in 21.0.13 (page lists 21.0.13.0.2)",
		},
		{
			name:             "Java 25.0.5 - fixed",
			version:          "25.0.5",
			wantCheck:        kinds.VersionOK,
			wantFixedVersion: "25.0.5",
			wantNote:         "fixed in 25.0.5 (page lists 25.0.5.0.2)",
		},
		{
			name:             "Java 25.0.4 - behind",
			version:          "25.0.4",
			wantCheck:        kinds.VersionBehind,
			wantFixedVersion: "25.0.5",
			wantNote:         "fixed in 25.0.5 (page lists 25.0.5.0.2)",
		},
		{
			name:             "Java 27.0.1 - fixed",
			version:          "27.0.1",
			wantCheck:        kinds.VersionOK,
			wantFixedVersion: "27.0.1",
			wantNote:         "fixed in 27.0.1 (page lists 27.0.1.0.2)",
		},
		{
			name:             "Java 27.0.0 - behind",
			version:          "27.0.0",
			wantCheck:        kinds.VersionBehind,
			wantFixedVersion: "27.0.1",
			wantNote:         "fixed in 27.0.1 (page lists 27.0.1.0.2)",
		},
		{
			name:             "Java 28.0.0 - newer than fixed lines",
			version:          "28.0.0",
			wantCheck:        kinds.VersionOK,
			wantFixedVersion: "",
			wantNote:         "newer than the fixed lines",
		},
		{
			name:             "Java 9 - no fix",
			version:          "9.0.4",
			wantCheck:        kinds.VersionNoFix,
			wantFixedVersion: "a fixed release of a supported line (8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1)",
			wantNote:         "fixes only published for 8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1",
		},
		{
			name:             "Empty version - unknown",
			version:          "",
			wantCheck:        kinds.VersionUnknown,
			wantFixedVersion: "",
			wantNote:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check, fixedVersion, note := LineCheck(tt.version)
			if check != tt.wantCheck {
				t.Errorf("LineCheck(%q) check = %v, want %v", tt.version, check, tt.wantCheck)
			}
			if fixedVersion != tt.wantFixedVersion {
				t.Errorf("LineCheck(%q) fixedVersion = %q, want %q", tt.version, fixedVersion, tt.wantFixedVersion)
			}
			if note != tt.wantNote {
				t.Errorf("LineCheck(%q) note = %q, want %q", tt.version, note, tt.wantNote)
			}
		})
	}
}

// TestJavaUndo tests the Undo functionality
func TestJavaUndo(t *testing.T) {
	t.Run("restores the newest backup", func(t *testing.T) {
		env := testutil.NewTestEnvT(t)

		// Create a fake Java home with cacerts
		javaHome := filepath.Join(env.TempDir, "jdk")
		libDir := filepath.Join(javaHome, "lib", "security")
		require.NoError(t, os.MkdirAll(libDir, 0755))

		cacertsPath := filepath.Join(libDir, "cacerts")
		require.NoError(t, os.WriteFile(cacertsPath, []byte("fake cacerts"), 0644))

		// Create a backup
		bakPath := cacertsPath + ".pre-emudhra-20260101120000"
		require.NoError(t, os.WriteFile(bakPath, []byte("original cacerts"), 0644))

		// Point JAVA_HOME at the fake JDK
		env.Environ["JAVA_HOME"] = javaHome

		var out bytes.Buffer
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true
		s := &fixrun.Session{
			DryRun: false, TempDir: env.TempDir, Stamp: "20260101130000",
			Priv: fakePriv, Out: &out, Run: env.Run,
			Prompt: prompt.NewFakePrompter(),
		}

		k := &Kind{}
		err := k.Undo(context.Background(), env, s)
		require.NoError(t, err)

		// Check output mentions the restore
		assert.Contains(t, out.String(), "restore from")
	})

	t.Run("dry run shows what would be restored", func(t *testing.T) {
		env := testutil.NewTestEnvT(t)

		javaHome := filepath.Join(env.TempDir, "jdk")
		libDir := filepath.Join(javaHome, "lib", "security")
		require.NoError(t, os.MkdirAll(libDir, 0755))

		cacertsPath := filepath.Join(libDir, "cacerts")
		require.NoError(t, os.WriteFile(cacertsPath, []byte("fake"), 0644))

		bakPath := cacertsPath + ".pre-emudhra-20260101120000"
		require.NoError(t, os.WriteFile(bakPath, []byte("original"), 0644))

		env.Environ["JAVA_HOME"] = javaHome

		var out bytes.Buffer
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true
		s := &fixrun.Session{
			DryRun: true, TempDir: env.TempDir, Stamp: "20260101130000",
			Priv: fakePriv, Out: &out, Run: env.Run,
			Prompt: prompt.NewFakePrompter(),
		}

		k := &Kind{}
		err := k.Undo(context.Background(), env, s)
		require.NoError(t, err)

		assert.Contains(t, out.String(), "[dry-run]")
	})

	t.Run("nothing to undo", func(t *testing.T) {
		env := testutil.NewTestEnvT(t)

		javaHome := filepath.Join(env.TempDir, "jdk")
		libDir := filepath.Join(javaHome, "lib", "security")
		require.NoError(t, os.MkdirAll(libDir, 0755))

		cacertsPath := filepath.Join(libDir, "cacerts")
		require.NoError(t, os.WriteFile(cacertsPath, []byte("fake"), 0644))

		env.Environ["JAVA_HOME"] = javaHome

		var out bytes.Buffer
		fakePriv := privilege.NewFakeEscalator()
		s := &fixrun.Session{
			DryRun: false, TempDir: env.TempDir, Stamp: "20260101130000",
			Priv: fakePriv, Out: &out, Run: env.Run,
			Prompt: prompt.NewFakePrompter(),
		}

		k := &Kind{}
		err := k.Undo(context.Background(), env, s)
		require.NoError(t, err)

		// No output when nothing to undo
		assert.Equal(t, "", out.String())
	})
}

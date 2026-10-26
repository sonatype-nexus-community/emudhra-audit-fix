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

package uvenv

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
)

func TestNewEnv(t *testing.T) {
	home := t.TempDir()
	uvBin := filepath.Join(home, "bin", "uv")

	env := &kinds.Env{
		Environ: map[string]string{
			"HOME":                  home,
			"UV_PYTHON_INSTALL_DIR": filepath.Join(home, "custom-python"),
			"UV_TOOL_DIR":           filepath.Join(home, "custom-tools"),
		},
	}

	uvenv := NewEnv(env, uvBin)

	assert.Equal(t, uvBin, uvenv.UV)
	assert.Equal(t, filepath.Join(home, "custom-python"), uvenv.PythonDir)
	assert.Equal(t, filepath.Join(home, "custom-tools"), uvenv.ToolDir)
}

func TestNewEnvDefaults(t *testing.T) {
	home := t.TempDir()
	uvBin := filepath.Join(home, "bin", "uv")

	env := &kinds.Env{
		Environ: map[string]string{
			"HOME": home,
		},
	}

	uvenv := NewEnv(env, uvBin)

	assert.Equal(t, filepath.Join(home, ".local", "share", "uv", "python"), uvenv.PythonDir)
	assert.Equal(t, filepath.Join(home, ".local", "share", "uv", "tools"), uvenv.ToolDir)
}

func TestToolNameSafe(t *testing.T) {
	for name, want := range map[string]bool{
		"ruff": true, "my-tool_2.0": true, "A9": true,
		"": false, "-rf": false, ".hidden": false, "a b": false, "a/b": false,
		"a:b": false, "a;b": false, "a$b": false, "naïve": false, "a\nb": false,
	} {
		assert.Equal(t, want, ToolNameSafe(name), "%q", name)
	}
}

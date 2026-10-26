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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The script requires the backup root to be owned by the user running it
// ([ -O "$backup_root" ]), so another user cannot plant a directory to receive
// the backups. A non-root test cannot create a directory owned by someone else,
// so the user the code compares against is swapped.
func TestUVPrepareBackupsRefusesARootOwnedBySomeoneElse(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "install")
	root := filepath.Join(dir, "backups")
	require.NoError(t, os.MkdirAll(source, 0o755))
	require.NoError(t, os.MkdirAll(root, 0o700))

	real := currentUID
	t.Cleanup(func() { currentUID = real })

	currentUID = real
	require.NoError(t, UVPrepareBackups(source, root, nil), "owned by us is accepted")

	currentUID = func() int { return real() + 1 }
	err := UVPrepareBackups(source, root, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not owned by current user")
}

func TestUVPrepareBackupsHonoursADiskSpaceCheck(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "install")
	root := filepath.Join(dir, "backups")
	require.NoError(t, os.MkdirAll(source, 0o755))

	require.NoError(t, UVPrepareBackups(source, root, func(string) (uint64, error) { return 1 << 30, nil }))

	err := UVPrepareBackups(source, root, func(string) (uint64, error) { return 0, fmt.Errorf("no space left on device") })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk space check failed")
}

// The script resolves an entrypoint's directory with `cd -P ... || return 1`: a
// directory that cannot be resolved is unsafe. Comparing the unresolved text
// instead would accept an entrypoint whose directory is missing or swapped.
func TestUVToolEntrypointsSafeRefusesAnUnresolvableDirectory(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "tools", "alpha")
	bindir := filepath.Join(dir, "bin") // never created, so it cannot be resolved
	require.NoError(t, os.MkdirAll(tool, 0o755))

	listing := fmt.Sprintf("alpha v1.0 (%s)\n- alpha-cli (%s)\n", tool, filepath.Join(bindir, "alpha-cli"))
	ok, err := UVToolEntrypointsSafe("alpha", tool, bindir, listing)
	assert.False(t, ok)
	assert.Error(t, err)
}

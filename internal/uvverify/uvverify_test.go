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

package uvverify

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/privilege"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/prompt"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

// stubPython plays an interpreter. `info` prints its metadata; `default` and `certifi` print what
// the TLS probe would ("ok|certerr|err URL" per host); `-m pip download` reports a certificate
// error, an answer from the server, or a network failure. Each path's behaviour is a knob.
func stubPython(version, certifi, pip, impl, def, cert, pipMode string) string {
	return `#!/bin/sh
case "$*" in
  *"-m pip download"*)
    # the control host is reachable and trusted; only the bad hosts differ
    case "$*" in
      *github.com*) echo "ERROR: 404 emudhra-probe-does-not-exist" >&2; exit 1 ;;
    esac
    case "` + pipMode + `" in
      reject) echo "SSLError: CERTIFICATE_VERIFY_FAILED" >&2; exit 1 ;;
      trust)  echo "ERROR: 404 emudhra-probe-does-not-exist" >&2; exit 1 ;;
      *)      echo "NewConnectionError" >&2; exit 1 ;;
    esac ;;
esac
mode="$4"
shift 4 2>/dev/null
emit() {
  case "$1" in
    reject) printf 'ok %s\ncerterr %s\ncerterr %s\n' "$2" "$3" "$4" ;;
    trust)  printf 'ok %s\nok %s\nok %s\n' "$2" "$3" "$4" ;;
    *)      printf 'ok %s\nerr %s\nerr %s\n' "$2" "$3" "$4" ;;
  esac
}
case "$mode" in
  info) cat <<'EOT'
pyver=` + version + `
baseprefix=/x
implementation=` + impl + `
certifi=` + certifi + `
pip=` + pip + `
cafile=
openssl=OpenSSL 3
EOT
  ;;
  default) emit ` + def + ` "$@" ;;
  certifi) emit ` + cert + ` "$@" ;;
esac
`
}

type pyOpts struct{ version, certifi, pip, impl, def, cert, pip3 string }

func good() pyOpts {
	return pyOpts{"3.11.17", "2026.10.19", "26.2.2", "cpython", "reject", "reject", "reject"}
}

func writePython(t *testing.T, o pyOpts) (*kinds.Env, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "python")
	require.NoError(t, os.WriteFile(p, []byte(stubPython(o.version, o.certifi, o.pip, o.impl, o.def, o.cert, o.pip3)), 0o755))
	env := testutil.NewTestEnvT(t)
	env.Run = exec.NewRealRunner()
	env.Environ = map[string]string{"HOME": dir, "PATH": dir}
	return env, p
}

func TestPython_ACleanInterpreterPasses(t *testing.T) {
	env, p := writePython(t, good())
	r := Python(context.Background(), env, p, "3.11", "")
	assert.True(t, r.Passed(), r.Reason)
	assert.Equal(t, "3.11.17", r.Version)
}

func TestPython_EachFailureHasItsOwnReason(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*pyOpts)
		minimum string
		minor   string
		want    string
	}{
		{"unreadable metadata", func(o *pyOpts) { o.impl = "" }, "", "3.11", "Python minor version or implementation changed unexpectedly"},
		{"a different minor line", func(o *pyOpts) { o.version = "3.12.1" }, "", "3.11", "Python minor version or implementation changed unexpectedly"},
		{"not CPython", func(o *pyOpts) { o.impl = "pypy" }, "", "3.11", "Python minor version or implementation changed unexpectedly"},
		{"older than the available patch", func(o *pyOpts) { o.version = "3.11.15" }, "3.11.17", "3.11", "selected Python 3.11.15 is older than the available patch 3.11.17"},
		{"certifi too old", func(o *pyOpts) { o.certifi = "2026.1.1" }, "", "3.11", "certifi 2026.1.1 is still older than the fixed release 2026.10.19"},
		{"pip too old", func(o *pyOpts) { o.pip = "26.2.1" }, "", "3.11", "pip 26.2.1 is still older than the fixed release 26.2.2"},
		{"default store still trusts", func(o *pyOpts) { o.def = "trust" }, "", "3.11", "default TLS probe: trusted"},
		{"default store inconclusive", func(o *pyOpts) { o.def = "err" }, "", "3.11", "default TLS probe: inconclusive"},
		{"certifi bundle still trusts", func(o *pyOpts) { o.cert = "trust" }, "", "3.11", "certifi TLS probe: trusted"},
		{"pip still trusts", func(o *pyOpts) { o.pip3 = "trust" }, "", "3.11", "pip TLS probe: trusted"},
		{"pip inconclusive cannot pass", func(o *pyOpts) { o.pip3 = "err" }, "", "3.11", "pip TLS probe: inconclusive"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := good()
			c.mutate(&o)
			env, p := writePython(t, o)
			r := Python(context.Background(), env, p, c.minor, c.minimum)
			assert.False(t, r.Passed())
			assert.Equal(t, c.want, r.Reason)
		})
	}
}

// A path that does not apply must not count against the interpreter: no certifi means no
// certifi probe, no pip means no pip probe.
func TestPython_AbsentCertifiAndPipAreNotProbedOrCounted(t *testing.T) {
	o := good()
	o.certifi, o.cert, o.pip, o.pip3 = "", "trust", "", "trust" // would fail if they were probed
	env, p := writePython(t, o)
	r := Python(context.Background(), env, p, "3.11", "")
	assert.True(t, r.Passed(), r.Reason)
}

func TestPython_AnInterpreterThatCannotRunIsReported(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "python")
	require.NoError(t, os.WriteFile(p, []byte("#!/bin/sh\nexit 1\n"), 0o755))
	env := testutil.NewTestEnvT(t)
	env.Run = exec.NewRealRunner()
	r := Python(context.Background(), env, p, "3.11", "")
	assert.Equal(t, "Python metadata could not be read", r.Reason)
}

// ---- Ready ---------------------------------------------------------------------------

func readySession(t *testing.T, uvOutput string) (*fixrun.Session, *bytes.Buffer, string) {
	t.Helper()
	dir := t.TempDir()
	uv := filepath.Join(dir, "uv")
	require.NoError(t, os.WriteFile(uv, []byte("#!/bin/sh\necho '"+uvOutput+"'\n"), 0o755))
	var out bytes.Buffer
	return &fixrun.Session{Run: exec.NewRealRunner(), Prompt: prompt.NewFakePrompter(), Priv: privilege.NewFakeEscalator(), Out: &out}, &out, uv
}

func TestReady(t *testing.T) {
	cases := []struct {
		name, out string
		want      bool
		msg       string
	}{
		{"the fixed release", "uv 0.13.4 (abc 2026-10-01)", true, ""},
		{"newer", "uv 0.13.5 (abc 2026-10-21)", true, ""},
		{"much newer", "uv 1.2.0", true, ""},
		{"older", "uv 0.13.3 (abc)", false, "uv 0.13.3 cannot safely perform these downloads; upgrade uv itself first to 0.13.4 or later"},
		{"much older", "uv 0.9.0", false, "uv 0.9.0 cannot safely perform"},
		{"a pre-release is not x.y.z", "uv 0.13.5-rc1 (abc)", false, "uv 0.13.5-rc1 cannot safely perform"},
		{"unreadable", "garbage", false, "uv unknown cannot safely perform"},
		{"empty", "", false, "uv unknown cannot safely perform"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, out, uv := readySession(t, c.out)
			assert.Equal(t, c.want, Ready(context.Background(), s, uv))
			if c.msg != "" {
				assert.Contains(t, out.String(), c.msg)
			} else {
				assert.Empty(t, out.String())
			}
		})
	}
}

func TestUVVersion(t *testing.T) {
	s, _, uv := readySession(t, "uv 0.13.5 (46776a95d 2026-10-21 aarch64-apple-darwin)")
	assert.Equal(t, "0.13.5", UVVersion(context.Background(), s, uv))
}

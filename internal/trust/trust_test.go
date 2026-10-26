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

package trust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBundle(t *testing.T) {
	// An empty bundle parses to an empty bundle, not an error.
	bundle, err := ParseBundle([]byte{})
	assert.NoError(t, err)
	assert.NotNil(t, bundle)
	assert.Equal(t, 0, bundle.Count())
}

func TestCountCerts(t *testing.T) {
	count, err := CountCerts([]byte{})
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestSanityCheck(t *testing.T) {
	// Empty bundle should fail sanity check
	bundle := &Bundle{Certs: []*x509.Certificate{}}
	err := bundle.SanityCheck()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no valid certificates")
}

func TestNormalizeSubject(t *testing.T) {
	result := normalizeSubject("  AAA   Certificate   Services  ")
	assert.Equal(t, "AAA Certificate Services", result)
}

func TestStripRoots(t *testing.T) {
	// Stripping an empty bundle removes nothing.
	bundle, err := ParseBundle([]byte{})
	require.NoError(t, err)

	result, removed, err := bundle.StripRoots()
	require.NoError(t, err)
	assert.Equal(t, 0, removed)
	// Result may be nil or empty byte slice for empty bundle
	if result != nil {
		assert.Equal(t, 0, len(result))
	}
}

func TestBundleString(t *testing.T) {
	bundle := &Bundle{Certs: []*x509.Certificate{}}
	str := bundle.String()
	assert.Contains(t, str, "certs: 0")
}

// certPEM makes a self-signed CA certificate with the given common name.
func certPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestStripRootsRemovesExactlyTheTwoRootsAndKeepsEverythingElse(t *testing.T) {
	keepA, keepB := certPEM(t, "Good Root A"), certPEM(t, "Good Root B")
	nearMiss := certPEM(t, "AAA Certificate Services 2") // not the root: must stay
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a certificate")})
	var in bytes.Buffer
	for _, b := range [][]byte{keepA, certPEM(t, "AAA Certificate Services"), key, keepB, certPEM(t, "emSign ECC Root CA - G3"), nearMiss} {
		in.Write(b)
	}

	out, removed, err := StripRootsFromData(in.Bytes())

	require.NoError(t, err)
	assert.Equal(t, 2, removed)
	remaining, err := ParseBundle(out)
	require.NoError(t, err)
	var names []string
	for _, c := range remaining.Certs {
		names = append(names, c.Subject.CommonName)
	}
	assert.Equal(t, []string{"Good Root A", "Good Root B", "AAA Certificate Services 2"}, names, "order preserved, near miss kept")
	assert.False(t, remaining.ContainsRoot())
	assert.Contains(t, string(out), "PRIVATE KEY", "non-certificate blocks are written back as they were")
}

func TestBundleReportsTheRootsItContains(t *testing.T) {
	var in bytes.Buffer
	for _, cn := range []string{"Good Root A", "emSign ECC Root CA - G3", "emSign ECC Root CA - G3"} {
		in.Write(certPEM(t, cn))
	}
	b, err := ParseBundle(in.Bytes())
	require.NoError(t, err)

	assert.Equal(t, 3, b.Count())
	assert.True(t, b.ContainsRoot())
	assert.Equal(t, []string{"emSign ECC Root CA - G3"}, b.RootsPresent(), "each root once")
	assert.NoError(t, b.SanityCheck())
	has, err := BundleHasRoots(in.Bytes())
	require.NoError(t, err)
	assert.True(t, has)
	n, err := CountCerts(in.Bytes())
	require.NoError(t, err)
	assert.Equal(t, 3, n)
}

func TestACleanBundleHasNoRoots(t *testing.T) {
	b, err := ParseBundle(certPEM(t, "Good Root A"))
	require.NoError(t, err)
	assert.False(t, b.ContainsRoot())
	assert.Empty(t, b.RootsPresent())
}

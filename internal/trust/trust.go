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

// Package trust provides PEM bundle helpers: strip_roots, count, sanity_check.
// Uses crypto/x509 and encoding/pem to manipulate certificate bundles.
package trust

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/advisory"
)

// Bundle represents a PEM certificate bundle.
type Bundle struct {
	Certs []*x509.Certificate
	Raw   []byte
}

// ParseBundle parses a PEM-encoded certificate bundle.
func ParseBundle(data []byte) (*Bundle, error) {
	var certs []*x509.Certificate
	remaining := data

	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			remaining = rest
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// Skip invalid certificates but continue parsing
			remaining = rest
			continue
		}

		certs = append(certs, cert)
		remaining = rest
	}

	return &Bundle{
		Certs: certs,
		Raw:   data,
	}, nil
}

// StripRoots returns a new bundle with the two distrusted roots removed.
// Returns the count of removed certificates.
func (b *Bundle) StripRoots() ([]byte, int, error) {
	var buf bytes.Buffer
	removed := 0

	remaining := b.Raw
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			// Write non-certificate blocks as-is
			if err := pem.Encode(&buf, block); err != nil {
				return nil, 0, fmt.Errorf("encoding PEM block: %w", err)
			}
			remaining = rest
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// Write invalid certificates as-is
			if err := pem.Encode(&buf, block); err != nil {
				return nil, 0, fmt.Errorf("encoding PEM block: %w", err)
			}
			remaining = rest
			continue
		}

		// Check if this is a root to distrust
		if advisory.IsRootToDistrust(cert.Subject.CommonName) {
			removed++
		} else {
			// Keep this certificate
			if err := pem.Encode(&buf, block); err != nil {
				return nil, 0, fmt.Errorf("encoding PEM block: %w", err)
			}
		}

		remaining = rest
	}

	return buf.Bytes(), removed, nil
}

// Count returns the count of certificates in the bundle.
func (b *Bundle) Count() int {
	return len(b.Certs)
}

// ContainsRoot returns true if any certificate in the bundle matches one of the distrusted roots.
func (b *Bundle) ContainsRoot() bool {
	for _, cert := range b.Certs {
		if advisory.IsRootToDistrust(cert.Subject.CommonName) {
			return true
		}
	}
	return false
}

// SanityCheck performs basic sanity checks on a certificate bundle.
// Returns an error if the bundle appears malformed or empty.
func (b *Bundle) SanityCheck() error {
	if len(b.Certs) == 0 {
		return fmt.Errorf("bundle contains no valid certificates")
	}

	// Check for obviously invalid certificates
	for i, cert := range b.Certs {
		if cert == nil {
			return fmt.Errorf("certificate %d is nil", i)
		}
		if len(cert.Raw) == 0 {
			return fmt.Errorf("certificate %d has no raw data", i)
		}
	}

	return nil
}

// RootsPresent returns the list of distrusted roots found in the bundle.
func (b *Bundle) RootsPresent() []string {
	var roots []string
	seen := make(map[string]bool)

	for _, cert := range b.Certs {
		name := cert.Subject.CommonName
		if name == "" {
			name = cert.Subject.String()
		}
		if advisory.IsRootToDistrust(name) && !seen[name] {
			roots = append(roots, name)
			seen[name] = true
		}
	}

	return roots
}

// String returns a human-readable summary of the bundle.
func (b *Bundle) String() string {
	return fmt.Sprintf("Bundle{certs: %d, affected: %v}", b.Count(), b.ContainsRoot())
}

// CountCerts is a convenience function that counts certificates in PEM data.
func CountCerts(data []byte) (int, error) {
	bundle, err := ParseBundle(data)
	if err != nil {
		return 0, err
	}
	return bundle.Count(), nil
}

// StripRootsFromData is a convenience function that strips roots from PEM data.
func StripRootsFromData(data []byte) ([]byte, int, error) {
	bundle, err := ParseBundle(data)
	if err != nil {
		return nil, 0, err
	}
	return bundle.StripRoots()
}

// BundleHasRoots returns true if the PEM data contains any of the distrusted roots.
func BundleHasRoots(data []byte) (bool, error) {
	bundle, err := ParseBundle(data)
	if err != nil {
		return false, err
	}
	return bundle.ContainsRoot(), nil
}

// normalizeSubject normalizes a certificate subject for comparison.
func normalizeSubject(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

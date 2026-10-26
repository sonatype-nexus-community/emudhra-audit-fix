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

// Package prompt handles user confirmation prompts, opening /dev/tty directly.
// This matches the script's confirm()/confirm_agree() semantics exactly.
package prompt

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Prompter is an interface for prompting users for confirmation.
type Prompter interface {
	// Confirm prompts the user with a y/N question.
	// Returns true if the user answers 'y' or 'yes' (case-insensitive).
	// With --yes, returns true without prompting.
	// With no TTY, returns false and logs a warning.
	Confirm(prompt string, yes bool) bool

	// ConfirmAgree prompts for exact "I AGREE" input (destructive operations).
	// Returns true only if the user types exactly "I AGREE" (preserving whitespace).
	// --yes NEVER answers this (returns false).
	// EOF (Ctrl+D) is refusal.
	// No TTY means no, with a warning.
	ConfirmAgree(prompt string) bool
}

// RealPrompter is the real implementation that reads from /dev/tty.
type RealPrompter struct {
	hasTTY bool
}

// NewRealPrompter creates a new RealPrompter.
func NewRealPrompter(hasTTY bool) *RealPrompter {
	return &RealPrompter{hasTTY: hasTTY}
}

// Confirm prompts the user with a y/N question.
func (p *RealPrompter) Confirm(prompt string, yes bool) bool {
	// With --yes, answer yes without prompting
	if yes {
		return true
	}

	// No TTY means no, with a warning
	if !p.hasTTY {
		fmt.Fprintf(os.Stderr, "WARNING: no TTY, cannot ask for confirmation; assuming no\n")
		return false
	}

	// Open /dev/tty directly (not stdin)
	tty, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: cannot open /dev/tty: %v; assuming no\n", err)
		return false
	}
	defer func() { _ = tty.Close() }()

	// Print prompt to stderr (preserves stdout for structured output)
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", prompt)

	// Read response
	reader := bufio.NewReader(tty)
	response, err := reader.ReadString('\n')
	if err != nil {
		// EOF is refusal
		fmt.Fprintf(os.Stderr, "\n")
		return false
	}

	// Trim whitespace and check
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

// ConfirmAgree prompts for exact "I AGREE" input.
func (p *RealPrompter) ConfirmAgree(prompt string) bool {
	// --yes NEVER answers this
	// No TTY means no
	if !p.hasTTY {
		fmt.Fprintf(os.Stderr, "WARNING: no TTY, cannot ask for confirmation; assuming no\n")
		return false
	}

	// Open /dev/tty
	tty, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: cannot open /dev/tty: %v; assuming no\n", err)
		return false
	}
	defer func() { _ = tty.Close() }()

	// Print prompt
	fmt.Fprintf(os.Stderr, "%s\n(type exactly 'I AGREE' to proceed): ", prompt)

	// Read response (preserving whitespace)
	reader := bufio.NewReader(tty)
	response, err := reader.ReadString('\n')
	if err != nil {
		// EOF is refusal
		fmt.Fprintf(os.Stderr, "\n")
		return false
	}

	// Remove trailing newline but preserve other whitespace
	response = strings.TrimSuffix(response, "\n")
	response = strings.TrimSuffix(response, "\r")

	// Must match exactly
	return response == "I AGREE"
}

// FakePrompter is a test implementation that returns scripted responses.
type FakePrompter struct {
	// ConfirmResponses is a queue of responses for Confirm calls.
	ConfirmResponses []bool

	// ConfirmAgreeResponses is a queue of responses for ConfirmAgree calls.
	ConfirmAgreeResponses []bool

	// ConfirmCalled tracks how many times Confirm was called.
	ConfirmCalled int

	// ConfirmAgreeCalled tracks how many times ConfirmAgree was called.
	ConfirmAgreeCalled int
}

// NewFakePrompter creates a new FakePrompter.
func NewFakePrompter() *FakePrompter {
	return &FakePrompter{
		ConfirmResponses:      make([]bool, 0),
		ConfirmAgreeResponses: make([]bool, 0),
	}
}

// Confirm returns the next scripted response.
func (f *FakePrompter) Confirm(prompt string, yes bool) bool {
	f.ConfirmCalled++
	// With --yes, return true immediately (matches RealPrompter behavior)
	if yes {
		return true
	}
	if len(f.ConfirmResponses) == 0 {
		return false
	}
	result := f.ConfirmResponses[0]
	f.ConfirmResponses = f.ConfirmResponses[1:]
	return result
}

// ConfirmAgree returns the next scripted response.
func (f *FakePrompter) ConfirmAgree(prompt string) bool {
	f.ConfirmAgreeCalled++
	if len(f.ConfirmAgreeResponses) == 0 {
		return false
	}
	result := f.ConfirmAgreeResponses[0]
	f.ConfirmAgreeResponses = f.ConfirmAgreeResponses[1:]
	return result
}

// AddConfirm adds a scripted response for Confirm.
func (f *FakePrompter) AddConfirm(response bool) {
	f.ConfirmResponses = append(f.ConfirmResponses, response)
}

// AddConfirmAgree adds a scripted response for ConfirmAgree.
func (f *FakePrompter) AddConfirmAgree(response bool) {
	f.ConfirmAgreeResponses = append(f.ConfirmAgreeResponses, response)
}

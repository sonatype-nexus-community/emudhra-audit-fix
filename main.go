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

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/banner"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/cli"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/logging"
)

// version and commit are set via -ldflags at build time (see .goreleaser.yml).
var (
	version = "dev"
	commit  = "none"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Set version in cli package
	cli.SetVersion(version, commit)

	// Parse flags and build options
	opts, err := cli.ParseFlags(os.Args[1:], version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	// Setup logging
	// -v is a fuller report on stdout, not more logging; -vv adds the probe commands and raw
	// TLS errors the script's -vv prints, and -vvv traces.
	logLevel := slog.LevelInfo
	if opts.Verbose == 2 {
		logLevel = slog.LevelDebug
	} else if opts.Verbose >= 3 {
		logLevel = logging.LevelTrace
	}
	logger := logging.New(logLevel, "text", os.Stderr)

	// Print banner (TTY-only, suppressed when not a tty or with --quiet)
	if opts.ShowBanner {
		banner.Print(os.Stdout, version)
	}

	// Execute command
	exitCode := cli.Execute(ctx, opts, logger)
	os.Exit(exitCode)
}

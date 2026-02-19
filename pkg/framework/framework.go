// Package framework provides a reusable library for building CLI tools on top
// of the Fastly authentication and API client setup. It decouples the
// initialisation, auth, and command dispatch logic from the full set of built-in
// CLI commands so that external tools can authenticate and call the Fastly API
// using the same patterns.
package framework

import (
	"fmt"
	"io"
)

// RunWithOptions is the top-level entry point that initialises application
// state and executes the resolved command.
func RunWithOptions(args []string, stdin io.Reader, opts Options) error {
	data, err := InitWithOptions(args, stdin, opts)
	if err != nil {
		return fmt.Errorf("failed to initialise application: %w", err)
	}
	return ExecWithOptions(data, opts)
}

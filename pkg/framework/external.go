package framework

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/fastly/cli/pkg/global"
)

// ExternalCommandLookup configures the external command (plugin) dispatch.
type ExternalCommandLookup struct {
	// Prefix is the binary prefix, e.g. "fastly".
	Prefix string
}

// Lookup takes the raw args and searches for a matching external binary.
// It builds candidate names from longest to shortest:
// e.g. "fastly-cmd-subcmd", "fastly-cmd" and checks exec.LookPath for each.
func (e *ExternalCommandLookup) Lookup(args []string) (binPath string, remainingArgs []string, found bool) {
	words := extractCommandWords(args)
	if len(words) == 0 {
		return "", nil, false
	}

	// Try longest match first.
	for i := len(words); i > 0; i-- {
		candidate := e.Prefix + "-" + strings.Join(words[:i], "-")
		if p, err := exec.LookPath(candidate); err == nil {
			remaining := append(words[i:], extractFlags(args)...)
			return p, remaining, true
		}
	}

	return "", nil, false
}

// extractCommandWords returns the non-flag arguments from args.
func extractCommandWords(args []string) []string {
	var words []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		words = append(words, a)
	}
	return words
}

// extractFlags returns only the flag arguments from args.
func extractFlags(args []string) []string {
	var flags []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		}
	}
	return flags
}

// externalCommand implements argparser.Command for external binaries.
type externalCommand struct {
	binPath string
	args    []string
	cmdName string
	data    *global.Data
}

// Name returns the command name.
func (c *externalCommand) Name() string {
	return c.cmdName
}

// Exec runs the external binary, inheriting stdin/stdout/stderr, and passing
// FASTLY_API_TOKEN and FASTLY_API_ENDPOINT via the environment if available.
func (c *externalCommand) Exec(_ io.Reader, _ io.Writer) error {
	// gosec flagged this:
	// G204 (CWE-78): Subprocess launched with variable
	// Disabling as we only execute binaries found via exec.LookPath.
	/* #nosec */
	cmd := exec.Command(c.binPath, c.args...) //nolint:gosec
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	// Pass token and endpoint to the subprocess via environment.
	if token, _ := c.data.Token(); token != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("FASTLY_API_TOKEN=%s", token))
	}
	if endpoint, _ := c.data.APIEndpoint(); endpoint != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("FASTLY_API_ENDPOINT=%s", endpoint))
	}

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("external command exited with code %d", exitErr.ExitCode())
		}
		return fmt.Errorf("failed to run external command %s: %w", c.binPath, err)
	}
	return nil
}

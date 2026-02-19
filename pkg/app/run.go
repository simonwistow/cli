package app

import (
	"fmt"
	"io"

	"github.com/fastly/cli/pkg/api"
	"github.com/fastly/cli/pkg/commands"
	"github.com/fastly/cli/pkg/commands/compute"
	"github.com/fastly/cli/pkg/framework"
	"github.com/fastly/cli/pkg/github"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/manifest"
)

// Run kick starts the CLI application.
//
// NOTE: We call Init (var) and Exec separately so that tests can mock Init.
func Run(args []string, stdin io.Reader) error {
	data, err := Init(args, stdin)
	if err != nil {
		return fmt.Errorf("failed to initialise application: %w", err)
	}
	return Exec(data)
}

// Init constructs all the required objects and data for Exec().
//
// NOTE: We define as a package level variable so we can mock output for tests.
var Init = func(args []string, stdin io.Reader) (*global.Data, error) {
	return framework.InitWithOptions(args, stdin, fastlyCLIOptions())
}

// Exec constructs the application including all of the subcommands, parses the
// args, invokes the client factory with the token to create a Fastly API
// client, and executes the chosen command, using the provided io.Reader and
// io.Writer for input and output, respectively. In the real CLI, func main is
// just a simple shim to this function; it exists to make end-to-end testing of
// commands easier/possible.
//
// The Exec helper should NOT output any error-related information to the out
// io.Writer. All error-related information should be encoded into an error type
// and returned to the caller. This includes usage text.
func Exec(data *global.Data) error {
	return framework.ExecWithOptions(data, fastlyCLIOptions())
}

// fastlyCLIOptions returns the Options that wire together the full Fastly CLI.
func fastlyCLIOptions() framework.Options {
	return framework.Options{
		AppName:        "fastly",
		AppHelp:        "A tool to interact with the Fastly API",
		DefineCommands: commands.Define,
		ConfigureVersioners: func(c api.HTTPClient, debugMode bool, md manifest.Data) global.Versioners {
			return global.Versioners{
				CLI: github.New(github.Opts{
					DebugMode:  debugMode,
					HTTPClient: c,
					Org:        "fastly",
					Repo:       "cli",
					Binary:     "fastly",
				}),
				Viceroy: github.New(github.Opts{
					DebugMode:  debugMode,
					HTTPClient: c,
					Org:        "fastly",
					Repo:       "viceroy",
					Binary:     "viceroy",
					Version:    md.File.LocalServer.ViceroyVersion,
				}),
				WasmTools: github.New(github.Opts{
					DebugMode:  debugMode,
					HTTPClient: c,
					Org:        "bytecodealliance",
					Repo:       "wasm-tools",
					Binary:     "wasm-tools",
					External:   true,
					Nested:     true,
				}),
			}
		},
		ExecuteWasmTools: compute.ExecuteWasmTools,
		CheckForUpdates:  true,
		ExternalLookup:   &framework.ExternalCommandLookup{Prefix: "fastly"},
	}
}


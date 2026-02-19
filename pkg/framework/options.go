package framework

import (
	"io"

	"github.com/fastly/kingpin"

	"github.com/fastly/cli/pkg/api"
	"github.com/fastly/cli/pkg/argparser"
	"github.com/fastly/cli/pkg/github"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/manifest"
)

// CommandDefiner registers commands with a kingpin Application and returns the
// list of all defined commands.
type CommandDefiner func(app *kingpin.Application, data *global.Data) []argparser.Command

// Options configures the framework's behaviour. External consumers provide
// their own Options to build lightweight tools on top of the Fastly
// authentication and API client setup.
type Options struct {
	// AppName is the kingpin application name (default: "fastly").
	AppName string
	// AppHelp is the kingpin application help text.
	AppHelp string
	// DefaultCommand is the default command to run if no command is passed; if nil, and no command is passed then no command will be run
	DefaultCommand string
	// DefineCommands registers commands; if nil, no built-in commands are loaded.
	DefineCommands CommandDefiner
	// ConfigureVersioners returns version checkers for CLI, Viceroy, etc.
	// If nil, versioners are left at their zero value.
	ConfigureVersioners func(c api.HTTPClient, debug bool, md manifest.Data) global.Versioners
	// ExecuteWasmTools is a function that executes the wasm-tools binary.
	// If nil, the field in global.Data is left unset.
	ExecuteWasmTools func(bin string, args []string, g *global.Data) error
	// CheckForUpdates enables the async update check at the end of command execution.
	CheckForUpdates bool
	// ExternalLookup enables plugin dispatch for unrecognised commands.
	// If nil, external dispatch is disabled.
	ExternalLookup *ExternalCommandLookup

	// Stdin overrides the default os.Stdin reader.
	// If nil, the stdin argument to RunWithOptions / InitWithOptions is used.
	Stdin io.Reader
}

// CheckFunc is the type of the async update-check function.
type CheckFunc func(av github.AssetVersioner, commandName string, quietMode bool) func(io.Writer)

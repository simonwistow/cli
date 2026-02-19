package framework

import (
	"fmt"
	"io"

	"github.com/fastly/kingpin"

	"github.com/fastly/cli/pkg/env"
	"github.com/fastly/cli/pkg/global"
)

// ConfigureKingpin creates and configures the kingpin application with global
// flags. The appName and appHelp parameters allow callers to customise the
// application identity.
func ConfigureKingpin(data *global.Data, appName, appHelp string) *kingpin.Application {
	if appName == "" {
		appName = "fastly"
	}
	if appHelp == "" {
		appHelp = "A tool to interact with the Fastly API"
	}

	app := kingpin.New(appName, appHelp)
	app.Writers(data.Output, io.Discard)
	app.UsageContext(&kingpin.UsageContext{
		Template: VerboseUsageTemplate,
		Funcs:    UsageTemplateFuncs,
	})

	// Prevent kingpin from calling os.Exit.
	app.Terminate(nil)

	// IMPORTANT: Kingpin doesn't support global flags.
	// Any flags defined below must also be added to two other places:
	// 1. ./usage.go (`GlobalFlags` map).
	// 2. ../cmd/argparser.go (`IsGlobalFlagsOnly` function).
	//
	// NOTE: Global flags (long and short) MUST be unique.
	tokenHelp := fmt.Sprintf("Fastly API token (or via %s)", env.APIToken)
	app.Flag("accept-defaults", "Accept default options for all interactive prompts apart from Yes/No confirmations").Short('d').BoolVar(&data.Flags.AcceptDefaults)
	app.Flag("account", "Fastly Accounts endpoint").Hidden().StringVar(&data.Flags.AccountEndpoint)
	app.Flag("api", "Fastly API endpoint").Hidden().StringVar(&data.Flags.APIEndpoint)
	app.Flag("auto-yes", "Answer yes automatically to all Yes/No confirmations. This may suppress security warnings").Short('y').BoolVar(&data.Flags.AutoYes)
	app.Flag("debug-mode", "Print API request and response details (NOTE: can disrupt the normal CLI flow output formatting)").BoolVar(&data.Flags.Debug)
	app.Flag("enable-sso", "Enable Single-Sign On (SSO) for current profile execution (see also: 'fastly sso')").BoolVar(&data.Flags.SSO)
	app.Flag("non-interactive", "Do not prompt for user input - suitable for CI processes. Equivalent to --accept-defaults and --auto-yes").Short('i').BoolVar(&data.Flags.NonInteractive)
	app.Flag("profile", "Switch account profile for single command execution (see also: 'fastly profile switch')").Short('o').StringVar(&data.Flags.Profile)
	app.Flag("quiet", "Silence all output except direct command output. This won't prevent interactive prompts (see: --accept-defaults, --auto-yes, --non-interactive)").Short('q').BoolVar(&data.Flags.Quiet)
	app.Flag("token", tokenHelp).HintAction(env.Vars).Short('t').StringVar(&data.Flags.Token)
	app.Flag("verbose", "Verbose logging").Short('v').BoolVar(&data.Flags.Verbose)

	return app
}

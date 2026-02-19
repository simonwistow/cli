package framework

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fastly/cli/pkg/argparser"
	fsterr "github.com/fastly/cli/pkg/errors"
	"github.com/fastly/cli/pkg/github"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/revision"
	"github.com/fastly/cli/pkg/text"
)

// ExecWithOptions wires together the command lifecycle: command parsing, auth,
// API client creation, and command execution. It uses opts to decide how
// commands are defined, whether to check for updates, etc.
func ExecWithOptions(data *global.Data, opts Options) error {
	app := ConfigureKingpin(data, opts.AppName, opts.AppHelp)

	var cmds []argparser.Command
	if opts.DefineCommands != nil {
		cmds = opts.DefineCommands(app, data)
	}

	var defaultCmd *string
	if opts.DefaultCommand != "" {
		defaultCmd = &opts.DefaultCommand
	}
	command, commandName, err := ProcessCommandInput(data, app, cmds, opts.ExternalLookup, defaultCmd)
	if err != nil {
		return err
	}

	// Check for --json flag early and set quiet mode if found.
	if slices.Contains(data.Args, "--json") {
		data.Flags.Quiet = true
	}

	// Short-circuit for specific cases.
	switch commandName {
	case "help--format=json", "help--formatjson", "shell-autocomplete":
		return nil
	}

	// External commands handle their own auth via env vars.
	if commandName == "external" {
		return command.Exec(data.Input, data.Output)
	}

	metadataDisable, _ := strconv.ParseBool(data.Env.WasmMetadataDisable)
	if !slices.Contains(data.Args, "--metadata-disable") && !metadataDisable && !data.Config.CLI.MetadataNoticeDisplayed && commandCollectsData(commandName) && !data.Flags.Quiet {
		text.Important(data.Output, "The Fastly CLI is configured to collect data related to Wasm builds (e.g. compilation times, resource usage, and other non-identifying data). To learn more about what data is being collected, why, and how to disable it: https://www.fastly.com/documentation/reference/cli")
		text.Break(data.Output)
		data.Config.CLI.MetadataNoticeDisplayed = true
		err := data.Config.Write(data.ConfigPath)
		if err != nil {
			return fmt.Errorf("failed to persist change to metadata notice: %w", err)
		}
		time.Sleep(5 * time.Second)
	}

	if data.Flags.Quiet {
		data.Manifest.File.SetQuiet(true)
	}

	apiEndpoint, endpointSource := data.APIEndpoint()
	if data.Verbose() && !commandSuppressesVerbose(command) {
		displayAPIEndpoint(apiEndpoint, endpointSource, data.Output)
	}

	if data.Flags.Debug {
		data.Env.DebugMode = "true"
	}

	if !commandRequiresToken(command) && commandRequiresAuthServer(commandName) {
		if data.AuthServer == nil {
			authServer, err := configureAuth(apiEndpoint, data.Args, data.Config, data.HTTPClient, data.Env)
			if err != nil {
				return fmt.Errorf("failed to configure authentication processes: %w", err)
			}
			data.AuthServer = authServer
		}
	}

	if commandRequiresToken(command) {
		if data.AuthServer == nil {
			authServer, err := configureAuth(apiEndpoint, data.Args, data.Config, data.HTTPClient, data.Env)
			if err != nil {
				return fmt.Errorf("failed to configure authentication processes: %w", err)
			}
			data.AuthServer = authServer
		}

		token, tokenSource, err := processToken(data)
		if err != nil {
			if errors.Is(err, fsterr.ErrDontContinue) {
				return nil
			}
			return fmt.Errorf("failed to process token: %w", err)
		}

		if data.Verbose() && !commandSuppressesVerbose(command) {
			displayToken(tokenSource, data)
		}
		if !data.Flags.Quiet {
			checkConfigPermissions(commandName, tokenSource, data.Output)
		}

		data.APIClient, data.RTSClient, err = configureClients(token, apiEndpoint, data.APIClientFactory, data.Flags.Debug)
		if err != nil {
			data.ErrLog.Add(err)
			return fmt.Errorf("error constructing client: %w", err)
		}
	}

	f := checkForUpdates(data.Versioners.CLI, commandName, data.Flags.Quiet, opts.CheckForUpdates)
	defer f(data.Output)

	return command.Exec(data.Input, data.Output)
}

func checkForUpdates(av github.AssetVersioner, commandName string, quietMode bool, enabled bool) func(io.Writer) {
	if enabled && av != nil && commandName != "update" && !revision.IsPreRelease(revision.AppVersion) {
		return github.CheckAsync(revision.AppVersion, av, quietMode)
	}
	return func(_ io.Writer) {
		// no-op
	}
}

// commandCollectsDataByName is an alias used by the external command check.
func commandCollectsDataByName(command string) bool {
	return commandCollectsData(command)
}

// commandRequiresTokenByName checks by command name string rather than interface.
func commandRequiresTokenByName(commandName string) bool {
	segs := strings.Split(commandName, " ")
	switch commandName {
	case "compute init", "compute build", "compute hash-files", "compute metadata", "compute serve":
		return false
	}
	switch segs[0] {
	case "config", "profile", "sso", "update", "version":
		return false
	}
	return true
}

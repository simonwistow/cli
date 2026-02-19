package framework

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/template"

	"github.com/fastly/kingpin"

	"github.com/fastly/cli/pkg/argparser"
	fsterr "github.com/fastly/cli/pkg/errors"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/text"
)

// Usage returns a contextual usage string for the application.
func Usage(args []string, app *kingpin.Application, out, errW io.Writer, vars map[string]any) string {
	var buf bytes.Buffer
	app.Writers(&buf, io.Discard)
	app.UsageContext(&kingpin.UsageContext{
		Template: CompactUsageTemplate,
		Funcs:    UsageTemplateFuncs,
		Vars:     vars,
	})
	app.Usage(args)
	app.Writers(out, errW)
	return buf.String()
}

// CompactUsageTemplate is the default usage template.
var CompactUsageTemplate = `{{define "FormatCommand" -}}
{{if .FlagSummary}} {{.FlagSummary}}{{end -}}
{{range .Args}} {{if not .Required}}[{{end}}<{{.Name}}>{{if .Value|IsCumulative}} ...{{end}}{{if not .Required}}]{{end}}{{end -}}
{{end -}}
{{define "FormatCommandList" -}}
{{range . -}}
{{if not .Hidden -}}
{{.Depth|Indent}}{{.Name}}{{if .Default}}*{{end}}{{template "FormatCommand" .}}
{{end -}}
{{template "FormatCommandList" .Commands -}}
{{end -}}
{{end -}}
{{define "FormatUsage" -}}
{{template "FormatCommand" .}}{{if .Commands}} <command> [<args> ...]{{end}}
{{if .Help}}
{{.Help|Wrap 0 -}}
{{end -}}
{{end -}}
{{define "FormatCommandName" -}}
{{if .Parent}}{{if .Parent.Parent}}{{.Parent.Parent.Name}} {{end -}}{{.Parent.Name}} {{end -}}{{.Name -}}
{{end -}}
{{if .Context.SelectedCommand -}}
{{T "USAGE"|Bold}}
  {{.App.Name}} {{template "FormatCommandName" .Context.SelectedCommand}}{{ template "FormatUsage" .Context.SelectedCommand}}
{{else -}}
{{T "USAGE"|Bold}}
  {{.App.Name}}{{template "FormatUsage" .App}}
{{end -}}
{{if .Context.Flags|RequiredFlags -}}
{{T "REQUIRED FLAGS"|Bold}}
{{.Context.Flags|RequiredFlags|FlagsToTwoColumns|FormatTwoColumns}}
{{end -}}
{{if .Context.Flags|OptionalFlags -}}
{{T "OPTIONAL FLAGS"|Bold}}
{{.Context.Flags|OptionalFlags|FlagsToTwoColumns|FormatTwoColumns}}
{{end -}}
{{if .Context.Flags|GlobalFlags -}}
{{T "GLOBAL FLAGS"|Bold}}
{{.Context.Flags|GlobalFlags|FlagsToTwoColumns|FormatTwoColumns}}
{{end -}}
{{if .Context.Args -}}
{{T "ARGS"|Bold}}
{{.Context.Args|ArgsToTwoColumns|FormatTwoColumns}}
{{end -}}
{{if .Context.SelectedCommand -}}
{{if .Context.SelectedCommand.Commands -}}
{{T "COMMANDS"|Bold}}
  {{.Context.SelectedCommand}}
{{.Context.SelectedCommand.Commands|CommandsToTwoColumns|FormatTwoColumns}}
{{end -}}
{{else if .App.Commands -}}
{{T "COMMANDS"|Bold}}
{{.App.Commands|CommandsToTwoColumns|FormatTwoColumns}}
{{end -}}
{{T "SEE ALSO"|Bold}}
{{.Context.SelectedCommand|SeeAlso}}
`

// UsageTemplateFuncs is a map of template functions for the usage template.
var UsageTemplateFuncs = template.FuncMap{
	"CommandsToTwoColumns": func(c []*kingpin.CmdModel) [][2]string {
		rows := [][2]string{}
		for _, cmd := range c {
			if !cmd.Hidden {
				rows = append(rows, [2]string{cmd.Name, cmd.Help})
			}
		}
		return rows
	},
	"GlobalFlags": func(f []*kingpin.ClauseModel) []*kingpin.ClauseModel {
		flags := []*kingpin.ClauseModel{}
		for _, flag := range f {
			if GlobalFlags[flag.Name] {
				flags = append(flags, flag)
			}
		}
		return flags
	},
	"OptionalFlags": func(f []*kingpin.ClauseModel) []*kingpin.ClauseModel {
		optionalFlags := []*kingpin.ClauseModel{}
		for _, flag := range f {
			if !flag.Required && !flag.Hidden && !GlobalFlags[flag.Name] {
				optionalFlags = append(optionalFlags, flag)
			}
		}
		return optionalFlags
	},
	"Bold": func(s string) string {
		return text.Bold(s)
	},
	"SeeAlso": func(cm *kingpin.CmdModel) string {
		cmd := cm.FullCommand()
		url := "https://www.fastly.com/documentation/reference/cli/"
		var trail string
		if len(cmd) > 0 {
			trail = "/"
		}
		return fmt.Sprintf("  %s%s%s", url, strings.ReplaceAll(cmd, " ", "/"), trail)
	},
}

// GlobalFlags is the set of flag names considered global.
//
// IMPORTANT: Kingpin doesn't support global flags.
// We hack a solution in the ConfigureKingpin function.
var GlobalFlags = map[string]bool{
	"accept-defaults": true,
	"account":         true,
	"auto-yes":        true,
	"debug-mode":      true,
	"enable-sso":      true,
	"endpoint":        true,
	"help":            true,
	"non-interactive": true,
	"profile":         true,
	"quiet":           true,
	"token":           true,
	"verbose":         true,
}

// VerboseUsageTemplate is the full-fat usage template.
const VerboseUsageTemplate = `{{define "FormatCommands" -}}
{{range .FlattenedCommands -}}
{{ if not .Hidden }}
  {{.CmdSummary|Bold }}
{{.Help|Wrap 4 }}
{{if .Flags -}}
{{with .Flags|FlagsToTwoColumns}}{{FormatTwoColumnsWithIndent . 4 2}}{{end -}}
{{end -}}
{{end -}}
{{end -}}
{{end -}}
{{define "FormatUsage" -}}
{{.AppSummary}}
{{if .Help}}
{{.Help|Wrap 0 -}}
{{end -}}
{{end -}}
{{if .Context.SelectedCommand -}}
{{T "USAGE"|Bold}}
  {{.App.Name}} {{.App.FlagSummary}} {{.Context.SelectedCommand.CmdSummary}}
{{else}}
{{- T "USAGE"|Bold}}
  {{template "FormatUsage" .App -}}
{{end -}}
{{if .Context.Flags|GlobalFlags }}
{{T "GLOBAL FLAGS"|Bold}}
{{.Context.Flags|GlobalFlags|FlagsToTwoColumns|FormatTwoColumns}}
{{end -}}
{{if .Context.Args -}}
{{T "ARGS"|Bold}}
{{.Context.Args|ArgsToTwoColumns|FormatTwoColumns}}
{{end -}}
{{if .Context.SelectedCommand -}}
{{if len .Context.SelectedCommand.Commands -}}
{{T "SUBCOMMANDS\n"|Bold -}}
  {{ template "FormatCommands" .Context.SelectedCommand}}
{{end -}}
{{else if .App.Commands -}}
{{T "COMMANDS"|Bold -}}
  {{template "FormatCommands" .App}}
{{end -}}
{{T "SEE ALSO"|Bold}}
{{.Context.SelectedCommand|SeeAlso}}
`

// ProcessCommandInput groups together all the logic related to parsing and
// processing the incoming command request from the user.
func ProcessCommandInput(
	data *global.Data,
	app *kingpin.Application,
	commands []argparser.Command,
	extLookup *ExternalCommandLookup,
	defaultCommand *string,
) (command argparser.Command, cmdName string, err error) {
	if argparser.ArgsIsHelpJSON(data.Args) {
		j, err := UsageJSON(app)
		if err != nil {
			data.ErrLog.Add(err)
			return command, cmdName, err
		}
		fmt.Fprintf(data.Output, "%s", j)
		return command, strings.Join(data.Args, ""), nil
	}

	help := displayHelp(data.ErrLog, data.Args, app, data.Output, io.Discard)

	app.Writers(io.Discard, io.Discard)

	var vars map[string]any

	if argparser.IsVerboseAndQuiet(data.Args) {
		return command, cmdName, fsterr.RemediationError{
			Inner:       errors.New("--verbose and --quiet flag provided"),
			Remediation: "Either remove both --verbose and --quiet flags, or one of them.",
		}
	}

	if argparser.IsHelpFlagOnly(data.Args) && len(data.Args) == 1 {
		return command, cmdName, fsterr.SkipExitError{
			Skip: true,
			Err:  help(vars, nil),
		}
	}

	noargs := len(data.Args) == 0
	globalFlagsOnly := argparser.IsGlobalFlagsOnly(data.Args)
	ctx, err := app.ParseContext(data.Args)
	if err != nil && !argparser.IsCompletion(data.Args) || noargs || globalFlagsOnly {
		if (noargs || globalFlagsOnly) && defaultCommand != nil {
			data.Args = append([]string{*defaultCommand}, data.Args...)
			ctx, err = app.ParseContext(data.Args)
			if err != nil {
				return command, cmdName, help(vars, err)
			}
			noargs = false
			globalFlagsOnly = false
			// Fall through to normal command selection below.
		} else {
			if noargs || globalFlagsOnly {
				err = fmt.Errorf("command not specified")
			}
			// Try external command dispatch before showing help.
			if extLookup != nil && !noargs && !globalFlagsOnly {
				if binPath, remaining, found := extLookup.Lookup(data.Args); found {
					return &externalCommand{binPath: binPath, args: remaining, cmdName: extractCommandName(data.Args), data: data}, "external", nil
				}
			}
			return command, cmdName, help(vars, err)
		}
	}

	if len(data.Args) == 1 && data.Args[0] == "--" {
		return command, cmdName, fsterr.RemediationError{
			Inner:       errors.New("-- is invalid input when not followed by a positional argument"),
			Remediation: "If looking for help output try: `fastly help` for full command list or `fastly --help` for command summary.",
		}
	}

	var found bool
	if !noargs && !globalFlagsOnly && !argparser.IsHelpOnly(data.Args) && !argparser.IsHelpFlagOnly(data.Args) && !argparser.IsCompletion(data.Args) && !argparser.IsCompletionScript(data.Args) {
		command, found = argparser.Select(ctx.SelectedCommand.FullCommand(), commands)
		if !found {
			return command, cmdName, help(vars, err)
		}
	}

	if argparser.ContextHasHelpFlag(ctx) && !argparser.IsHelpFlagOnly(data.Args) {
		return command, cmdName, fsterr.SkipExitError{
			Skip: true,
			Err:  help(vars, nil),
		}
	}

	if argparser.IsCompletionScript(data.Args) {
		data.Args = append(data.Args, "shellcomplete")
	}

	cmdName, err = app.Parse(data.Args)
	if err != nil {
		// Try external command dispatch before showing help.
		if extLookup != nil {
			if binPath, remaining, found := extLookup.Lookup(data.Args); found {
				return &externalCommand{binPath: binPath, args: remaining, cmdName: extractCommandName(data.Args), data: data}, "external", nil
			}
		}
		return command, "", help(vars, err)
	}

	app.Writers(data.Output, io.Discard)

	if argparser.IsCompletion(data.Args) || argparser.IsCompletionScript(data.Args) {
		app.Terminate(os.Exit)
		return command, "shell-autocomplete", nil
	}

	if cmdName == "help" {
		return command, cmdName, fsterr.SkipExitError{
			Skip: true,
			Err: fsterr.RemediationError{
				Prefix: useFullHelpOutput(app, data.Args, data.Output).String(),
			},
		}
	}

	if argparser.IsHelpFlagOnly(data.Args) {
		return command, cmdName, fsterr.SkipExitError{
			Skip: true,
			Err:  help(vars, nil),
		}
	}

	return command, cmdName, nil
}

func useFullHelpOutput(app *kingpin.Application, args []string, out io.Writer) *bytes.Buffer {
	var buf bytes.Buffer
	app.Writers(&buf, io.Discard)
	_, _ = app.Parse(args)
	app.Writers(out, io.Discard)

	if len(args) > 0 && args[len(args)-1] == "help" {
		fmt.Fprintln(&buf, "\nFor help on a specific command, try e.g.")
		fmt.Fprintln(&buf, "")
		fmt.Fprintln(&buf, "\tfastly help profile")
		fmt.Fprintln(&buf, "\tfastly profile --help")
		fmt.Fprintln(&buf, "")
	}
	return &buf
}

//go:embed metadata.json
var metadata []byte

type commandsMetadata map[string]any

// UsageJSON returns a structured representation of the application usage
// documentation in JSON format.
func UsageJSON(app *kingpin.Application) (string, error) {
	var data commandsMetadata
	err := json.Unmarshal(metadata, &data)
	if err != nil {
		return "", err
	}

	usage := &usageJSON{
		GlobalFlags: getGlobalFlagJSON(app.Model().Flags),
		Commands:    getCommandJSON(app.Model().Commands, data),
	}

	j, err := json.Marshal(usage)
	if err != nil {
		return "", err
	}

	return string(j), nil
}

type usageJSON struct {
	GlobalFlags []flagJSON    `json:"globalFlags"`
	Commands    []commandJSON `json:"commands"`
}

type flagJSON struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Placeholder string `json:"placeholder"`
	Required    bool   `json:"required"`
	Default     string `json:"default"`
	IsBool      bool   `json:"isBool"`
}

// Example represents a metadata.json command example.
type Example struct {
	Cmd         string `json:"cmd"`
	Description string `json:"description,omitempty"`
	Title       string `json:"title"`
}

type commandJSON struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Flags       []flagJSON    `json:"flags"`
	Children    []commandJSON `json:"children"`
	APIs        []string      `json:"apis,omitempty"`
	Examples    []Example     `json:"examples,omitempty"`
}

func getGlobalFlagJSON(models []*kingpin.ClauseModel) []flagJSON {
	var gf []*kingpin.ClauseModel
	for _, f := range models {
		if !f.Hidden {
			gf = append(gf, f)
		}
	}
	return getFlagJSON(gf)
}

func getCommandJSON(models []*kingpin.CmdModel, data commandsMetadata) []commandJSON {
	var cmds []commandJSON
	for _, m := range models {
		if m.Hidden {
			continue
		}
		var cj commandJSON
		cj.Name = m.Name
		cj.Description = m.Help
		cj.Flags = getFlagJSON(m.Flags)
		cj.Children = getCommandJSON(m.Commands, data)
		cj.APIs = []string{}
		cj.Examples = []Example{}

		segs := strings.Split(m.FullCommand(), " ")
		data := recurse(m.Depth, segs, data)
		apis, ok := data["apis"]
		if ok {
			apis, ok := apis.([]any)
			if ok {
				for _, api := range apis {
					a, ok := api.(string)
					if ok {
						cj.APIs = append(cj.APIs, a)
					}
				}
			}
		}

		examples, ok := data["examples"]
		if ok {
			examples, ok := examples.([]any)
			if ok {
				for _, example := range examples {
					c := resolveToString(example, "cmd")
					d := resolveToString(example, "description")
					t := resolveToString(example, "title")
					if c != "" && t != "" {
						cj.Examples = append(cj.Examples, Example{
							Cmd:         c,
							Description: d,
							Title:       t,
						})
					}
				}
			}
		}

		cmds = append(cmds, cj)
	}
	return cmds
}

func recurse(n int, segs []string, data commandsMetadata) commandsMetadata {
	if n == 0 {
		return data
	}
	value, ok := data[segs[0]]
	if ok {
		value, ok := value.(map[string]any)
		if ok {
			return recurse(n-1, segs[1:], value)
		}
	}
	return nil
}

func resolveToString(i any, key string) string {
	m, ok := i.(map[string]any)
	if ok {
		v, ok := m[key]
		if ok {
			v, ok := v.(string)
			if ok {
				return v
			}
		}
	}
	return ""
}

func getFlagJSON(models []*kingpin.ClauseModel) []flagJSON {
	var flags []flagJSON
	for _, m := range models {
		if m.Hidden {
			continue
		}
		var flag flagJSON
		flag.Name = m.Name
		flag.Description = m.Help
		flag.Placeholder = m.PlaceHolder
		flag.Required = m.Required
		flag.Default = strings.Join(m.Default, ",")
		flag.IsBool = m.IsBoolFlag()
		flags = append(flags, flag)
	}
	return flags
}

func displayHelp(
	errLog fsterr.LogInterface,
	args []string,
	app *kingpin.Application,
	stdout, stderr io.Writer,
) func(vars map[string]any, err error) error {
	return func(vars map[string]any, err error) error {
		usage := Usage(args, app, stdout, stderr, vars)
		remediation := fsterr.RemediationError{Prefix: usage}
		if err != nil {
			errLog.Add(err)
			remediation.Inner = fmt.Errorf("error parsing arguments: %w", err)
		}
		return remediation
	}
}

// extractCommandName extracts the first non-flag argument as the command name.
func extractCommandName(args []string) string {
	var parts []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

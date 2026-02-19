package framework

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/skratchdot/open-golang/open"

	"github.com/fastly/go-fastly/v12/fastly"

	"github.com/fastly/cli/pkg/api"
	"github.com/fastly/cli/pkg/config"
	"github.com/fastly/cli/pkg/env"
	fsterr "github.com/fastly/cli/pkg/errors"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/manifest"
	"github.com/fastly/cli/pkg/sync"
	"github.com/fastly/cli/pkg/useragent"
)

// InitWithOptions constructs all the required objects and data for
// ExecWithOptions. The opts parameter allows callers to customise behaviour
// (e.g. providing their own versioners or disabling built-in commands).
func InitWithOptions(args []string, stdin io.Reader, opts Options) (*global.Data, error) {
	args = args[1:]

	httpClient := &http.Client{Timeout: time.Minute * 2}

	var (
		in            = stdin
		out io.Writer = sync.NewWriter(color.Output)
	)

	var e config.Environment
	e.Read(env.Parse(os.Environ()))

	var verboseOutput bool
	for _, seg := range args {
		if seg == "-v" || seg == "--verbose" {
			verboseOutput = true
		}
	}

	var autoYes, nonInteractive bool
	for _, seg := range args {
		if seg == "-y" || seg == "--auto-yes" {
			autoYes = true
		}
		if seg == "-i" || seg == "--non-interactive" {
			nonInteractive = true
		}
	}

	var cfg config.File
	cfg.SetAutoYes(autoYes)
	cfg.SetNonInteractive(nonInteractive)
	if err := cfg.Read(config.FilePath, in, out, fsterr.Log, verboseOutput); err != nil {
		return nil, err
	}

	var md manifest.Data
	md.File.Args = args
	md.File.SetErrLog(fsterr.Log)
	md.File.SetOutput(out)
	_ = md.File.Read(manifest.Filename)

	factory := func(token, endpoint string, debugMode bool) (api.Interface, error) {
		client, err := fastly.NewClientForEndpoint(token, endpoint)
		if debugMode {
			client.DebugMode = true
		}
		return client, err
	}

	var debugMode bool
	for _, seg := range args {
		if seg == "--debug-mode" {
			debugMode = true
		}
	}

	var versioners global.Versioners
	if opts.ConfigureVersioners != nil {
		versioners = opts.ConfigureVersioners(httpClient, debugMode, md)
	}

	if e.UserAgentExtension != "" {
		useragent.SetExtension(e.UserAgentExtension)
	}
	fastly.UserAgent = fmt.Sprintf("%s, %s", useragent.Name, fastly.UserAgent)

	data := &global.Data{
		APIClientFactory: factory,
		Args:             args,
		Config:           cfg,
		ConfigPath:       config.FilePath,
		Env:              e,
		ErrLog:           fsterr.Log,
		HTTPClient:       httpClient,
		Manifest:         &md,
		Opener:           open.Run,
		Output:           out,
		Versioners:       versioners,
		Input:            in,
	}

	if opts.ExecuteWasmTools != nil {
		data.ExecuteWasmTools = opts.ExecuteWasmTools
	}

	return data, nil
}

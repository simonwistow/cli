// fastly-info is an example CLI tool built on the Fastly CLI framework.
// It demonstrates how to build a standalone tool that authenticates and calls
// the Fastly API using the same patterns as the main CLI, but without
// importing pkg/commands/.
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/fastly/go-fastly/v12/fastly"
	"github.com/fastly/kingpin"

	"github.com/fastly/cli/pkg/argparser"
	"github.com/fastly/cli/pkg/framework"
	"github.com/fastly/cli/pkg/global"
)

func main() {
	opts := framework.Options{
		AppName:        "fastly-info",
		AppHelp:        "Display Fastly account information",
		DefaultCommand: "info",
		DefineCommands: defineCommands,
	}
	if err := framework.RunWithOptions(os.Args, os.Stdin, opts); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func defineCommands(app *kingpin.Application, data *global.Data) []argparser.Command {
	info := newInfoCommand(app, data)
	return []argparser.Command{info}
}

// infoCommand displays current user and service information.
type infoCommand struct {
	argparser.Base
}

func newInfoCommand(parent argparser.Registerer, g *global.Data) *infoCommand {
	var c infoCommand
	c.Globals = g
	c.CmdClause = parent.Command("info", "Display current user and service information")
	return &c
}

// Exec implements the argparser.Command interface.
func (c *infoCommand) Exec(_ io.Reader, out io.Writer) error {
	ctx := context.Background()

	user, err := c.Globals.APIClient.GetCurrentUser(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	fmt.Fprintf(out, "User: %s (%s)\n", fastly.ToValue(user.Name), fastly.ToValue(user.Login))
	fmt.Fprintf(out, "Role: %s\n", fastly.ToValue(user.Role))
	fmt.Fprintf(out, "Customer ID: %s\n", fastly.ToValue(user.CustomerID))
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Services:")
	paginator := c.Globals.APIClient.GetServices(ctx, &fastly.GetServicesInput{})
	var count int
	for paginator.HasNext() {
		services, err := paginator.GetNext()
		if err != nil {
			return fmt.Errorf("failed to list services: %w", err)
		}
		for _, svc := range services {
			name := fastly.ToValue(svc.Name)
			if name == "" {
				name = "(unnamed)"
			}
			fmt.Fprintf(out, "  - %s (ID: %s)\n", name, fastly.ToValue(svc.ServiceID))
			count++
		}
	}
	fmt.Fprintf(out, "\nTotal services: %d\n", count)

	return nil
}

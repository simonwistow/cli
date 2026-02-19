package framework

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/fastly/kingpin"

	"github.com/fastly/cli/pkg/argparser"
	fsterr "github.com/fastly/cli/pkg/errors"
	"github.com/fastly/cli/pkg/global"
)

// stubCommand implements argparser.Command for testing.
type stubCommand struct {
	argparser.Base
	executed bool
}

func (c *stubCommand) Exec(_ io.Reader, out io.Writer) error {
	c.executed = true
	return nil
}

// setupTestApp creates a kingpin app with a single "info" command and returns
// the app, the command list, and the stub command instance.
func setupTestApp(data *global.Data) (*kingpin.Application, []argparser.Command, *stubCommand) {
	app := ConfigureKingpin(data, "test-app", "A test application")
	cmd := &stubCommand{}
	cmd.Globals = data
	cmd.CmdClause = app.Command("info", "Show info")
	return app, []argparser.Command{cmd}, cmd
}

func newTestData(args []string) *global.Data {
	return &global.Data{
		Args:   args,
		Output: &bytes.Buffer{},
		ErrLog: fsterr.MockLog{},
	}
}

func TestProcessCommandInput_NoDefaultNoArgs(t *testing.T) {
	data := newTestData([]string{})
	app, cmds, _ := setupTestApp(data)

	_, _, err := ProcessCommandInput(data, app, cmds, nil, nil)
	if err == nil {
		t.Fatal("expected error when no args and no default command, got nil")
	}
	if !strings.Contains(err.Error(), "command not specified") {
		t.Fatalf("expected 'command not specified' error, got: %v", err)
	}
}

func TestProcessCommandInput_DefaultSetNoArgs(t *testing.T) {
	data := newTestData([]string{})
	app, cmds, _ := setupTestApp(data)

	defaultCmd := "info"
	cmd, name, err := ProcessCommandInput(data, app, cmds, nil, &defaultCmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "info" {
		t.Fatalf("expected command name 'info', got %q", name)
	}
	if cmd == nil {
		t.Fatal("expected command to be selected, got nil")
	}
}

func TestProcessCommandInput_DefaultSetExplicitCommand(t *testing.T) {
	data := newTestData([]string{"info"})
	app, cmds, _ := setupTestApp(data)

	// Add a second command so we can tell them apart.
	other := &stubCommand{}
	other.Globals = data
	other.CmdClause = app.Command("other", "Other command")
	cmds = append(cmds, other)

	defaultCmd := "other"
	cmd, name, err := ProcessCommandInput(data, app, cmds, nil, &defaultCmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "info" {
		t.Fatalf("expected explicit command 'info' to take precedence, got %q", name)
	}
	if cmd == nil {
		t.Fatal("expected command to be selected, got nil")
	}
	if cmd.Name() != "info" {
		t.Fatalf("expected 'info' command, got %q", cmd.Name())
	}
}

func TestProcessCommandInput_DefaultSetGlobalFlagsOnly(t *testing.T) {
	data := newTestData([]string{"--verbose"})
	app, cmds, _ := setupTestApp(data)

	defaultCmd := "info"
	cmd, name, err := ProcessCommandInput(data, app, cmds, nil, &defaultCmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "info" {
		t.Fatalf("expected default command 'info', got %q", name)
	}
	if cmd == nil {
		t.Fatal("expected command to be selected, got nil")
	}
}

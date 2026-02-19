package app

import (
	"text/template"

	"github.com/fastly/cli/pkg/framework"
)

// The following are re-exported from the framework package for backward
// compatibility. New code should import pkg/framework directly.

// CompactUsageTemplate is the default usage template.
var CompactUsageTemplate = framework.CompactUsageTemplate

// UsageTemplateFuncs is a map of template functions for the usage template.
var UsageTemplateFuncs template.FuncMap

// VerboseUsageTemplate is the full-fat usage template.
const VerboseUsageTemplate = framework.VerboseUsageTemplate

func init() {
	UsageTemplateFuncs = framework.UsageTemplateFuncs
}

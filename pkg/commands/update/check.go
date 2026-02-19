package update

import (
	"io"

	"github.com/blang/semver"

	"github.com/fastly/cli/pkg/github"
)

// Check if the CLI can be updated.
//
// Deprecated: Use github.Check instead.
func Check(currentVersion string, av github.AssetVersioner) (current, latest semver.Version, shouldUpdate bool) {
	return github.Check(currentVersion, av)
}

// CheckAsync is a helper function for running Check asynchronously.
//
// Deprecated: Use github.CheckAsync instead.
func CheckAsync(
	currentVersion string,
	av github.AssetVersioner,
	quietMode bool,
) (printResults func(io.Writer)) {
	return github.CheckAsync(currentVersion, av, quietMode)
}

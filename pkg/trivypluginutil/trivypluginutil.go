package trivypluginutil

import (
	"log/slog"
	"os"
	"strings"
)

// IsTrivyPluginMode returns whether the binary is being executed as a trivy plugin mode.
// Not robust.
func IsTrivyPluginMode() bool {
	exe, err := os.Executable()
	if err != nil {
		slog.Error("failed to call os.Executable()", "error", err)
		return false
	}
	return strings.Contains(exe, "/.trivy/plugins/vexllm")
}

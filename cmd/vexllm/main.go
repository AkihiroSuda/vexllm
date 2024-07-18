package main

import (
	"log/slog"
	"os"

	"github.com/AkihiroSuda/vexllm/cmd/vexllm/commands/generate"
	"github.com/AkihiroSuda/vexllm/cmd/vexllm/version"
	"github.com/AkihiroSuda/vexllm/pkg/envutil"
	"github.com/spf13/cobra"
)

var logLevel = new(slog.LevelVar)

func main() {
	logHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(logHandler))
	if err := newRootCommand().Execute(); err != nil {
		slog.Error("Error", "error", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "vexllm",
		Short:         "Silence negligible CVE alerts",
		Example:       generate.Example,
		Version:       version.GetVersion(),
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	flags := cmd.PersistentFlags()
	flags.Bool("debug", envutil.Bool("DEBUG", false), "debug mode [$DEBUG]")

	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if debug, _ := cmd.Flags().GetBool("debug"); debug {
			logLevel.Set(slog.LevelDebug)
		}
		return nil
	}

	cmd.AddCommand(
		generate.New(),
	)
	return cmd
}

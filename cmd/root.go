package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/JulienBalestra/dry/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
)

func NewRootCommand(ctx context.Context) *cobra.Command {
	zapConfig := zap.NewProductionConfig()
	zapLevel := zapConfig.Level.String()

	root := &cobra.Command{
		Short: "wireguard stun",
		Long:  "wireguard stun",
		Use:   "",
	}
	root.AddCommand(version.NewCommand())

	fs := &pflag.FlagSet{}
	timezone := time.Local.String()

	fs.StringVar(&timezone, "timezone", timezone, "timezone")
	fs.StringVar(&zapLevel, "log-level", zapLevel, fmt.Sprintf("log level - %s %s %s %s %s %s %s", zap.DebugLevel, zap.InfoLevel, zap.WarnLevel, zap.ErrorLevel, zap.DPanicLevel, zap.PanicLevel, zap.FatalLevel))
	fs.StringSliceVar(&zapConfig.OutputPaths, "log-output", zapConfig.OutputPaths, "log output")

	root.PersistentFlags().AddFlagSet(fs)
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		err := zapConfig.Level.UnmarshalText([]byte(zapLevel))
		if err != nil {
			return err
		}
		logger, err := zapConfig.Build()
		if err != nil {
			return err
		}
		logger = logger.With(zap.Int("pid", os.Getpid()))
		zap.ReplaceGlobals(logger)
		zap.RedirectStdLog(logger)

		tz, err := time.LoadLocation(timezone)
		if err != nil {
			return err
		}
		time.Local = tz
		return nil
	}

	root.AddCommand(NewRegistryCommand(ctx))
	root.AddCommand(NewPeerDNSCommand(ctx))
	return root
}

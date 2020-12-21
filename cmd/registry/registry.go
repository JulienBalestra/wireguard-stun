package registry

import (
	"context"

	"github.com/spf13/cobra"
)

func NewRegistryCommand(ctx context.Context) *cobra.Command {
	registryCmd := &cobra.Command{
		Short:   "registry",
		Long:    "registry",
		Use:     "registry",
		Aliases: []string{"r"},
	}
	registryCmd.AddCommand(NewRoute53Command(ctx))
	registryCmd.AddCommand(NewPubSubCommand(ctx))
	return registryCmd
}

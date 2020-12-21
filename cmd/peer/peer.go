package peer

import (
	"context"

	"github.com/spf13/cobra"
)

func NewPeerCommand(ctx context.Context) *cobra.Command {
	p := &cobra.Command{
		Short:   "peer",
		Long:    "peer",
		Use:     "peer",
		Aliases: []string{"p"},
	}
	p.AddCommand(NewDNSCommand(ctx))
	p.AddCommand(NewPubCommand(ctx))
	return p
}

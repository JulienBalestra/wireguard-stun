package registry

import (
	"context"
	"sync"
	"time"

	"github.com/JulienBalestra/dry/pkg/signals"
	"github.com/JulienBalestra/wireguard-stun/pkg/registry/http/pub"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func NewPubSubCommand(ctx context.Context) *cobra.Command {
	pubsubCmd := &cobra.Command{
		Short:   "pub-sub",
		Long:    "pub-sub",
		Use:     "pub-sub",
		Aliases: []string{"ps"},
	}
	fs := &pflag.FlagSet{}

	reconcileConfig := &pub.Config{
		WireguardConfig: &wireguard.Config{},
	}
	fs.StringVar(&reconcileConfig.WireguardConfig.DeviceName, "device-name", "wg0", "wireguard device name")
	fs.DurationVar(&reconcileConfig.RemoteSubTTL, "remote-sub-ttl", time.Minute*10, "remote sub max TTL")
	fs.StringVar(&reconcileConfig.ListenAddr, "listen-address", "0.0.0.0:8989", "listen address")
	fs.DurationVar(&reconcileConfig.HandshakeAge, "handshake-age", time.Minute*3, "skip recent handshake peers")
	fs.DurationVar(&reconcileConfig.ReconcileInterval, "reconcile-interval", time.Millisecond*100, "reconciliation interval")

	pubsubCmd.Flags().AddFlagSet(fs)
	pubsubCmd.RunE = func(cmd *cobra.Command, args []string) error {
		rec, err := pub.NewPub(reconcileConfig)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithCancel(ctx)
		waitGroup := &sync.WaitGroup{}
		waitGroup.Add(1)
		go func() {
			signals.NotifySignals(ctx, func() {})
			cancel()
			waitGroup.Done()
		}()

		err = rec.Run(ctx)
		cancel()
		waitGroup.Wait()
		return err
	}
	return pubsubCmd
}

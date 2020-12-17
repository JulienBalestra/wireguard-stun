package cmd

import (
	"context"
	"sync"
	"time"

	"github.com/JulienBalestra/dry/pkg/signals"
	"github.com/JulienBalestra/wireguard-stun/pkg/registry"
	"github.com/JulienBalestra/wireguard-stun/pkg/registry/route53"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func NewRegistryCommand(ctx context.Context) *cobra.Command {
	registryCmd := &cobra.Command{
		Short:   "registry",
		Long:    "registry",
		Use:     "registry",
		Aliases: []string{"r"},
	}
	fs := &pflag.FlagSet{}

	reconcileConfig := &registry.Config{
		WireguardConfig: &wireguard.Config{},
		Route53Config:   &route53.Config{},
	}

	fs.StringVar(&reconcileConfig.WireguardConfig.DeviceName, "device-name", "wg0", "wireguard device name")
	fs.StringVar(&reconcileConfig.Route53Config.SRVRecordSuffix, "srv-record-suffix", "._wg._udp.julienbalestra.com.", "SRV route53 record suffix")
	fs.StringVar(&reconcileConfig.Route53Config.ARecordSuffix, "a-record-suffix", ".wg.julienbalestra.com.", "A route53 record suffix")
	fs.StringVar(&reconcileConfig.Route53Config.ZoneID, "zone-id", "", "route53 hosted zone id")
	fs.Int64Var(&reconcileConfig.Route53Config.TTL, "ttl", 60, "route53 record TTL")
	fs.DurationVar(&reconcileConfig.ReconcileInterval, "reconcile-interval", time.Second*30, "reconciliation interval")

	registryCmd.Flags().AddFlagSet(fs)
	registryCmd.RunE = func(cmd *cobra.Command, args []string) error {
		rec, err := registry.NewRegistry(reconcileConfig)
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

		_ = rec.Run(ctx)
		cancel()
		waitGroup.Wait()
		return nil
	}
	return registryCmd
}

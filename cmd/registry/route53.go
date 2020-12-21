package registry

import (
	"context"
	"sync"
	"time"

	"github.com/JulienBalestra/dry/pkg/signals"
	"github.com/JulienBalestra/wireguard-stun/pkg/registry/route53"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func NewRoute53Command(ctx context.Context) *cobra.Command {
	r53cmd := &cobra.Command{
		Short:   "route53",
		Long:    "route53",
		Use:     "route53",
		Aliases: []string{"r53"},
	}
	fs := &pflag.FlagSet{}

	reconcileConfig := &route53.Config{
		WireguardConfig: &wireguard.Config{},
		Route53Config:   &route53.AWSClientConfig{},
	}

	fs.StringVar(&reconcileConfig.WireguardConfig.DeviceName, "device-name", "wg0", "wireguard device name")
	fs.StringVar(&reconcileConfig.Route53Config.SRVRecordSuffix, "srv-record-suffix", "._wg._udp.julienbalestra.com.", "SRV route53 record suffix")
	fs.StringVar(&reconcileConfig.Route53Config.ARecordSuffix, "a-record-suffix", ".wg.julienbalestra.com.", "A route53 record suffix")
	fs.StringVar(&reconcileConfig.Route53Config.ZoneID, "zone-id", "", "route53 hosted zone id")
	fs.Int64Var(&reconcileConfig.Route53Config.TTL, "ttl", 60, "route53 record TTL")
	fs.DurationVar(&reconcileConfig.ReconcileInterval, "reconcile-interval", time.Second*30, "reconciliation interval")
	fs.DurationVar(&reconcileConfig.HandshakeAge, "handshake-age", time.Minute*3, "skip recent handshake peers")

	r53cmd.Flags().AddFlagSet(fs)
	r53cmd.RunE = func(cmd *cobra.Command, args []string) error {
		rec, err := route53.NewRegistry(reconcileConfig)
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
	return r53cmd
}

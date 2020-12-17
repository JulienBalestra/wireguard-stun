package cmd

import (
	"context"
	"sync"
	"time"

	"github.com/JulienBalestra/dry/pkg/signals"
	"github.com/JulienBalestra/wireguard-stun/pkg/peerdns"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func NewPeerDNSCommand(ctx context.Context) *cobra.Command {
	registry := &cobra.Command{
		Short:   "peer-dns",
		Long:    "peer-dns",
		Use:     "peer-dns",
		Aliases: []string{"p"},
	}
	fs := &pflag.FlagSet{}

	peerDNSConfig := &peerdns.Config{
		WireguardConfig: &wireguard.Config{},
	}

	fs.StringVar(&peerDNSConfig.WireguardConfig.DeviceName, "device-name", "wg0", "wireguard device name")
	fs.StringVar(&peerDNSConfig.SRVRecordSuffix, "srv-record-suffix", "._wg._udp.julienbalestra.com.", "SRV route53 record suffix")
	fs.StringVar(&peerDNSConfig.ResolverEndpoint, "resolver-endpoint", "ns-174.awsdns-21.com:53", "dns resolver endpoint ip:port")
	fs.DurationVar(&peerDNSConfig.DNSTimeout, "dns-timeout", time.Second*60, "per dns query timeout")
	fs.StringArrayVar(&peerDNSConfig.StaticPeers, "static-peers", nil, "static peers to ignore")
	fs.DurationVar(&peerDNSConfig.ReconcileInterval, "reconcile-interval", time.Second*30, "reconciliation interval")

	registry.Flags().AddFlagSet(fs)
	registry.RunE = func(cmd *cobra.Command, args []string) error {
		pd, err := peerdns.NewPeerDNS(peerDNSConfig)
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

		err = pd.Run(ctx)
		cancel()
		waitGroup.Wait()
		return err
	}
	return registry
}

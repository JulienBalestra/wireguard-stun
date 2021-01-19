package peer

import (
	"context"
	"sync"
	"time"

	"github.com/JulienBalestra/dry/pkg/signals"
	"github.com/JulienBalestra/wireguard-stun/pkg/peer/dns"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func NewDNSCommand(ctx context.Context) *cobra.Command {
	d := &cobra.Command{
		Short:   "dns",
		Long:    "dns",
		Use:     "dns",
		Aliases: []string{"d"},
	}
	fs := &pflag.FlagSet{}

	config := &dns.Config{
		Wireguard: &wireguard.Config{},
	}

	fs.StringVar(&config.Wireguard.DeviceName, "device-name", defaultDeviceName, "wireguard device name")
	fs.StringVar(&config.SRVRecordSuffix, "srv-record-suffix", "._wireguard._udp.mesh.local.", "SRV record suffix")
	fs.StringVar(&config.ResolverEndpoint, "resolver-endpoint", "", "dns resolver endpoint ip:port")
	fs.DurationVar(&config.DNSTimeout, "dns-timeout", time.Second*60, "per dns query timeout")
	fs.StringArrayVar(&config.StaticPeers, "static-peers", nil, "skip static peers by public key")
	fs.DurationVar(&config.ReconcileInterval, "reconcile-interval", time.Hour, "reconciliation interval")
	fs.DurationVar(&config.HandshakeAge, "handshake-age", time.Minute*3, "skip recent handshake peers")

	d.Flags().AddFlagSet(fs)
	d.RunE = func(cmd *cobra.Command, args []string) error {
		pd, err := dns.NewPeerDNS(config)
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
	return d
}

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

	peerDNSConfig := &dns.Config{
		WireguardConfig: &wireguard.Config{},
	}

	fs.StringVar(&peerDNSConfig.WireguardConfig.DeviceName, "device-name", defaultDeviceName, "wireguard device name")
	fs.StringVar(&peerDNSConfig.SRVRecordSuffix, "srv-record-suffix", "._wireguard._udp.mesh.local.", "SRV record suffix")
	fs.StringVar(&peerDNSConfig.ResolverEndpoint, "resolver-endpoint", "", "dns resolver endpoint ip:port")
	fs.DurationVar(&peerDNSConfig.DNSTimeout, "dns-timeout", time.Second*60, "per dns query timeout")
	fs.StringArrayVar(&peerDNSConfig.StaticPeers, "static-peers", []string{wireguard.GetDevicePublicKey(defaultDeviceName)}, "skip static peers by public key")
	fs.DurationVar(&peerDNSConfig.ReconcileInterval, "reconcile-interval", time.Hour, "reconciliation interval")
	fs.DurationVar(&peerDNSConfig.HandshakeAge, "handshake-age", time.Minute*3, "skip recent handshake peers")

	d.Flags().AddFlagSet(fs)
	d.RunE = func(cmd *cobra.Command, args []string) error {
		pd, err := dns.NewPeerDNS(peerDNSConfig)
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

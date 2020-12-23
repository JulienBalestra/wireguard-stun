package peer

import (
	"context"
	"sync"
	"time"

	"github.com/JulienBalestra/dry/pkg/signals"
	"github.com/JulienBalestra/wireguard-stun/pkg/peer/sub"
	"github.com/JulienBalestra/wireguard-stun/pkg/pubsub"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func NewPubCommand(ctx context.Context) *cobra.Command {
	d := &cobra.Command{
		Short:   "sub",
		Long:    "subscription",
		Use:     "sub",
		Aliases: []string{"s"},
	}
	fs := &pflag.FlagSet{}

	subConfig := &sub.Config{
		WireguardConfig: &wireguard.Config{},
	}

	fs.StringVar(&subConfig.WireguardConfig.DeviceName, "device-name", defaultDeviceName, "wireguard device name")
	fs.StringVar(&subConfig.PublicKey, "public-key", wireguard.GetDevicePublicKey(defaultDeviceName), "local interface public key")
	fs.StringVar(&subConfig.ListenAddr, "listen-address", "0.0.0.0:8989", "listen address")
	fs.StringVar(&subConfig.SubURL, "sub-url", "http://10.0.0.1:8989"+pubsub.SubAPIPath, "subscription url, remote endpoint of the registry to subscribe to updates")
	fs.StringVar(&subConfig.PubURL, "pub-url", "http://10.0.0.11:8989"+pubsub.PubAPIPath, "publish url, local endpoint where the registry is going to push updates, linked with the listen-address")
	fs.DurationVar(&subConfig.RenewInterval, "subscription-renew", pubsub.SubscriptionRenew, "subscription renew")
	fs.DurationVar(&subConfig.SubscriptionTTL, "subscription-ttl", pubsub.SubscriptionTTL, "subscription ttl")
	fs.DurationVar(&subConfig.WireguardConfig.DiscardStalingEndpoints, "endpoint-discard-age", time.Minute*15, "wireguard peer endpoint with staling handshake age to set to discard")
	fs.DurationVar(&subConfig.WireguardConfig.DiscardGracePeriod, "endpoint-discard-grace-period", time.Minute*10, "grace period for wireguard endpoint marked to discard")

	d.Flags().AddFlagSet(fs)
	d.RunE = func(cmd *cobra.Command, args []string) error {
		subscription, err := sub.NewSubscription(subConfig)
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
		err = subscription.Run(ctx)
		cancel()
		waitGroup.Wait()
		return err
	}
	return d
}

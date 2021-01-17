package peer

import (
	"context"
	"sync"

	"github.com/JulienBalestra/dry/pkg/signals"
	"github.com/JulienBalestra/wireguard-stun/pkg/peer/etcd"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func NewEtcdCommand(ctx context.Context) *cobra.Command {
	d := &cobra.Command{
		Short:   "etcd",
		Long:    "etcd",
		Use:     "etcd",
		Aliases: []string{"e"},
	}
	fs := &pflag.FlagSet{}

	config := &etcd.Config{
		Wireguard: &wireguard.Config{},
	}

	fs.StringVar(&config.Wireguard.DeviceName, "device-name", defaultDeviceName, "wireguard device name")
	fs.StringArrayVar(&config.EtcdEndpoints, "etcd-endpoints", []string{"127.0.0.1:2379"}, "etcd endpoints")

	d.Flags().AddFlagSet(fs)
	d.RunE = func(cmd *cobra.Command, args []string) error {
		peerEtcd, err := etcd.NewPeerEtcd(config)
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

		err = peerEtcd.Run(ctx)
		cancel()
		waitGroup.Wait()
		return err
	}
	return d
}

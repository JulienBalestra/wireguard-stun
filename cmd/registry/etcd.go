package registry

import (
	"context"
	"sync"
	"time"

	"github.com/JulienBalestra/dry/pkg/signals"
	"github.com/JulienBalestra/wireguard-stun/pkg/registry/etcd"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func NewEtcdCommand(ctx context.Context) *cobra.Command {
	etcdCommand := &cobra.Command{
		Short:   "etcd",
		Long:    "etcd",
		Use:     "etcd",
		Aliases: []string{"e"},
	}
	fs := &pflag.FlagSet{}

	reconcileConfig := &etcd.Config{
		Wireguard: &wireguard.Config{},
	}
	fs.StringVar(&reconcileConfig.Wireguard.DeviceName, "device-name", "wg0", "wireguard device name")
	fs.StringArrayVar(&reconcileConfig.EtcdEndpoints, "etcd-endpoints", []string{"127.0.0.1:2379"}, "etcd endpoints")
	fs.DurationVar(&reconcileConfig.ReconcileInterval, "reconcile-interval", time.Millisecond*100, "reconciliation interval")
	fs.DurationVar(&reconcileConfig.ResyncInterval, "resync-interval", time.Minute*10, "full resync interval")
	fs.StringVar(&reconcileConfig.ListenAddr, "listen-address", "0.0.0.0:8989", "listen address")

	etcdCommand.Flags().AddFlagSet(fs)
	etcdCommand.RunE = func(cmd *cobra.Command, args []string) error {
		rec, err := etcd.NewEtcd(reconcileConfig)
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
	return etcdCommand
}

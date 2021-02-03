package registry

import (
	"context"
	"sync"
	"time"

	"github.com/JulienBalestra/dry/pkg/signals"
	"github.com/JulienBalestra/wireguard-stun/pkg/etcd/schema"
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

	config := &etcd.Config{
		Wireguard: &wireguard.Config{},
	}
	fs.StringVar(&config.Wireguard.DeviceName, "device-name", "wg0", "wireguard device name")
	fs.StringArrayVar(&config.EtcdEndpoints, "etcd-endpoints", []string{"127.0.0.1:2379"}, "etcd endpoints")
	fs.StringVar(&config.EtcdPrefix, "etcd-prefix", schema.PeerKeyPrefix, "etcd key prefix for peers")
	fs.DurationVar(&config.ReconcileInterval, "reconcile-interval", time.Millisecond*100, "reconciliation interval")
	fs.DurationVar(&config.ReSyncInterval, "resync-interval", time.Minute, "full resync interval")
	fs.DurationVar(&config.CompactionInterval, "compaction-interval", time.Hour, "compaction interval")
	fs.DurationVar(&config.DefragInterval, "defragment-interval", time.Hour*8, "defragment interval")
	fs.StringVar(&config.ListenAddr, "listen-address", "127.0.0.1:8989", "listen address")

	etcdCommand.Flags().AddFlagSet(fs)
	etcdCommand.RunE = func(cmd *cobra.Command, args []string) error {
		rec, err := etcd.NewEtcd(config)
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

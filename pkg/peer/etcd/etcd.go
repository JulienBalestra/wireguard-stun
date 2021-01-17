package etcd

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/JulienBalestra/wireguard-stun/pkg/registry/etcd"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"go.etcd.io/etcd/clientv3"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Config struct {
	EtcdEndpoint      string
	ReconcileInterval time.Duration
	EtcdPrefix        string

	Wireguard     *wireguard.Config
	EtcdEndpoints []string
	ListenAddr    string
}

type Etcd struct {
	conf *Config

	wg *wireguard.Wireguard
}

func NewPeerEtcd(conf *Config) (*Etcd, error) {
	wg, err := wireguard.NewWireguardClient(conf.Wireguard)
	if err != nil {
		return nil, err
	}

	e := &Etcd{
		conf: conf,
		wg:   wg,
	}
	return e, nil
}

func (e *Etcd) processEvents(ctx context.Context, w clientv3.WatchChan) error {
	for {
		select {
		case <-ctx.Done():
			return nil

		case update, ok := <-w:
			if !ok {
				zap.L().Info("context canceled")
				return nil
			}
			if update.Canceled {
				zap.L().Info("update canceled")
				return nil
			}
			if update.Err() != nil {
				zap.L().Error("error while watching", zap.Error(update.Err()))
				return update.Err()
			}
			if len(update.Events) == 0 {
				zap.L().Info("no event")
				continue
			}
			currentPeers, err := e.wg.GetIndexedPeers()
			if err != nil {
				zap.L().Error("failed to get peers", zap.Error(err))
				continue
			}
			updates := make(map[wgtypes.Key]net.UDPAddr, len(update.Events))
			for _, ev := range update.Events {
				if ev.Type != clientv3.EventTypePut {
					continue
				}
				key := string(ev.Kv.Key)
				value := ev.Kv.Value
				publicKey := strings.TrimLeft(key, e.conf.EtcdPrefix)
				zctx := zap.L().With(
					zap.String("etcdKey", key),
					zap.String("publicKey", publicKey),
					zap.ByteString("etcdValue", value),
				)
				k, err := wgtypes.ParseKey(publicKey)
				if err != nil {
					zctx.Error("failed to decode publicKey", zap.Error(err))
					continue
				}
				cp, ok := currentPeers[k]
				if !ok {
					zctx.Info("unknown peer")
					continue
				}
				ep := &etcd.Peer{}
				err = json.Unmarshal(value, ep)
				if err != nil {
					zctx.Error("failed to decode event", zap.Error(err))
					continue
				}
				zctx = zctx.With(
					zap.String("currentEndpoint", cp.Endpoint.String()),
					zap.Int64("currentHandshakeTimestamp", cp.LastHandshakeTime.Unix()),
					zap.Float64("currentHandshakeAge", time.Since(cp.LastHandshakeTime).Seconds()),
					zap.String("eventEndpoint", ep.Endpoint),
					zap.Int64("eventHandshakeAge", time.Now().Unix()-ep.HandshakeTimestamp),
				)
				if cp.LastHandshakeTime.Unix() > ep.HandshakeTimestamp {
					zctx.Info("current handshake is newer")
					continue
				}
				u, err := wireguard.ParseEndpoint(ep.Endpoint)
				if err != nil {
					zctx.Error("failed to parse endpoint", zap.Error(err))
					continue
				}
				updates[cp.PublicKey] = u
			}
			if len(updates) == 0 {
				continue
			}
			err = e.wg.SetNewEndpoints(updates)
			if err != nil {
				zap.L().Error("failed to set new endpoints", zap.Error(err))
				continue
			}
		}
	}
}

func (e *Etcd) Run(ctx context.Context) error {
	zap.L().Info("starting etcd reconciliation", zap.Duration("reconcileInterval", e.conf.ReconcileInterval))

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   e.conf.EtcdEndpoints,
		DialTimeout: time.Second * 5,
		Context:     ctx,
	})
	if err != nil {
		return err
	}
	after := time.After(0)
	for {
		select {
		case <-ctx.Done():
			return nil

		case <-after:
			peers, err := e.wg.GetPeers()
			if err != nil {
				zap.L().Error("failed to get peers", zap.Error(err))
				after = time.After(time.Second * 5)
				continue
			}
			wCtx, cancel := context.WithTimeout(ctx, e.conf.ReconcileInterval)
			wg := sync.WaitGroup{}
			for _, p := range peers {
				wg.Add(1)
				go func(s string) {
					defer cancel()
					defer wg.Done()
					etcdKey := e.conf.EtcdPrefix + s
					zctx := zap.L().With(
						zap.String("publicKey", s),
						zap.String("etcdKey", etcdKey),
						zap.Float64("watchDurationSeconds", e.conf.ReconcileInterval.Seconds()),
					)
					// TODO: get and set before watch
					zctx.Info("starting to watch")
					w := cli.Watch(wCtx, etcdKey, clientv3.WithFilterDelete())
					err = e.processEvents(ctx, w)
					if err != nil {
						zctx.Error("finished to watch on error", zap.Error(err))
						after = time.After(time.Second * 15)
						return
					}
					zctx.Info("finished to watch")
				}(p.PublicKey.String())
			}
			wg.Wait()
			cancel()
		}
	}
}

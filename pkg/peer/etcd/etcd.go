package etcd

import (
	"context"
	"encoding/json"
	"net"
	"strings"
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

func (e *Etcd) Run(ctx context.Context) error {
	zap.L().Info("starting etcd reconciliation", zap.Duration("reconcileInterval", e.conf.ReconcileInterval))

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   e.conf.EtcdEndpoints,
		DialTimeout: time.Second * 5,
	})
	if err != nil {
		return err
	}
	const prefix = "/peers/"
	w := cli.Watch(ctx, prefix, clientv3.WithPrefix())
	for {
		select {
		case <-ctx.Done():
			return nil

		case update := <-w:
			if update.Canceled {
				continue
			}
			if update.Err() != nil {
				zap.L().Error("error while watching", zap.Error(err))
				continue
			}
			peers, err := e.wg.GetPeers()
			if err != nil {
				zap.L().Error("failed to get peers", zap.Error(err))
				continue
			}
			currentPeers := make(map[string]wgtypes.Peer, len(peers))
			for _, p := range peers {
				currentPeers[p.PublicKey.String()] = p
			}
			updates := make(map[wgtypes.Key]net.UDPAddr, len(update.Events))
			for _, ev := range update.Events {
				if ev.Type != clientv3.EventTypePut {
					continue
				}
				key := string(ev.Kv.Key)
				publicKey := strings.TrimLeft(key, prefix)
				zctx := zap.L().With(
					zap.String("etcdKey", key),
					zap.String("publicKey", publicKey),
				)
				cp, ok := currentPeers[publicKey]
				if !ok {
					zctx.Info("unknown peer")
					continue
				}
				ep := &etcd.Peer{}
				err = json.Unmarshal(ev.Kv.Value, ep)
				if err != nil {
					zctx.Error("failed to decode event", zap.Error(err))
					continue
				}
				zctx = zctx.With(
					zap.String("currentEndpoint", cp.Endpoint.String()),
					zap.Int64("currentHandshakeAge", cp.LastHandshakeTime.Unix()),
					zap.String("eventEndpoint", ep.Endpoint),
					zap.Int64("eventHandshakeAge", ep.HandshakeTimestamp),
				)
				if cp.LastHandshakeTime.Unix() > ep.HandshakeTimestamp {
					zctx.Info("current handshake is newer")
					continue
				}
				if cp.Endpoint.String() == ep.Endpoint {
					zctx.Info("same endpoints")
					continue
				}
				u, err := wireguard.ParseEndpoint(ep.Endpoint)
				if err != nil {
					zctx.Error("failed to parse endpoint", zap.Error(err))
					continue
				}
				updates[cp.PublicKey] = u
			}
			err = e.wg.SetNewEndpoints(updates)
			if err != nil {
				zap.L().Error("failed to set new endpoints", zap.Error(err))
				continue
			}
		}
	}
}

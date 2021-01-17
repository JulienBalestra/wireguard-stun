package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/JulienBalestra/dry/pkg/promregister"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.etcd.io/etcd/clientv3"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Config struct {
	Wireguard *wireguard.Config

	ReconcileInterval time.Duration
	ResyncInterval    time.Duration
	HandshakeAge      time.Duration

	EtcdEndpoints []string
	ListenAddr    string
}

type Etcd struct {
	conf      *Config
	c         *wgctrl.Client
	seenPeers map[wgtypes.Key]*Peer

	updateMetrics     *prometheus.CounterVec
	updateEtcdMetrics *prometheus.CounterVec
	seenPeersMetrics  prometheus.Gauge
	mux               *mux.Router
}

func NewEtcd(conf *Config) (*Etcd, error) {
	if conf.EtcdEndpoints == nil {
		return nil, errors.New("must provide etcd endpoints")
	}
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	_, err = c.Device(conf.Wireguard.DeviceName)
	if err != nil {
		return nil, err
	}
	e := &Etcd{
		conf:      conf,
		c:         c,
		mux:       mux.NewRouter(),
		seenPeers: make(map[wgtypes.Key]*Peer),
		updateMetrics: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wireguard_stun_registry_etcd_update_triggers",
			ConstLabels: prometheus.Labels{
				"device": conf.Wireguard.DeviceName,
			},
		},
			[]string{
				"new",
				"endpoint",
				"handshake",
			},
		),
		updateEtcdMetrics: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wireguard_stun_registry_etcd_txn",
			ConstLabels: prometheus.Labels{
				"device": conf.Wireguard.DeviceName,
			},
		},
			[]string{
				"success",
				"put",
			},
		),
		seenPeersMetrics: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "wireguard_stun_registry_etcd_peers",
			ConstLabels: prometheus.Labels{
				"device": conf.Wireguard.DeviceName,
			},
		}),
	}
	err = promregister.Register(e.seenPeersMetrics, e.updateEtcdMetrics, e.updateMetrics)
	if err != nil {
		return nil, err
	}
	e.mux.NewRoute().Name("metrics").Path("/metrics").Methods(http.MethodGet).Handler(promhttp.Handler())
	return e, nil
}

type Peer struct {
	Endpoint           string `json:"endpoint"`
	HandshakeTimestamp int64  `json:"handshake-ts"`
}

func (e *Etcd) updateEtcdState(ctx context.Context) error {
	d, err := e.c.Device(e.conf.Wireguard.DeviceName)
	if err != nil {
		zap.L().Error("failed to get device", zap.Error(err))
		return err
	}

	updates := make(map[wgtypes.Key]*Peer)
	for _, currentPeer := range d.Peers {
		if currentPeer.Endpoint == nil {
			continue
		}
		cp := &Peer{
			Endpoint:           currentPeer.Endpoint.String(),
			HandshakeTimestamp: currentPeer.LastHandshakeTime.Unix(),
		}
		seenPeer, ok := e.seenPeers[currentPeer.PublicKey]
		if !ok {
			updates[currentPeer.PublicKey] = cp
			zap.L().With(
				zap.String("publicKey", currentPeer.PublicKey.String()),
				zap.String("endpoint", cp.Endpoint),
				zap.Int64("handshakeTimestamp", cp.HandshakeTimestamp),
				zap.Bool("newPeer", true),
				zap.Bool("handshakeUpdate", false),
				zap.Bool("endpointUpdate", false),
			).Info("new peer detected")
			e.updateMetrics.WithLabelValues(
				"true",
				"false",
				"false",
			).Inc()
			continue
		}
		if cp.HandshakeTimestamp > seenPeer.HandshakeTimestamp {
			endpointUpdate := seenPeer.Endpoint != cp.Endpoint
			updates[currentPeer.PublicKey] = cp
			zap.L().With(
				zap.String("publicKey", currentPeer.PublicKey.String()),
				zap.String("endpoint", cp.Endpoint),
				zap.Int64("handshakeTimestamp", cp.HandshakeTimestamp),
				zap.Bool("newPeer", false),
				zap.Bool("handshakeUpdate", true),
				zap.Bool("endpointUpdate", endpointUpdate),
			).Info("update on peer detected")
			e.updateMetrics.WithLabelValues(
				"false",
				"true",
				strconv.FormatBool(seenPeer.Endpoint != cp.Endpoint),
			).Inc()
			continue
		}
		if seenPeer.Endpoint != cp.Endpoint {
			updates[currentPeer.PublicKey] = cp
			zap.L().With(
				zap.String("publicKey", currentPeer.PublicKey.String()),
				zap.String("endpoint", cp.Endpoint),
				zap.Int64("handshakeTimestamp", cp.HandshakeTimestamp),
				zap.Bool("newPeer", false),
				zap.Bool("handshakeUpdate", false),
				zap.Bool("endpointUpdate", true),
			).Info("update on peer detected")
			e.updateMetrics.WithLabelValues(
				"false",
				"false",
				"true",
			).Inc()
			continue
		}
		// nothing to update
	}
	if len(updates) == 0 {
		return nil
	}
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   e.conf.EtcdEndpoints,
		DialTimeout: time.Second * 5,
	})
	if err != nil {
		return err
	}
	for key, peer := range updates {
		etcdKey := "/peers/" + key.String()
		zctx := zap.L().With(
			zap.String("etcdKey", etcdKey),
			zap.String("publicKey", key.String()),
			zap.String("endpoint", peer.Endpoint),
			zap.Int64("handshakeTimestamp", peer.HandshakeTimestamp),
		)
		b, err := json.Marshal(peer)
		if err != nil {
			zctx.Error("failed to marshal peer", zap.Error(err))
			e.updateEtcdMetrics.WithLabelValues("false", "false").Inc()
			continue
		}
		etcdData := string(b)
		resp, err := cli.Txn(ctx).If(
			clientv3.Compare(clientv3.Value(etcdKey), "=", etcdData),
		).Else(
			clientv3.OpPut(etcdKey, etcdData),
		).Commit()
		if err != nil {
			zctx.Error("failed to commit peer to etcd", zap.Error(err))
			e.updateEtcdMetrics.WithLabelValues("false", "false").Inc()
			continue
		}
		e.seenPeers[key] = peer
		zctx.With(
			zap.Bool("etcdPUT", !resp.Succeeded),
		).Info("successfully updated etcd state")
		e.updateEtcdMetrics.WithLabelValues("true", strconv.FormatBool(!resp.Succeeded)).Inc()
	}
	e.seenPeersMetrics.Set(float64(len(e.seenPeers)))
	return cli.Close()
}

func (e *Etcd) Run(ctx context.Context) error {
	l, err := net.Listen("tcp4", e.conf.ListenAddr)
	if err != nil {
		return err
	}

	go http.Serve(l, e.mux)

	ticker := time.NewTicker(e.conf.ResyncInterval)
	defer ticker.Stop()
	for {
		after := time.After(e.conf.ReconcileInterval)
		select {
		case <-ctx.Done():
			return l.Close()

		case <-ticker.C:
			zap.L().Info("forcing a full resync")
			e.seenPeers = make(map[wgtypes.Key]*Peer, len(e.seenPeers))

		case <-after:
			err := e.updateEtcdState(ctx)
			if err != nil {
				zap.L().Error("failed to update etcd state", zap.Error(err))
			}
		}
	}
}

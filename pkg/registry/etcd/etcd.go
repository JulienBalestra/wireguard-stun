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
	"github.com/JulienBalestra/dry/pkg/ticknow"
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

	ReconcileInterval  time.Duration
	ResyncInterval     time.Duration
	DefragInterval     time.Duration
	CompactionInterval time.Duration
	HandshakeAge       time.Duration

	EtcdEndpoints []string
	ListenAddr    string
}

type Etcd struct {
	conf           *Config
	wgClient       *wgctrl.Client
	etcdClient     *clientv3.Client
	seenPeers      map[wgtypes.Key]*Peer
	latestRevision int64

	updateMetrics     *prometheus.CounterVec
	etcdConnState     *prometheus.CounterVec
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
	e := &Etcd{
		conf:     conf,
		mux:      mux.NewRouter(),
		wgClient: c,
		updateMetrics: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wireguard_stun_registry_etcd_update_triggers",
			ConstLabels: prometheus.Labels{
				"device": conf.Wireguard.DeviceName,
			},
		},
			[]string{
				"resync",
				"handshake",
				"endpoint",
			},
		),
		etcdConnState: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wireguard_stun_etcd_conn_state",
		},
			[]string{
				"state",
				"target",
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
			Name: "wireguard_stun_peers",
			ConstLabels: prometheus.Labels{
				"device": conf.Wireguard.DeviceName,
			},
		}),
	}
	err = promregister.Register(
		e.seenPeersMetrics,
		e.updateEtcdMetrics,
		e.updateMetrics,
		e.etcdConnState,
	)
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
	d, err := e.wgClient.Device(e.conf.Wireguard.DeviceName)
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
				zap.Bool("resyncPeer", true),
				zap.Bool("handshakeUpdate", false),
				zap.Bool("endpointUpdate", false),
			).Debug("resync peer detected")
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
				zap.Bool("resyncPeer", false),
				zap.Bool("handshakeUpdate", true),
				zap.Bool("endpointUpdate", endpointUpdate),
			).Debug("update on peer detected")
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
				zap.Bool("resyncPeer", false),
				zap.Bool("handshakeUpdate", false),
				zap.Bool("endpointUpdate", true),
			).Debug("update on peer detected")
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
		resp, err := e.etcdClient.Txn(ctx).If(
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
		zctx = zctx.With(
			zap.Bool("etcdPUT", !resp.Succeeded),
			zap.Int64("etcdRevision", resp.Header.GetRevision()),
		)
		e.updateEtcdMetrics.WithLabelValues("true", strconv.FormatBool(!resp.Succeeded)).Inc()
		if resp.Succeeded {
			zctx.Debug("etcd state already up to date")
			continue
		}
		e.latestRevision = resp.Header.GetRevision()
		zctx.Info("successfully updated etcd state")
	}
	e.seenPeersMetrics.Set(float64(len(e.seenPeers)))
	return nil
}

func (e *Etcd) Run(ctx context.Context) error {
	l, err := net.Listen("tcp4", e.conf.ListenAddr)
	if err != nil {
		return err
	}

	go http.Serve(l, e.mux)

	e.etcdClient, err = clientv3.New(clientv3.Config{
		Endpoints:            e.conf.EtcdEndpoints,
		DialTimeout:          time.Second * 5,
		DialKeepAliveTime:    time.Minute,
		DialKeepAliveTimeout: time.Second * 5,
		Context:              ctx,
	})
	if err != nil {
		return err
	}
	resync := ticknow.NewTickNow(ctx, e.conf.ResyncInterval)
	ticker := ticknow.NewTickNow(ctx, time.Second)
	var reconcile <-chan time.Time

	defrag := time.NewTicker(e.conf.DefragInterval)
	defer defrag.Stop()

	compaction := time.NewTicker(e.conf.CompactionInterval)
	defer compaction.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = e.etcdClient.ActiveConnection().Close()
			_ = e.etcdClient.Close()
			_ = e.wgClient.Close()
			return l.Close()

		case <-compaction.C:
			if e.latestRevision == 0 {
				continue
			}
			zctx := zap.L().With(
				zap.Int64("latestRevision", e.latestRevision),
			)
			_, err := e.etcdClient.Compact(ctx, e.latestRevision)
			e.latestRevision = 0
			if err != nil {
				zctx.Error("failed to compact revision", zap.Error(err))
				continue
			}
			zctx.Info("successfully compacted")

		case <-defrag.C:
			for _, ep := range e.etcdClient.Endpoints() {
				zctx := zap.L().With(
					zap.String("endpoint", ep),
				)
				_, err := e.etcdClient.Defragment(ctx, ep)
				if err != nil {
					zctx.Error("failed to defragment", zap.Error(err))
					continue
				}
				zctx.Info("successfully defragment")
			}

		case <-ticker.C:
			e.etcdConnState.WithLabelValues(
				e.etcdClient.ActiveConnection().GetState().String(),
				e.etcdClient.ActiveConnection().Target(),
			).Inc()

		case <-resync.C:
			zap.L().Debug("forcing a full resync")
			e.seenPeers = make(map[wgtypes.Key]*Peer, len(e.seenPeers))
			if reconcile == nil {
				zap.L().Info("starting reconciliation")
				reconcile = time.After(0)
			}

		case <-reconcile:
			err := e.updateEtcdState(ctx)
			if err != nil {
				zap.L().Error("failed to update etcd state", zap.Error(err))
				reconcile = time.After(e.conf.ReconcileInterval * 10)
				continue
			}
			reconcile = time.After(e.conf.ReconcileInterval)
		}
	}
}

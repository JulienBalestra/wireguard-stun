package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/JulienBalestra/dry/pkg/promregister"
	"github.com/JulienBalestra/dry/pkg/ticknow"
	"github.com/JulienBalestra/wireguard-stun/pkg/etcd/metrics"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.etcd.io/etcd/clientv3"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Config struct {
	Wireguard *wireguard.Config

	ReconcileInterval  time.Duration
	ReSyncInterval     time.Duration
	DefragInterval     time.Duration
	CompactionInterval time.Duration
	HandshakeAge       time.Duration

	EtcdEndpoints []string
	EtcdPrefix    string
	ListenAddr    string
}

type Etcd struct {
	conf               *Config
	wg                 *wireguard.Wireguard
	etcdClient         *clientv3.Client
	seenPeers          map[wgtypes.Key]*Peer
	compactionRevision int64
	mu                 *sync.RWMutex

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
	c, err := wireguard.NewWireguardClient(conf.Wireguard)
	if err != nil {
		return nil, err
	}
	e := &Etcd{
		conf: conf,
		mux:  mux.NewRouter(),
		mu:   &sync.RWMutex{},
		wg:   c,
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
	e.seenPeersMetrics.Set(0)
	labels := []string{"true", "false"}
	for _, first := range labels {
		for _, second := range labels {
			e.updateEtcdMetrics.WithLabelValues(first, second).Add(0)
			for _, third := range labels {
				e.updateMetrics.WithLabelValues(first, second, third).Add(0)
			}
		}
	}
	e.mux.NewRoute().Name("metrics").Path("/metrics").Methods(http.MethodGet).Handler(promhttp.Handler())
	return e, nil
}

type Peer struct {
	Endpoint           string `json:"endpoint"`
	HandshakeTimestamp int64  `json:"handshake-ts"`
}

func (e *Etcd) updateEtcdState(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	peers, err := e.wg.GetPeers()
	if err != nil {
		zap.L().Error("failed to get device", zap.Error(err))
		return err
	}

	updates := make(map[wgtypes.Key]*Peer)
	for _, currentPeer := range peers {
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
		etcdKey := e.conf.EtcdPrefix + key.String()
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
		e.compactionRevision = resp.Header.GetRevision()
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
	metrics.InitEtcdConnectionState(e.etcdConnState, e.etcdClient.ActiveConnection())

	wg := &sync.WaitGroup{}
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		connState := ticknow.NewTickNowWithContext(ctx, time.Second)
		for {
			select {
			case <-ctx.Done():
				return

			case <-connState.C:
				e.etcdConnState.WithLabelValues(
					e.etcdClient.ActiveConnection().GetState().String(),
					e.etcdClient.ActiveConnection().Target(),
				).Inc()
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defrag := time.NewTicker(e.conf.DefragInterval)
		for {
			select {
			case <-ctx.Done():
				return

			case <-defrag.C:
				var after time.Duration = 0
				for _, ep := range e.etcdClient.Endpoints() {
					select {
					case <-ctx.Done():
						return

					case <-time.After(after):
						after = time.Second * 5
						zctx := zap.L().With(
							zap.String("endpoint", ep),
						)
						_, err = e.etcdClient.Defragment(ctx, ep)
						if err != nil {
							zctx.Error("failed to defragment", zap.Error(err))
							continue
						}
						zctx.Info("successfully defragment")
						// TODO: do something smarter
					}
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		compaction := time.NewTicker(e.conf.CompactionInterval)
		for {
			select {
			case <-ctx.Done():
				return

			case <-compaction.C:
				e.mu.RLock()
				rev := e.compactionRevision
				e.mu.RUnlock()
				if rev == 0 {
					continue
				}
				zctx := zap.L().With(
					zap.Int64("compactionRevision", e.compactionRevision),
				)
				_, err = e.etcdClient.Compact(ctx, e.compactionRevision)
				e.compactionRevision = 0
				if err != nil {
					zctx.Error("failed to compact revision", zap.Error(err))
					continue
				}
				zctx.Info("successfully compacted")
			}
		}
	}()

	reSync := ticknow.NewTickNowWithContext(ctx, e.conf.ReSyncInterval)
	var reconcile <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			_ = e.etcdClient.ActiveConnection().Close()
			_ = e.etcdClient.Close()
			_ = l.Close()
			return nil

		case <-reSync.C:
			zap.L().Debug("forcing a full resync")
			e.mu.Lock()
			e.seenPeers = make(map[wgtypes.Key]*Peer, len(e.seenPeers))
			e.mu.Unlock()
			if reconcile == nil {
				zap.L().Info("starting reconciliation")
				reconcile = time.After(0)
			}

		case <-reconcile:
			err = e.updateEtcdState(ctx)
			if err != nil {
				zap.L().Error("failed to update etcd state", zap.Error(err))
				reconcile = time.After(e.conf.ReconcileInterval * 10)
				continue
			}
			reconcile = time.After(e.conf.ReconcileInterval)
		}
	}
}

package etcd

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/JulienBalestra/dry/pkg/promregister"
	"github.com/JulienBalestra/dry/pkg/ticknow"
	"github.com/JulienBalestra/wireguard-stun/pkg/etcd/metrics"
	"github.com/JulienBalestra/wireguard-stun/pkg/registry/etcd"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.etcd.io/etcd/clientv3"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/connectivity"
)

const (
	labelProgressNotify = "progress-notify"
	labelClose          = "close"
	labelEvents         = "events"
	labelError          = "error"
	labelCancel         = "cancel"
	labelEmpty          = "empty"
)

type Config struct {
	EtcdEndpoint string
	EtcdPrefix   string

	Wireguard     *wireguard.Config
	EtcdEndpoints []string
	ListenAddr    string
	StaticPeers   []string
}

type Etcd struct {
	conf *Config

	wg          *wireguard.Wireguard
	etcdClient  *clientv3.Client
	mux         *mux.Router
	staticPeers map[wgtypes.Key]struct{}

	receivedEvents *prometheus.CounterVec
	etcdConnState  *prometheus.CounterVec
	seenPeers      prometheus.Gauge
}

func NewPeerEtcd(conf *Config) (*Etcd, error) {
	wg, err := wireguard.NewWireguardClient(conf.Wireguard)
	if err != nil {
		return nil, err
	}
	sc, err := wireguard.ParseStaticConfiguration(conf.Wireguard.DeviceName)
	if err != nil {
		return nil, err
	}
	staticPeers := make(map[wgtypes.Key]struct{}, len(conf.StaticPeers)+len(sc.Peers))
	for _, p := range conf.StaticPeers {
		k, err := wgtypes.ParseKey(p)
		if err != nil {
			return nil, err
		}
		staticPeers[k] = struct{}{}
	}
	for _, p := range sc.Peers {
		if p.Endpoint == nil {
			continue
		}
		staticPeers[p.PublicKey] = struct{}{}
	}
	e := &Etcd{
		conf:        conf,
		staticPeers: staticPeers,
		wg:          wg,
		mux:         mux.NewRouter(),
		receivedEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wireguard_stun_peer_etcd_updates",
			ConstLabels: prometheus.Labels{
				"device": conf.Wireguard.DeviceName,
			},
		},
			[]string{
				"type",
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
		seenPeers: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "wireguard_stun_peers",
			ConstLabels: prometheus.Labels{
				"device": conf.Wireguard.DeviceName,
			},
		}),
	}
	err = promregister.Register(
		e.receivedEvents,
		e.etcdConnState,
		e.seenPeers,
	)
	if err != nil {
		return nil, err
	}
	e.seenPeers.Set(0)
	e.receivedEvents.WithLabelValues(labelClose).Add(0)
	e.receivedEvents.WithLabelValues(labelEvents).Add(0)
	e.receivedEvents.WithLabelValues(labelProgressNotify).Add(0)
	e.receivedEvents.WithLabelValues(labelError).Add(0)
	e.receivedEvents.WithLabelValues(labelCancel).Add(0)
	e.receivedEvents.WithLabelValues(labelEmpty).Add(0)
	e.mux.NewRoute().Name("metrics").Path("/metrics").Methods(http.MethodGet).Handler(promhttp.Handler())
	return e, nil
}

func (e *Etcd) processEvents(ctx context.Context, w clientv3.WatchChan) error {
	for {
		select {
		case <-ctx.Done():
			return nil

		case update, ok := <-w:
			if !ok {
				zap.L().Info("chan is closed")
				e.receivedEvents.WithLabelValues(labelClose).Inc()
				return nil
			}
			if update.Canceled {
				zap.L().Info("updates canceled")
				e.receivedEvents.WithLabelValues(labelCancel).Inc()
				return nil
			}
			if update.Err() != nil {
				zap.L().Error("error while watching", zap.Error(update.Err()))
				e.receivedEvents.WithLabelValues(labelError).Inc()
				return update.Err()
			}
			if update.IsProgressNotify() {
				zap.L().Info("received progress notify")
				e.receivedEvents.WithLabelValues(labelProgressNotify).Inc()
				continue
			}
			if len(update.Events) == 0 {
				zap.L().Warn("no event")
				e.receivedEvents.WithLabelValues(labelEmpty).Inc()
				continue
			}
			e.receivedEvents.WithLabelValues(labelEvents)

			// now the logic begins
			currentPeers, err := e.wg.GetIndexedPeers()
			if err != nil {
				zap.L().Error("failed to get peers", zap.Error(err))
				continue
			}
			e.seenPeers.Set(float64(len(currentPeers)))
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
					zctx.Warn("unknown peer")
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
				updates[cp.PublicKey] = *u
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

func (e *Etcd) isConnReady(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, time.Minute*2)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return false

		default:
			state := e.etcdClient.ActiveConnection().GetState()
			zctx := zap.L().With(
				zap.String("target", e.etcdClient.ActiveConnection().Target()),
				zap.String("state", state.String()),
			)
			switch state {
			case connectivity.Connecting:
				zctx.Info("connecting")
				if !e.etcdClient.ActiveConnection().WaitForStateChange(ctx, connectivity.Connecting) {
					return false
				}

			case connectivity.TransientFailure:
				zctx.Warn("connectivity with transient failure, retrying")
				if !e.etcdClient.ActiveConnection().WaitForStateChange(ctx, connectivity.TransientFailure) {
					return false
				}

			case connectivity.Ready:
				zap.L().With(
					zap.String("target", e.etcdClient.ActiveConnection().Target()),
					zap.String("state", state.String()),
				).Debug("connection is ready")
				return true

			case connectivity.Idle:
				zctx.Debug("idle, retrying")
				if !e.etcdClient.ActiveConnection().WaitForStateChange(ctx, connectivity.Idle) {
					return false
				}

			case connectivity.Shutdown:
				zctx.Warn("shutting down, retrying")
				if !e.etcdClient.ActiveConnection().WaitForStateChange(ctx, connectivity.Shutdown) {
					return false
				}
			}
		}
	}
}

func (e *Etcd) watchWireguardPeers(ctx context.Context) error {
	peers, err := e.wg.GetPeers()
	if err != nil {
		zap.L().Error("failed to get peers", zap.Error(err))
		return err
	}
	e.seenPeers.Set(float64(len(peers)))

	ctx, cancel := context.WithCancel(ctx)
	wg := sync.WaitGroup{}
	for _, p := range peers {
		_, ok := e.staticPeers[p.PublicKey]
		if ok {
			continue
		}
		wg.Add(1)
		go func(s string) {
			defer cancel()
			defer wg.Done()
			etcdKey := e.conf.EtcdPrefix + s
			zctx := zap.L().With(
				zap.String("publicKey", s),
				zap.String("etcdKey", etcdKey),
			)
			// TODO: get and set before watch
			zctx.Info("starting to watch")
			w := e.etcdClient.Watch(ctx, etcdKey, clientv3.WithFilterDelete(), clientv3.WithProgressNotify())
			err = e.processEvents(ctx, w)
			if err != nil {
				zctx.Error("finished to watch on error", zap.Error(err))
				return
			}
			zctx.Info("finished to watch")
		}(p.PublicKey.String())
	}
	watchdog := time.NewTicker(time.Millisecond * 100)
	for {
		select {
		case <-ctx.Done():
			watchdog.Stop()
			cancel()
			wg.Wait()
			return nil

		case <-watchdog.C:
			state := e.etcdClient.ActiveConnection().GetState()
			switch state {
			case connectivity.TransientFailure:
				zap.L().With(
					zap.String("state", state.String()),
				).Warn("connectivity with transient failure, canceling watches")
				cancel()
			case connectivity.Connecting:
				zap.L().With(
					zap.String("state", state.String()),
				).Warn("lost connection, canceling watches")
				cancel()
			}
		}
	}
}

func (e *Etcd) Run(ctx context.Context) error {
	l, err := net.Listen("tcp4", e.conf.ListenAddr)
	if err != nil {
		return err
	}

	go http.Serve(l, e.mux)

	e.etcdClient, err = clientv3.New(clientv3.Config{
		Endpoints:            e.conf.EtcdEndpoints,
		DialTimeout:          time.Second * 15,
		DialKeepAliveTime:    time.Minute,
		DialKeepAliveTimeout: time.Second * 15,
		Context:              ctx,
		PermitWithoutStream:  true,
	})
	if err != nil {
		zap.L().Error("failed to create etcd client", zap.Error(err))
		return err
	}
	metrics.InitEtcdConnectionState(e.etcdConnState, e.etcdClient.ActiveConnection())
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		connState := ticknow.NewTickNowWithContext(ctx, time.Second)
		for {
			select {
			case <-ctx.Done():
				wg.Done()
				return

			case <-connState.C:
				e.etcdConnState.WithLabelValues(
					e.etcdClient.ActiveConnection().GetState().String(),
					e.etcdClient.ActiveConnection().Target(),
				).Inc()
			}
		}
	}()

	after := time.After(0)
	for {
		select {
		case <-ctx.Done():
			_ = e.etcdClient.Watcher.Close()
			_ = e.etcdClient.ActiveConnection().Close()
			_ = e.etcdClient.Close()
			wg.Wait()
			return nil

		case <-after:
			var wait time.Duration = 0

			zap.L().Info("starting etcd reconciliation")
			if !e.isConnReady(ctx) {
				after = time.After(wait)
				continue
			}
			err = e.watchWireguardPeers(ctx)
			if err != nil {
				wait = time.Second
			}
			after = time.After(wait)
		}
	}
}

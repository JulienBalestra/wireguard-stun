package etcd

import (
	"context"
	"encoding/json"
	"google.golang.org/grpc/connectivity"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/JulienBalestra/dry/pkg/promregister"
	"github.com/JulienBalestra/dry/pkg/ticknow"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/JulienBalestra/wireguard-stun/pkg/registry/etcd"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"go.etcd.io/etcd/clientv3"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
	sp := make(map[wgtypes.Key]struct{}, len(conf.StaticPeers))
	for _, p := range conf.StaticPeers {
		k, err := wgtypes.ParseKey(p)
		if err != nil {
			return nil, err
		}
		sp[k] = struct{}{}
	}
	e := &Etcd{
		conf:        conf,
		staticPeers: sp,
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
				zap.L().Info("context canceled")
				e.receivedEvents.WithLabelValues("close").Inc()
				return nil
			}
			if update.Canceled {
				zap.L().Info("update canceled")
				e.receivedEvents.WithLabelValues("cancel").Inc()
				return nil
			}
			if update.Err() != nil {
				zap.L().Error("error while watching", zap.Error(update.Err()))
				e.receivedEvents.WithLabelValues("error").Inc()
				return update.Err()
			}
			if update.IsProgressNotify() {
				zap.L().Info("received progress notify")
				e.receivedEvents.WithLabelValues("progress-notify").Inc()
				continue
			}
			if len(update.Events) == 0 {
				zap.L().Info("no event")
				e.receivedEvents.WithLabelValues("empty").Inc()
				continue
			}
			e.receivedEvents.WithLabelValues("events").Inc()
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
	l, err := net.Listen("tcp4", e.conf.ListenAddr)
	if err != nil {
		return err
	}

	go http.Serve(l, e.mux)

	zap.L().Info("starting etcd reconciliation")
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:            e.conf.EtcdEndpoints,
		DialTimeout:          time.Second * 5,
		DialKeepAliveTime:    time.Minute,
		DialKeepAliveTimeout: time.Second * 5,
		Context:              ctx,
	})
	if err != nil {
		zap.L().Error("failed to create etcd client", zap.Error(err))
		return err
	}

	after := time.After(time.Second)
	connState := ticknow.NewTickNow(ctx, time.Second)
	const waitBeforeRetry = time.Second * 15
	for {
		select {
		case <-ctx.Done():
			_ = cli.Watcher.Close()
			_ = cli.ActiveConnection().Close()
			_ = cli.Close()
			return nil

		case <-connState.C:
			e.etcdConnState.WithLabelValues(
				cli.ActiveConnection().GetState().String(),
				cli.ActiveConnection().Target(),
			).Inc()

		case <-after:
			switch cli.ActiveConnection().GetState() {
			case connectivity.TransientFailure:
				zap.L().With(
					zap.String("target", cli.ActiveConnection().Target()),
				).Info("Connectivity with transient failure, retrying")
				after = time.After(waitBeforeRetry)
				continue
			case connectivity.Connecting:
				zap.L().With(
					zap.String("target", cli.ActiveConnection().Target()),
				).Info("Still connecting")
				after = time.After(waitBeforeRetry)
				continue
			case connectivity.Ready:
				cli.ActiveConnection().ResetConnectBackoff()
			}
			peers, err := e.wg.GetPeers()
			if err != nil {
				zap.L().Error("failed to get peers", zap.Error(err))
				after = time.After(waitBeforeRetry)
				continue
			}
			e.seenPeers.Set(float64(len(peers)))
			go func() {
				wCtx, cancel := context.WithCancel(ctx)
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
						w := cli.Watch(wCtx, etcdKey, clientv3.WithFilterDelete(), clientv3.WithProgressNotify())
						err = e.processEvents(ctx, w)
						if err != nil {
							zctx.Error("finished to watch on error", zap.Error(err))
							return
						}
						zctx.Info("finished to watch")
					}(p.PublicKey.String())
				}
				watchdog := ticknow.NewTickNow(wCtx, time.Millisecond*100)
				for {
					select {
					case <-watchdog.C:
						switch cli.ActiveConnection().GetState() {
						case connectivity.TransientFailure:
							zap.L().With(
								zap.String("target", cli.ActiveConnection().Target()),
							).Warn("connectivity with transient failure, canceling watches")
							cancel()
						case connectivity.Connecting:
							zap.L().With(
								zap.String("target", cli.ActiveConnection().Target()),
							).Warn("lost connection, canceling watches")
							cancel()
						}
					case <-wCtx.Done():
						cancel()
						wg.Wait()
						after = time.After(waitBeforeRetry)
						return
					}
				}
			}()
		}
	}
}

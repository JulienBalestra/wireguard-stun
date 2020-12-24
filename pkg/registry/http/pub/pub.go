package pub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/JulienBalestra/wireguard-stun/pkg/pubsub"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Config struct {
	WireguardConfig   *wireguard.Config
	ListenAddr        string
	HandshakeAge      time.Duration
	RemoteSubTTL      time.Duration
	ReconcileInterval time.Duration
}

type Pub struct {
	conf *Config
	c    *wgctrl.Client
	mux  *mux.Router

	mu           sync.Mutex
	subscription map[string]*Sub
	httpClient   *http.Client

	activeSubscriptions prometheus.Gauge
	activePeers         prometheus.Gauge
	newSubscriptions    *prometheus.CounterVec
	eventsSent          *prometheus.CounterVec
}

func NewPub(conf *Config) (*Pub, error) {
	if conf.WireguardConfig.DeviceName == "" {
		return nil, errors.New("empty wireguard device name")
	}
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	p := &Pub{
		conf:         conf,
		c:            c,
		mux:          mux.NewRouter(),
		subscription: make(map[string]*Sub),
		httpClient: &http.Client{
			Timeout: time.Second,
		},
		activeSubscriptions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "wireguard_stun_pubsub_active_subscriptions",
			ConstLabels: prometheus.Labels{
				"device": conf.WireguardConfig.DeviceName,
			},
		}),
		activePeers: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "wireguard_stun_pubsub_active_peers",
			ConstLabels: prometheus.Labels{
				"device": conf.WireguardConfig.DeviceName,
			},
		}),
		newSubscriptions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wireguard_stun_pubsub_new_subscriptions",
			ConstLabels: prometheus.Labels{
				"device": conf.WireguardConfig.DeviceName,
			},
		},
			[]string{
				"success",
			},
		),
		eventsSent: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wireguard_stun_pubsub_sent_events",
			ConstLabels: prometheus.Labels{
				"device": conf.WireguardConfig.DeviceName,
			},
		},
			[]string{
				"success",
			},
		),
	}
	prometheus.MustRegister(
		p.activeSubscriptions,
		p.activePeers,
		p.newSubscriptions,
		p.eventsSent,
	)
	p.mux.NewRoute().Name("metrics").Path("/metrics").Methods(http.MethodGet).Handler(promhttp.Handler())
	p.mux.NewRoute().Name("sub").Path(pubsub.SubAPIPath).Methods(http.MethodPost).HandlerFunc(p.ServeHTTP)
	return p, nil
}

type Sub struct {
	Remote    *pubsub.PubSub
	Timestamp time.Time

	activePeers map[wgtypes.Key]wgtypes.Peer
}

func (p *Pub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		zap.L().Error("failed to read body", zap.Error(err))
		p.newSubscriptions.WithLabelValues("false").Inc()
		return
	}
	rp := &pubsub.PubSub{}
	err = json.Unmarshal(b, rp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		zap.L().Error("failed to unmarshal sub")
		p.newSubscriptions.WithLabelValues("false").Inc()
		return
	}
	zctx := zap.L().With(
		zap.String("publicKey", rp.PublicKey),
		zap.String("endpoint", rp.URL),
		zap.Duration("ttl", rp.TTL),
	)
	if rp.PublicKey == "" {
		w.WriteHeader(http.StatusBadRequest)
		zctx.Error("missing publicKey")
		p.newSubscriptions.WithLabelValues("false").Inc()
		return
	}
	if rp.URL == "" {
		w.WriteHeader(http.StatusBadRequest)
		zctx.Error("missing url")
		p.newSubscriptions.WithLabelValues("false").Inc()
		return
	}

	p.mu.Lock()
	p.subscription[rp.PublicKey] = &Sub{
		Remote:      rp,
		Timestamp:   time.Now(),
		activePeers: make(map[wgtypes.Key]wgtypes.Peer),
	}
	p.mu.Unlock()
	zctx.Info("new subscription")
	p.newSubscriptions.WithLabelValues("true").Inc()
}

func (p *Pub) post(ctx context.Context, endpoint string, updates map[string]string) error {
	var body bytes.Buffer
	err := json.NewEncoder(&body).Encode(updates)
	if err != nil {
		zap.L().Error("event marshal failed", zap.Error(err))
		p.eventsSent.WithLabelValues("false").Inc()
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &body)
	if err != nil {
		zap.L().Error("failed to create request", zap.Error(err))
		p.eventsSent.WithLabelValues("false").Inc()
		return err
	}
	_, err = p.httpClient.Do(req)
	if err != nil {
		zap.L().Error("failed to post request", zap.Error(err))
		p.eventsSent.WithLabelValues("false").Inc()
		return err
	}
	p.eventsSent.WithLabelValues("true").Inc()
	return nil
}

func (p *Pub) discoverBroadcast(ctx context.Context) error {
	zap.L().Debug("discovering")
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.subscription) == 0 {
		return nil
	}
	d, err := p.c.Device(p.conf.WireguardConfig.DeviceName)
	if err != nil {
		zap.L().Error("failed to get device", zap.Error(err))
		return err
	}

	activePeers := map[wgtypes.Key]wgtypes.Peer{}
	for _, newPeer := range d.Peers {
		if newPeer.Endpoint == nil {
			continue
		}
		if time.Since(newPeer.LastHandshakeTime) > p.conf.HandshakeAge {
			continue
		}
		activePeers[newPeer.PublicKey] = newPeer
	}
	p.activePeers.Set(float64(len(activePeers)))

	waitGroup := sync.WaitGroup{}
	pubCtx, cancel := context.WithTimeout(ctx, time.Second*2)
	for pubkey, sub := range p.subscription {
		if time.Since(sub.Timestamp) > sub.Remote.TTL {
			delete(p.subscription, pubkey)
			zap.L().With(
				zap.String("subPublicKey", pubkey),
				zap.Duration("ttl", sub.Remote.TTL),
			).Info("subscription is expired")
			continue
		}

		diff := make(map[wgtypes.Key]wgtypes.Peer, len(activePeers))
		for k, v := range activePeers {
			ap, ok := sub.activePeers[k]
			if !ok {
				diff[k] = v
				continue
			}
			if ap.Endpoint.String() != v.Endpoint.String() {
				diff[k] = v
				continue
			}
		}
		sub.activePeers = activePeers
		updates := make(pubsub.Updates)
		for k, v := range diff {
			if k.String() == pubkey {
				continue
			}
			updates[v.PublicKey.String()] = v.Endpoint.String()
			zap.L().Info("event detected",
				zap.String("subPublicKey", sub.Remote.PublicKey),
				zap.String("subEndpoint", sub.Remote.URL),
				zap.String("wgEndpoint", v.Endpoint.String()),
				zap.String("wgPublicKey", v.PublicKey.String()),
			)
			waitGroup.Add(1)
			go func(endpoint string, u map[string]string) {
				err := p.post(pubCtx, endpoint, u)
				if err != nil {
					zap.L().Error("failed to push update",
						zap.String("endpoint", endpoint),
						zap.Error(err),
					)
					// TODO manage retry ?
				}
				waitGroup.Done()
			}(sub.Remote.URL, updates)
		}
	}
	p.activeSubscriptions.Set(float64(len(p.subscription)))
	waitGroup.Wait()
	cancel()
	return nil
}

func (p *Pub) Run(ctx context.Context) error {
	l, err := net.Listen("tcp4", p.conf.ListenAddr)
	if err != nil {
		return err
	}
	defer l.Close()

	go http.Serve(l, p.mux)

	for {
		after := time.After(p.conf.ReconcileInterval)
		select {
		case <-ctx.Done():
			return nil

		case <-after:
			_ = p.discoverBroadcast(ctx)
		}
	}
}

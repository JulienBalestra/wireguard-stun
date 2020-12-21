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

	mu           sync.Mutex
	subscription map[string]*Sub
	httpClient   *http.Client
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
		subscription: make(map[string]*Sub),
		httpClient: &http.Client{
			Timeout: time.Second,
		},
	}
	r := mux.NewRouter()
	r.NewRoute().Name("sub").Path(pubsub.SubAPIPath).Methods(http.MethodPost).HandlerFunc(p.ServeHTTP)
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
		return
	}
	rp := &pubsub.PubSub{}
	err = json.Unmarshal(b, rp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		zap.L().Error("failed to unmarshal sub")
		return
	}
	zctx := zap.L().With(
		zap.String("publicKey", rp.PublicKey),
		zap.String("endpoint", rp.URL),
	)
	if rp.PublicKey == "" {
		w.WriteHeader(http.StatusBadRequest)
		zctx.Error("missing publicKey")
		return
	}
	if rp.URL == "" {
		w.WriteHeader(http.StatusBadRequest)
		zctx.Error("missing url")
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
}

func (p *Pub) post(ctx context.Context, endpoint string, updates map[string]string) error {
	var body bytes.Buffer
	err := json.NewEncoder(&body).Encode(updates)
	if err != nil {
		zap.L().Error("event marshal failed", zap.Error(err))
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &body)
	if err != nil {
		zap.L().Error("failed to create request", zap.Error(err))
		return err
	}
	_, err = p.httpClient.Do(req)
	if err != nil {
		zap.L().Error("failed to post request", zap.Error(err))
		return err
	}
	return nil
}

func (p *Pub) Run(ctx context.Context) error {
	l, err := net.Listen("tcp4", p.conf.ListenAddr)
	if err != nil {
		return err
	}

	defer l.Close()
	go http.Serve(l, p)

	for {
		after := time.After(p.conf.ReconcileInterval)
		select {
		case <-ctx.Done():
			return nil

		case <-after:
			zap.L().Debug("discovering")
			d, err := p.c.Device(p.conf.WireguardConfig.DeviceName)
			if err != nil {
				zap.L().Error("failed to get device", zap.Error(err))
				continue
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

			waitGroup := sync.WaitGroup{}
			pubCtx, cancel := context.WithTimeout(ctx, time.Second*2)
			p.mu.Lock()
			for pubkey, sub := range p.subscription {
				if time.Since(sub.Timestamp) > pubsub.SubscriptionTTL {
					delete(p.subscription, pubkey)
					zap.L().With(
						zap.String("subPublicKey", pubkey),
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
			p.mu.Unlock()
			waitGroup.Wait()
			cancel()
		}
	}
}

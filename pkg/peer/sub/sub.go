package sub

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JulienBalestra/dry/pkg/ticknow"
	"github.com/JulienBalestra/wireguard-stun/pkg/pubsub"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Config struct {
	PublicKey       string
	SubURL, PubURL  string
	RenewInterval   time.Duration
	SubscriptionTTL time.Duration
	WireguardConfig *wireguard.Config

	ListenAddr string
}

type Subscription struct {
	conf *Config
	wg   *wireguard.Wireguard

	httpClient *http.Client
}

func NewSubscription(conf *Config) (*Subscription, error) {

	wg, err := wireguard.NewWireguardClient(conf.WireguardConfig)
	if err != nil {
		return nil, err
	}
	s := &Subscription{
		conf: conf,
		wg:   wg,
		httpClient: &http.Client{
			Timeout: time.Second * 30,
		},
	}
	r := mux.NewRouter()
	r.NewRoute().Name("pub").Path(pubsub.PubAPIPath).Methods(http.MethodPost).HandlerFunc(s.ServeHTTP)
	return s, nil
}

func parseRemotePeer(key string, endpoint string) (*wgtypes.Key, *net.UDPAddr, error) {
	publicKey, err := wgtypes.ParseKey(key)
	if err != nil {
		return nil, nil, err
	}
	fields := strings.Split(endpoint, ":")
	if len(fields) != 2 {
		return nil, nil, err
	}
	endpointIP := net.ParseIP(fields[0])
	if endpointIP == nil {
		return nil, nil, err
	}
	endpointPort, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, nil, err
	}
	return &publicKey, &net.UDPAddr{
		IP:   endpointIP,
		Port: endpointPort,
	}, nil
}

func (s *Subscription) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		zap.L().Error("failed to ready body", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	updates := make(pubsub.Updates)
	err = json.Unmarshal(b, &updates)
	if err != nil {
		zap.L().Error("failed to unmarshal body", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	peerUpdates := make(map[wgtypes.Key]net.UDPAddr, len(updates))
	for k, v := range updates {
		pubKey, endpoint, err := parseRemotePeer(k, v)
		if err != nil {
			zap.L().Error("failed to parse remote peer", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		peerUpdates[*pubKey] = *endpoint
	}
	err = s.wg.SetNewEndpoints(peerUpdates)
	if err != nil {
		zap.L().Error("failed to set new endpoints", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Subscription) Run(ctx context.Context) error {
	zctx := zap.L().With(
		zap.String("subURL", s.conf.SubURL),
		zap.String("listenAddr", s.conf.ListenAddr),
		zap.Duration("subTTL", s.conf.SubscriptionTTL),
		zap.Duration("subRenew", s.conf.RenewInterval),
	)
	l, err := net.Listen("tcp4", s.conf.ListenAddr)
	if err != nil {
		return err
	}
	defer l.Close()

	ctx, cancel := context.WithCancel(ctx)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		err := http.Serve(l, s)
		if err != http.ErrServerClosed {
			zctx.Error("stop listening", zap.Error(err))
			cancel()
		}
		wg.Done()
	}()
	sub := ticknow.NewTickNow(ctx, s.conf.RenewInterval)
	gc := ticknow.NewTickNow(ctx, time.Second*25)
	for {
		select {
		case <-ctx.Done():
			return nil

		case <-sub.C:
			Peer := pubsub.PubSub{
				URL:       s.conf.PubURL,
				PublicKey: s.conf.PublicKey,
				TTL:       s.conf.SubscriptionTTL,
			}
			payload, err := json.Marshal(&Peer)
			if err != nil {
				zctx.Error("failed to marshal request", zap.Error(err))
				continue
			}
			var buf bytes.Buffer
			_, err = buf.Write(payload)
			if err != nil {
				zctx.Error("failed to create body request", zap.Error(err))
				continue
			}
			subCtx, subCancel := context.WithTimeout(ctx, time.Second*10)
			req, err := http.NewRequestWithContext(subCtx, http.MethodPost, s.conf.SubURL, &buf)
			if err != nil {
				zctx.Error("failed to create request", zap.Error(err))
				subCancel()
				continue
			}
			resp, err := s.httpClient.Do(req)
			subCancel()
			if err != nil {
				zctx.Error("failed to subscribe", zap.Error(err))
				continue
			}
			if resp.StatusCode != http.StatusOK {
				zctx.Error("failed to subscribe; un-excepted status code", zap.Int("code", resp.StatusCode))
				continue
			}
			zctx.Info("successfully subscribed")

		case <-gc.C:
			// TODO: do not discard registry endpoints
			//err = s.wg.DiscardStalingEndpoints()
			//if err != nil {
			//	zap.L().Error("failed to discard staling endpoints", zap.Error(err))
			//}
		}
	}
}

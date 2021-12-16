package dns

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/JulienBalestra/dry/pkg/ticknow"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Config struct {
	SRVRecordSuffix   string
	DNSTimeout        time.Duration
	ResolverEndpoint  string
	ReconcileInterval time.Duration

	Wireguard    *wireguard.Config
	StaticPeers  []string
	HandshakeAge time.Duration
}

type PeerDNS struct {
	conf *Config

	wg          *wireguard.Wireguard
	dnsClient   *dns.Client
	staticPeers map[wgtypes.Key]struct{}
}

func NewPeerDNS(conf *Config) (*PeerDNS, error) {
	if conf.SRVRecordSuffix == "" {
		return nil, errors.New("must provide a SRVRecordSuffix")
	}
	if conf.DNSTimeout == 0 {
		return nil, errors.New("must provide a DNSTimeout")
	}
	if conf.ResolverEndpoint == "" {
		return nil, errors.New("must provide a ResolverEndpoint")
	}
	wg, err := wireguard.NewWireguardClient(conf.Wireguard)
	if err != nil {
		return nil, err
	}

	sc, err := wireguard.ParseStaticConfiguration(conf.Wireguard.DeviceName)
	if err != nil {
		return nil, err
	}
	staticPeers := make(map[wgtypes.Key]struct{}, len(conf.StaticPeers)+len(sc.Peers))
	for _, elt := range conf.StaticPeers {
		k, err := wgtypes.ParseKey(elt)
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
	return &PeerDNS{
		conf: conf,
		wg:   wg,

		dnsClient: &dns.Client{
			Timeout: time.Second * 30,
		},
		staticPeers: staticPeers,
	}, nil
}

func (p *PeerDNS) Run(ctx context.Context) error {
	zap.L().Info("starting dns reconciliation",
		zap.Duration("reconcileInterval", p.conf.ReconcileInterval),
		zap.String("resolver", p.conf.ResolverEndpoint),
	)
	ticker := ticknow.NewTickNowWithContext(ctx, p.conf.ReconcileInterval)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = p.ReconcilePeerEndpoints(ctx)
		}
	}
}

func (p *PeerDNS) ReconcilePeerEndpoints(ctx context.Context) error {
	zctx := zap.L().With(
		zap.String("resolver", p.conf.ResolverEndpoint),
	)
	peers, err := p.wg.GetHashedPeers()
	if err != nil {
		return err
	}

	peerUpdates := make(map[wgtypes.Key]net.UDPAddr)
	for _, peer := range peers {
		_, ok := p.staticPeers[peer.PublicKey]
		if ok {
			continue
		}
		handshakeAge := time.Since(peer.LastHandshakeTime)
		srvQuery := peer.PublicKeyShortSha1 + p.conf.SRVRecordSuffix
		zctx = zctx.With(
			zap.String("publicKey", peer.PublicKey.String()),
			zap.String("publicKeyHash", peer.PublicKeyShortSha1),
			zap.String("srvQuery", srvQuery),
			zap.String("resolverEndpoint", p.conf.ResolverEndpoint),
			zap.Duration("handshakeAge", handshakeAge),
		)
		if handshakeAge < p.conf.HandshakeAge {
			zctx.Info("skipping peer with recent handshake")
			continue
		}
		msg := &dns.Msg{}
		msg.SetQuestion(srvQuery, dns.TypeSRV)
		resp, _, err := p.dnsClient.ExchangeContext(ctx, msg, p.conf.ResolverEndpoint)
		if err != nil {
			zctx.Error("skipping failed SRV query", zap.Error(err))
			continue
		}
		zctx = zctx.With(
			zap.Any("srvAnswer", resp.Answer),
		)
		if len(resp.Answer) != 1 {
			zctx.Warn("skipping invalid SRV answer", zap.Error(err))
			continue
		}
		srvAnswer, ok := resp.Answer[0].(*dns.SRV)
		if !ok {
			zctx.Warn("skipping invalid SRV answer", zap.Error(err))
			continue
		}
		if len(resp.Extra) == 1 {
			aAnswer, ok := resp.Extra[0].(*dns.A)
			if ok {
				peerUpdates[peer.PublicKey] = net.UDPAddr{
					IP:   aAnswer.A,
					Port: int(srvAnswer.Port),
				}
				continue
			}
			zctx.Warn("skipping invalid SRV extra answer", zap.Error(err))
		}
		zctx = zctx.With(
			zap.String("aQuery", srvAnswer.Target),
		)
		msg.SetQuestion(srvAnswer.Target, dns.TypeA)
		resp, _, err = p.dnsClient.ExchangeContext(ctx, msg, p.conf.ResolverEndpoint)
		if err != nil {
			zctx.Warn("skipping failed A query", zap.Error(err))
			continue
		}
		zctx = zctx.With(
			zap.Any("aAnswer", resp.Answer),
		)
		if len(resp.Answer) != 1 {
			zctx.Warn("skipping invalid A answer")
			continue
		}
		aAnswer, ok := resp.Answer[0].(*dns.A)
		if !ok {
			zctx.Warn("skipping invalid A answer")
			continue
		}
		peerUpdates[peer.PublicKey] = net.UDPAddr{
			IP:   aAnswer.A,
			Port: int(srvAnswer.Port),
		}
	}
	if len(peerUpdates) == 0 {
		zctx.Debug("no update")
		return nil
	}
	zctx.Debug("updating peer configuration")
	return p.wg.SetNewEndpoints(peerUpdates)
}

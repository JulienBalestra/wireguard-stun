package peerdns

import (
	"context"
	"errors"
	"net"
	"time"

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

	WireguardConfig *wireguard.Config
	StaticPeers     []string
	HandshakeAge    time.Duration
}

type PeerDNS struct {
	conf *Config

	wg          *wireguard.Wireguard
	dnsClient   *dns.Client
	staticPeers map[string]struct{}
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
	wg, err := wireguard.NewWireguardClient(conf.WireguardConfig)
	if err != nil {
		return nil, err
	}
	s := make(map[string]struct{})
	for _, elt := range conf.StaticPeers {
		s[elt] = struct{}{}
	}
	return &PeerDNS{
		conf: conf,
		wg:   wg,

		dnsClient: &dns.Client{
			Timeout: time.Second * 30,
		},
		staticPeers: s,
	}, nil
}

func (p *PeerDNS) Run(ctx context.Context) error {
	ticker := time.NewTicker(p.conf.ReconcileInterval)
	defer ticker.Stop()
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
	peers, err := p.wg.GetPeers()
	if err != nil {
		return err
	}

	peerUpdates := make(map[wgtypes.Key]net.UDPAddr)
	for _, peer := range peers {
		_, ok := p.staticPeers[peer.PublicKey.String()]
		if ok {
			continue
		}
		handshakeAge := time.Since(peer.LastHandshakeTime)
		srvQuery := peer.PublicKeyHash + p.conf.SRVRecordSuffix
		zctx := zap.L().With(
			zap.String("publicKey", peer.PublicKey.String()),
			zap.String("publicKeyHash", peer.PublicKeyHash),
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
		zap.L().Debug("no update")
		return nil
	}
	zap.L().Debug("updating peer configuration")
	return p.wg.SetNewEndpoints(peerUpdates)
}

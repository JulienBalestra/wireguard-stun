package wireguard

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"net"
	"time"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	DiscardIP   = "127.0.0.1"
	DiscardPort = 9 // IANA discard
)

type Config struct {
	DeviceName              string
	DiscardStalingEndpoints time.Duration
	DiscardGracePeriod      time.Duration
}

type Wireguard struct {
	conf *Config

	discardGracePeriod map[wgtypes.Key]time.Time
	discardEndpoint    *net.UDPAddr
}

type Peer struct {
	wgtypes.Peer

	PublicKeyHash string
}

func NewPeer(peer *wgtypes.Peer) *Peer {
	h := sha1.New()
	_, _ = h.Write(peer.PublicKey[:])
	hash := hex.EncodeToString(h.Sum(nil))[:7]
	return &Peer{
		Peer:          *peer,
		PublicKeyHash: hash,
	}
}

func NewWireguardClient(conf *Config) (*Wireguard, error) {
	if conf.DeviceName == "" {
		return nil, errors.New("must provide a DeviceName")
	}
	wgc, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wgc.Close()
	_, err = wgc.Device(conf.DeviceName)
	if err != nil {
		return nil, err
	}
	return &Wireguard{
		conf:               conf,
		discardGracePeriod: make(map[wgtypes.Key]time.Time),
		discardEndpoint: &net.UDPAddr{
			IP:   net.ParseIP(DiscardIP),
			Port: DiscardPort,
		},
	}, nil
}

func (w *Wireguard) GetPeers() ([]wgtypes.Peer, error) {
	zctx := zap.L().With(
		zap.String("device", w.conf.DeviceName),
	)
	wgc, err := wgctrl.New()
	if err != nil {
		zctx.Error("failed to create wireguard client", zap.Error(err))
		return nil, err
	}
	defer wgc.Close()

	device, err := wgc.Device(w.conf.DeviceName)
	if err != nil {
		zctx.Error("failed to get wireguard device", zap.Error(err))
		return nil, err
	}
	return device.Peers, nil
}

func (w *Wireguard) GetHashedPeers() ([]Peer, error) {
	wgPeers, err := w.GetPeers()
	if err != nil {
		return nil, err
	}
	var peers []Peer
	for _, p := range wgPeers {
		np := NewPeer(&p)
		pctx := zap.L().With(
			zap.String("publicKeyHash", np.PublicKeyHash),
			zap.String("publicKey", np.PublicKey.String()),
		)
		pctx.Debug("discovering peer", zap.String("endpoint", np.Endpoint.String()))
		peers = append(peers, *np)
	}
	return peers, nil
}

func (w *Wireguard) SetNewEndpoints(peerUpdates map[wgtypes.Key]net.UDPAddr) error {
	zctx := zap.L().With(
		zap.String("device", w.conf.DeviceName),
	)
	wgc, err := wgctrl.New()
	if err != nil {
		zctx.Error("failed to create wireguard client", zap.Error(err))
		return err
	}
	defer wgc.Close()
	device, err := wgc.Device(w.conf.DeviceName)
	if err != nil {
		zctx.Error("failed to get wireguard device", zap.Error(err))
		return err
	}

	var peerConfigs []wgtypes.PeerConfig
	for _, peer := range device.Peers {
		newEndpoint, ok := peerUpdates[peer.PublicKey]
		if !ok {
			continue
		}
		zctx.Info("setting peer endpoint",
			zap.String("endpoint", newEndpoint.String()),
			zap.String("publicKey", peer.PublicKey.String()),
		)
		cfg := wgtypes.PeerConfig{
			PublicKey:                   peer.PublicKey,
			UpdateOnly:                  false,
			PresharedKey:                &peer.PresharedKey,
			Endpoint:                    &newEndpoint,
			PersistentKeepaliveInterval: &peer.PersistentKeepaliveInterval,
			ReplaceAllowedIPs:           false,
			AllowedIPs:                  peer.AllowedIPs,
		}
		delete(peerUpdates, peer.PublicKey)
		peerConfigs = append(peerConfigs, cfg)
	}
	if len(peerUpdates) != 0 {
		err := errors.New("failed to update peer endpoints")
		for publicKey := range peerUpdates {
			zctx.Error("failed to find peer", zap.Error(err), zap.String("publicKey", publicKey.String()))
		}
		return err
	}
	err = wgc.ConfigureDevice(w.conf.DeviceName, wgtypes.Config{
		PrivateKey:   &device.PrivateKey,
		ListenPort:   &device.ListenPort,
		FirewallMark: &device.FirewallMark,
		ReplacePeers: false,
		Peers:        peerConfigs,
	})
	return err
}

func (w *Wireguard) DiscardStalingEndpoints() error {
	if w.conf.DiscardGracePeriod == 0 {
		return nil
	}
	zctx := zap.L().With(
		zap.String("device", w.conf.DeviceName),
	)
	wgc, err := wgctrl.New()
	if err != nil {
		zctx.Error("failed to create wireguard client", zap.Error(err))
		return err
	}
	defer wgc.Close()
	device, err := wgc.Device(w.conf.DeviceName)
	if err != nil {
		zctx.Error("failed to get wireguard device", zap.Error(err))
		return err
	}

	var peerConfigs []wgtypes.PeerConfig
	for _, p := range device.Peers {
		if p.Endpoint == nil {
			delete(w.discardGracePeriod, p.PublicKey)
			continue
		}
		if p.Endpoint.String() == w.discardEndpoint.String() {
			delete(w.discardGracePeriod, p.PublicKey)
			continue
		}
		if time.Since(p.LastHandshakeTime) < w.conf.DiscardStalingEndpoints {
			delete(w.discardGracePeriod, p.PublicKey)
			continue
		}
		gc, ok := w.discardGracePeriod[p.PublicKey]
		if !ok {
			w.discardGracePeriod[p.PublicKey] = time.Now()
			zctx.Info("endpoint candidate for discard",
				zap.String("publicKey", p.PublicKey.String()),
				zap.String("endpoint", p.Endpoint.String()),
			)
			continue
		}
		if time.Since(gc) < w.conf.DiscardGracePeriod {
			zctx.Info("endpoint candidate for discard under grace period",
				zap.String("publicKey", p.PublicKey.String()),
				zap.String("endpoint", p.Endpoint.String()),
			)
			continue
		}

		zctx.Info("endpoint marked for discard",
			zap.String("publicKey", p.PublicKey.String()),
			zap.String("endpoint", p.Endpoint.String()),
		)
		cfg := wgtypes.PeerConfig{
			PublicKey:                   p.PublicKey,
			UpdateOnly:                  false,
			PresharedKey:                &p.PresharedKey,
			Endpoint:                    w.discardEndpoint,
			PersistentKeepaliveInterval: &p.PersistentKeepaliveInterval,
			ReplaceAllowedIPs:           false,
			AllowedIPs:                  p.AllowedIPs,
		}
		peerConfigs = append(peerConfigs, cfg)
		delete(w.discardGracePeriod, p.PublicKey)
	}
	for k, t := range w.discardGracePeriod {
		if time.Since(t) > w.conf.DiscardGracePeriod {
			delete(w.discardGracePeriod, k)
		}
	}
	if len(peerConfigs) == 0 {
		zap.L().Info("no peer endpoint to discard yet", zap.Int("candidates", len(w.discardGracePeriod)))
		return nil
	}
	return wgc.ConfigureDevice(w.conf.DeviceName, wgtypes.Config{
		PrivateKey:   &device.PrivateKey,
		ListenPort:   &device.ListenPort,
		FirewallMark: &device.FirewallMark,
		ReplacePeers: false,
		Peers:        peerConfigs,
	})
}

func GetDevicePublicKey(device string) string {
	wgc, err := wgctrl.New()
	if err != nil {
		return ""
	}
	defer wgc.Close()
	d, err := wgc.Device(device)
	if err != nil {
		return ""
	}
	return d.PublicKey.String()
}

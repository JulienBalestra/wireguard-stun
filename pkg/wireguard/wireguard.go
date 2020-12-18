package wireguard

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"net"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Config struct {
	DeviceName string
}

type Wireguard struct {
	conf *Config
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
		conf: conf,
	}, nil
}

func (w *Wireguard) GetPeers() ([]Peer, error) {
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
	var peers []Peer
	for _, p := range device.Peers {
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
		zctx.Info("setting peer endpoint")
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

package wireguard

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
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

func (w *Wireguard) GetIndexedPeers() (map[wgtypes.Key]wgtypes.Peer, error) {
	peers, err := w.GetPeers()
	if err != nil {
		return nil, err
	}
	currentPeers := make(map[wgtypes.Key]wgtypes.Peer, len(peers))
	for _, p := range peers {
		currentPeers[p.PublicKey] = p
	}
	return currentPeers, nil
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

func ParseEndpoint(s string) (*net.UDPAddr, error) {
	u := net.UDPAddr{}
	i := strings.Index(s, ":")
	if i == -1 {
		return nil, errors.New("invalid endpoint: " + s)
	}
	if i+1 > len(s) {
		return nil, errors.New("invalid endpoint: " + s)
	}
	u.IP = net.ParseIP(s[:i])
	if u.IP == nil {
		return nil, errors.New("invalid ip endpoint: " + s)
	}
	p, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return nil, err
	}
	u.Port = p
	return &u, nil
}

type DeviceConfiguration struct {
	Peers []wgtypes.Peer
}

func ParseStaticConfiguration(device string) (*DeviceConfiguration, error) {
	const basePath = "/etc/wireguard/"
	const extension = ".conf"

	file, err := os.Open(path.Join(basePath, device+extension))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	sc := &DeviceConfiguration{}
	var sp *wgtypes.Peer = nil
	scanner := bufio.NewScanner(file)
	for {
		if !scanner.Scan() {
			if sp != nil && sp.PublicKey.String() != "" {
				sc.Peers = append(sc.Peers, *sp)
			}
			break
		}
		line := scanner.Text()
		if line == "[Peer]" {
			if sp != nil && sp.PublicKey.String() != "" {
				sc.Peers = append(sc.Peers, *sp)
			}
			sp = &wgtypes.Peer{}
			continue
		}
		if sp == nil {
			continue
		}
		if strings.HasPrefix(line, "PublicKey") {
			// "PublicKey="
			s := line[9+1:]
			s = strings.Trim(s, " ")
			s = strings.TrimLeft(s, " =")
			sp.PublicKey, err = wgtypes.ParseKey(s)
			if err != nil {
				return nil, err
			}
			continue
		}
		if strings.HasPrefix(line, "PresharedKey") {
			// "PresharedKey="
			s := line[12+1:]
			s = strings.Trim(s, " ")
			s = strings.TrimLeft(s, " =")
			sp.PresharedKey, err = wgtypes.ParseKey(s)
			if err != nil {
				return nil, err
			}
			continue
		}
		if strings.HasPrefix(line, "PersistentKeepalive") {
			// "PersistentKeepalive="
			s := line[19+1:]
			s = strings.Trim(s, " =")
			sp.PersistentKeepaliveInterval, err = time.ParseDuration(s + "s")
			if err != nil {
				return nil, err
			}
			continue
		}
		if strings.HasPrefix(line, "AllowedIPs") {
			// "AllowedIPs="
			s := line[10+1:]
			s = strings.Trim(s, " =")
			for _, elt := range strings.Split(s, ",") {
				elt = strings.Trim(elt, " ")
				_, i, err := net.ParseCIDR(elt)
				if err != nil {
					return nil, err
				}
				sp.AllowedIPs = append(sp.AllowedIPs, *i)
			}
			continue
		}
		if strings.HasPrefix(line, "Endpoint") {
			// "Endpoint="
			s := line[8+1:]
			s = strings.Trim(s, " =")
			sp.Endpoint, err = ParseEndpoint(s)
			if err != nil {
				return nil, err
			}
			continue
		}
	}
	return sc, nil
}

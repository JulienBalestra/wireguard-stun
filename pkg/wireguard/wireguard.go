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

type Config struct {
	DeviceName string
}

type Wireguard struct {
	conf *Config
}

type PeerSHA struct {
	wgtypes.Peer

	PublicKeyShortSha1 string
	PublicKeySha1      string
}

func NewPeer(peer *wgtypes.Peer) *PeerSHA {
	h := sha1.New()
	_, _ = h.Write(peer.PublicKey[:])
	hash := hex.EncodeToString(h.Sum(nil))
	return &PeerSHA{
		Peer:               *peer,
		PublicKeyShortSha1: hash[:7],
		PublicKeySha1:      hash,
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

func (w *Wireguard) GetHashedPeers() ([]PeerSHA, error) {
	wgPeers, err := w.GetPeers()
	if err != nil {
		return nil, err
	}
	var peers []PeerSHA
	for _, p := range wgPeers {
		np := NewPeer(&p)
		pctx := zap.L().With(
			zap.String("publicKeyHash", np.PublicKeyShortSha1),
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

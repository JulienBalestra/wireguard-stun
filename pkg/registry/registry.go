package registry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/JulienBalestra/dry/pkg/ticknow"

	r53Client "github.com/JulienBalestra/wireguard-stun/pkg/registry/route53"
	"github.com/JulienBalestra/wireguard-stun/pkg/wireguard"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/route53"
	"go.uber.org/zap"
)

type Config struct {
	WireguardConfig *wireguard.Config
	Route53Config   *r53Client.Config

	ReconcileInterval time.Duration
}

type Registry struct {
	conf *Config

	wg  *wireguard.Wireguard
	r53 *r53Client.Route53

	mu            sync.RWMutex
	peers         []wireguard.Peer
	srvRecordSets map[string]*route53.ResourceRecordSet
	aRecordSets   map[string]*route53.ResourceRecordSet
}

func NewRegistry(conf *Config) (*Registry, error) {
	wg, err := wireguard.NewWireguardClient(conf.WireguardConfig)
	if err != nil {
		return nil, err
	}
	r53, err := r53Client.New(conf.Route53Config)
	if err != nil {
		return nil, err
	}

	return &Registry{
		conf: conf,
		wg:   wg,
		r53:  r53,
	}, nil
}

type peerRecord struct {
	name       string
	recordType string
	value      string
	toDelete   bool
	peer       *wireguard.Peer
}

type peerRecords struct {
	srv *peerRecord
	a   *peerRecord
}

func (r *Registry) processRecordChange(upserts, deletes []*route53.Change, recordSets map[string]*route53.ResourceRecordSet, peerRecord *peerRecord) ([]*route53.Change, []*route53.Change) {
	zctx := zap.L().With(
		zap.String("name", peerRecord.name),
		zap.String("type", peerRecord.recordType),
		zap.String("value", peerRecord.value),
		zap.String("publicKey", peerRecord.peer.PublicKey.String()),
	)
	record, ok := recordSets[peerRecord.name]
	if !ok && peerRecord.toDelete {
		zctx.Debug("record already deleted")
		return upserts, deletes
	}
	if !ok {
		zctx.Info("record creation")
		return append(upserts, &route53.Change{
			Action: aws.String(route53.ChangeActionCreate),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: &peerRecord.name,
				Type: &peerRecord.recordType,
				TTL:  aws.Int64(r.conf.Route53Config.TTL),
				ResourceRecords: []*route53.ResourceRecord{
					{
						Value: &peerRecord.value,
					},
				},
			},
		}), deletes
	}
	if peerRecord.toDelete {
		zctx.Info("record deletion")
		return upserts, append(deletes, &route53.Change{
			Action: aws.String(route53.ChangeActionDelete),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name:            &peerRecord.name,
				Type:            &peerRecord.recordType,
				TTL:             record.TTL,
				ResourceRecords: record.ResourceRecords,
			},
		})
	}
	potentialChange := &route53.Change{
		Action: aws.String(route53.ChangeActionUpsert),
		ResourceRecordSet: &route53.ResourceRecordSet{
			Name: &peerRecord.name,
			Type: &peerRecord.recordType,
			TTL:  &r.conf.Route53Config.TTL,
			ResourceRecords: []*route53.ResourceRecord{
				{
					Value: &peerRecord.value,
				},
			},
		},
	}
	zctx.Debug("existing record")
	if len(record.ResourceRecords) != len(potentialChange.ResourceRecordSet.ResourceRecords) {
		zctx.Info("change in resources")
		return append(upserts, potentialChange), deletes
	}
	if *record.ResourceRecords[0].Value != *potentialChange.ResourceRecordSet.ResourceRecords[0].Value {
		zctx.Info("change in resource value", zap.String("currentValue", *record.ResourceRecords[0].Value))
		return append(upserts, potentialChange), deletes
	}
	if *record.Type != *potentialChange.ResourceRecordSet.Type {
		zctx.Info("change record type", zap.String("currentType", *record.Type))
		return append(upserts, potentialChange), deletes
	}
	if *record.TTL != *potentialChange.ResourceRecordSet.TTL {
		return append(upserts, potentialChange), deletes
	}
	zctx.Debug("uptodate record", zap.String("name", peerRecord.name))
	return upserts, deletes
}

func (r *Registry) newPeerRecords(peer *wireguard.Peer) *peerRecords {
	toDelete := time.Since(peer.LastHandshakeTime) > time.Minute*3+time.Second*30
	prs := &peerRecords{
		srv: &peerRecord{
			name:       peer.PublicKeyHash + r.conf.Route53Config.SRVRecordSuffix,
			recordType: route53.RRTypeSrv,
			toDelete:   toDelete,
			peer:       peer,
		},
		a: &peerRecord{
			name:       peer.PublicKeyHash + r.conf.Route53Config.ARecordSuffix,
			recordType: route53.RRTypeA,
			toDelete:   toDelete,
			peer:       peer,
		},
	}
	zap.L().Debug("building peer record specs",
		zap.Duration("sinceLastHandshake", time.Since(peer.LastHandshakeTime)),
		zap.String("publicKey", peer.PublicKey.String()),
		zap.String("publicKeyHash", peer.PublicKeyHash),
	)
	if toDelete {
		return prs
	}
	prs.a.value = peer.Endpoint.IP.String()
	prs.srv.value = fmt.Sprintf("0 0 %d %s", peer.Endpoint.Port, prs.a.name)
	return prs
}

func (r *Registry) updateCachedRecords(ctx context.Context) error {
	srvRecordSets, aRecordSets, err := r.r53.GetRecords(ctx)
	if err != nil {
		zap.L().Error("failed to get record sets", zap.Error(err))
		return err
	}
	r.mu.Lock()
	r.srvRecordSets = srvRecordSets
	r.aRecordSets = aRecordSets
	r.mu.Unlock()
	return nil
}

func (r *Registry) updateCachedPeers() error {
	peers, err := r.wg.GetPeers()
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.peers = peers
	r.mu.Unlock()
	return nil
}

func (r *Registry) Run(ctx context.Context) error {
	wgTicker := ticknow.NewTickNow(ctx, time.Second*3)
	r53Ticker := ticknow.NewTickNow(ctx, r.conf.ReconcileInterval)

	skipReconcile := true
	for {
		select {
		case <-ctx.Done():
			return nil

		case <-wgTicker.C:
			err := r.updateCachedPeers()
			if err != nil {
				continue
			}
			if skipReconcile {
				continue
			}
			err = r.Reconcile(ctx)
			if err != nil {
				zap.L().Error("failed to reconcile", zap.Error(err))
			}
			skipReconcile = err != nil

		case <-r53Ticker.C:
			err := r.updateCachedRecords(ctx)
			if err != nil {
				continue
			}
			err = r.Reconcile(ctx)
			if err != nil {
				zap.L().Error("failed to reconcile", zap.Error(err))
			}
			skipReconcile = err != nil
		}
	}
}

func (r *Registry) Reconcile(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var upserts []*route53.Change
	var deletes []*route53.Change
	for _, peer := range r.peers {
		if peer.Endpoint == nil {
			continue
		}
		prs := r.newPeerRecords(&peer)
		upserts, deletes = r.processRecordChange(
			upserts,
			deletes,
			r.srvRecordSets,
			prs.srv,
		)
		upserts, deletes = r.processRecordChange(
			upserts,
			deletes,
			r.aRecordSets,
			prs.a,
		)
	}
	if len(upserts) == 0 && len(deletes) == 0 {
		return nil
	}
	err := r.r53.ExecuteChanges(ctx, append(upserts, deletes...))
	if err != nil {
		return err
	}
	for _, deletion := range deletes {
		delete(r.srvRecordSets, *deletion.ResourceRecordSet.Name)
		delete(r.aRecordSets, *deletion.ResourceRecordSet.Name)
	}
	for _, upsert := range upserts {
		r.srvRecordSets[*upsert.ResourceRecordSet.Name] = upsert.ResourceRecordSet
		r.aRecordSets[*upsert.ResourceRecordSet.Name] = upsert.ResourceRecordSet
	}
	return nil
}

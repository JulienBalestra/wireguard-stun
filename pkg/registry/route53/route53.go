package route53

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	"go.uber.org/zap"
)

type Config struct {
	SRVRecordSuffix string
	ARecordSuffix   string
	ZoneID          string
	TTL             int64
}

type Route53 struct {
	conf *Config

	awsConfig *aws.Config
	zoneID    *string

	rc *route53.Route53
}

func New(conf *Config) (*Route53, error) {
	if conf.SRVRecordSuffix == "" {
		return nil, errors.New("must provide a SRVRecordSuffix")
	}
	if conf.ARecordSuffix == "" {
		return nil, errors.New("must provide a ARecordSuffix")
	}
	if conf.ZoneID == "" {
		return nil, errors.New("must provide a ZoneID")
	}

	awsConfig := aws.NewConfig()
	awsConfig.CredentialsChainVerboseErrors = aws.Bool(true)

	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, err
	}
	return &Route53{
		conf:      conf,
		awsConfig: awsConfig,

		zoneID: aws.String(conf.ZoneID),
		rc:     route53.New(sess),
	}, nil
}

func (r *Route53) GetRecords(ctx aws.Context) (map[string]*route53.ResourceRecordSet, map[string]*route53.ResourceRecordSet, error) {
	zctx := zap.L().With(
		zap.String("srvRecordSuffix", r.conf.SRVRecordSuffix),
		zap.String("aRecordSuffix", r.conf.ARecordSuffix),
	)
	zctx.Info("listing resource record sets")
	records, err := r.rc.ListResourceRecordSetsWithContext(
		ctx,
		&route53.ListResourceRecordSetsInput{
			HostedZoneId: r.zoneID,
		},
	)
	if err != nil {
		zctx.Error("failed to list resource record sets", zap.Error(err))
		return nil, nil, err
	}
	peerSRVRecords := make(map[string]*route53.ResourceRecordSet)
	peerARecords := make(map[string]*route53.ResourceRecordSet)
	for _, elt := range records.ResourceRecordSets {
		rctx := zctx.With(
			zap.String("name", *elt.Name),
			zap.String("type", *elt.Type),
		)
		if *elt.Type == route53.RRTypeSrv {
			if !strings.HasSuffix(*elt.Name, r.conf.SRVRecordSuffix) {
				rctx.Debug("skipping record")
				continue
			}
			rctx.Debug("found SRV record matching prefix")
			peerSRVRecords[*elt.Name] = elt
			continue
		}
		if *elt.Type != route53.RRTypeA {
			rctx.Debug("skipping record")
			continue
		}
		if !strings.HasSuffix(*elt.Name, r.conf.ARecordSuffix) {
			rctx.Debug("skipping record")
			continue
		}
		rctx.Debug("found A record matching prefix")
		peerARecords[*elt.Name] = elt
	}
	return peerSRVRecords, peerARecords, nil
}

func (r *Route53) ExecuteChanges(ctx context.Context, changes []*route53.Change) error {
	zap.L().Info("changing resource record sets")
	_, err := r.rc.ChangeResourceRecordSetsWithContext(
		ctx,
		&route53.ChangeResourceRecordSetsInput{
			ChangeBatch: &route53.ChangeBatch{
				Changes: changes,
			},
			HostedZoneId: r.zoneID,
		},
	)
	return err
}

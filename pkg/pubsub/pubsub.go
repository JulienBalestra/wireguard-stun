package pubsub

import "time"

const (
	SubAPIPath = "/sub"
	PubAPIPath = "/pub"

	SubscriptionTTL   = time.Minute * 3
	SubscriptionRenew = time.Minute
)

type PubSub struct {
	URL       string        `json:"url"`
	PublicKey string        `json:"publicKey"`
	TTL       time.Duration `json:"ttl"`
}

type Updates map[string]string

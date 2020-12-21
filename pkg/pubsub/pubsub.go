package pubsub

import "time"

const (
	SubAPIPath = "/sub"
	PubAPIPath = "/pub"

	SubscriptionTTL   = time.Minute * 30
	SubscriptionRenew = SubscriptionTTL - (time.Second - 10)
)

type PubSub struct {
	URL       string `json:"url"`
	PublicKey string `json:"publicKey"`
}

type Updates map[string]string

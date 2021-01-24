package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

func InitEtcdConnectionState(c *prometheus.CounterVec, conn *grpc.ClientConn) {
	target := conn.Target()
	c.WithLabelValues(connectivity.Idle.String(), target).Add(0)
	c.WithLabelValues(connectivity.Connecting.String(), target).Add(0)
	c.WithLabelValues(connectivity.Ready.String(), target).Add(0)
	c.WithLabelValues(connectivity.TransientFailure.String(), target).Add(0)
	c.WithLabelValues(connectivity.Shutdown.String(), target).Add(0)
}

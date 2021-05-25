package main

import "github.com/prometheus/client_golang/prometheus"

var (
	enableMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "enable_requests",
			Help: "number of times something was enabled",
		},
		[]string{"service"},
	)
	disableMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "disable_requests",
			Help: "number of times something was enabled",
		},
		[]string{"service"},
	)
)

func init() {
	prometheus.MustRegister(enableMetric, disableMetric)
}

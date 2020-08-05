package main

import (
	"context"
	"flag"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ribbybibby/kube-container-security-operator/adapter/trivy"
	"github.com/ribbybibby/kube-container-security-operator/scanner"
	"log"
	"net/http"
	"time"
)

var (
	namespace       = flag.String("namespace", "", "Restrict operation to a specific namespace")
	trivyClient     = flag.Bool("trivy-client", true, "Run trivy in client mode")
	resyncPeriod    = flag.Duration("resync-period", 10*time.Minute, "Resync period")
	rescanThreshold = flag.Duration("rescan-theshold", 60*time.Minute, "The amount of time before scanning an image again")
	metricsAddress  = flag.String("metrics-address", ":8080", "The address to serve metrics on")
)

func main() {
	flag.Parse()

	s, err := scanner.New(
		*namespace,
		&trivy.Client{
			Client: *trivyClient,
		},
		*rescanThreshold,
		*resyncPeriod,
	)
	if err != nil {
		log.Fatalln(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx.Done())

	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(*metricsAddress, nil); err != http.ErrServerClosed {
		log.Println("Failed while serving prometheus: " + err.Error())
	}

	cancel()
}

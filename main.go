package main

import (
	"context"
	"flag"
	"github.com/ribbybibby/kube-container-security-operator/adapter/trivy"
	"github.com/ribbybibby/kube-container-security-operator/scanner"
	"log"
)

var (
	namespace   = flag.String("namespace", "", "Restrict operation to a specific namespace")
	trivyClient = flag.Bool("trivy.client", true, "Run trivy in client mode")
)

func main() {
	flag.Parse()

	s, err := scanner.New(*namespace, &trivy.Client{
		Client: *trivyClient,
	})
	if err != nil {
		log.Fatalln(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.Run(ctx.Done())

	cancel()
}

package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"time"
)

var (
	PromVulnerabilities = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "scanner_cluster_vulnerabilities",
			Help: "Total number of unique vulnerabilities in the cluster by severity",
		},
		[]string{
			"severity",
		},
	)

	PromVulnerableImages = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "scanner_cluster_vulnerable_images",
			Help: "Total number of unique vulnerable images running by severity",
		},
		[]string{
			"severity",
		},
	)

	PromVulnerabilityReports = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "scanner_vulnerabilityreports",
			Help: "Total number of vulnerability reports by namespace and highest severity",
		},
		[]string{
			"namespace",
			"severity",
		},
	)

	PromScans = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scanner_scans",
			Help: "Total number of scans performed, by namespace",
		},
		[]string{
			"namespace",
		},
	)

	PromScanDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "scanner_scan_duration_seconds",
			Help: "Time it takes to scan an image, in seconds",
		},
	)
)

func ObserveScanDuration() func() {
	start := time.Now()
	return func() {
		PromScanDurationSeconds.Observe(time.Since(start).Seconds())
	}
}

func init() {
	metrics.Registry.MustRegister(
		PromVulnerabilities,
		PromVulnerableImages,
		PromVulnerabilityReports,
		PromScans,
		PromScanDurationSeconds,
	)
}

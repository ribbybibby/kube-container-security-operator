package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"
	"log"
	"time"
)

var (
	PromVulnerabilities = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "scanner_cluster_vulnerabilities",
			Help: "Total number of unique vulnerabilities in the cluster, labeled by severity",
		},
		[]string{
			"severity",
		},
	)

	PromVulnerableImages = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "scanner_cluster_vulnerable_images",
			Help: "Total number of unique vulnerable images running",
		},
		[]string{
			"severity",
		},
	)

	PromPodEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scanner_pod_events_total",
			Help: "Total number of pod events, per namespace",
		},
		[]string{
			"event",
			"namespace",
		},
	)

	PromVulnerabilityReportEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scanner_vulnerability_report_events_total",
			Help: "Total number of VulnerabilityReport events, per namespace",
		},
		[]string{
			"event",
			"namespace",
		},
	)

	PromVulnerabilityReports = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "scanner_vulnerability_reports",
			Help: "Total number of vulnerability reports by namespace and highest severity",
		},
		[]string{
			"namespace",
			"severity",
		},
	)

	PromScansTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scanner_scans_total",
			Help: "Total number of scans performed, by namespace",
		},
		[]string{
			"namespace",
		},
	)

	PromQueueSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "scanner_queue_size",
			Help: "Number of items in the scanner's queue to process",
		},
	)

	PromReconciliationDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "scanner_reconciliation_duration_seconds",
			Help: "Time it takes for the operator's reconciliation, in seconds",
		},
	)

	PromScanDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "scanner_scan_duration_seconds",
			Help: "Time it takes to scan an image, in seconds",
		},
	)
)

func ObserveReconciliationDuration() func() {
	start := time.Now()
	return func() {
		PromReconciliationDurationSeconds.Observe(time.Since(start).Seconds())
	}
}

func ObserveScanDuration() func() {
	start := time.Now()
	return func() {
		PromScanDurationSeconds.Observe(time.Since(start).Seconds())
	}
}

func init() {
	prometheus.MustRegister(PromVulnerabilities)
	prometheus.MustRegister(PromVulnerableImages)
	prometheus.MustRegister(PromPodEventsTotal)
	prometheus.MustRegister(PromVulnerabilityReportEventsTotal)
	prometheus.MustRegister(PromVulnerabilityReports)
	prometheus.MustRegister(PromQueueSize)
	prometheus.MustRegister(PromScansTotal)
	prometheus.MustRegister(PromScanDurationSeconds)
	prometheus.MustRegister(PromReconciliationDurationSeconds)

	log.Println("Registered prometheus metrics")
}

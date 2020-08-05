package scanner

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ribbybibby/kube-container-security-operator/adapter"
	secscanv1alpha1 "github.com/ribbybibby/kube-container-security-operator/apis/secscan/v1alpha1"
	"github.com/ribbybibby/kube-container-security-operator/generated/versioned"
	"github.com/ribbybibby/kube-container-security-operator/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"
	"log"
	"strings"
	"time"
	// support any type of auth in kubeconfig
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

var (
	errPodNotRunningOrReady = fmt.Errorf("Pod not running or ready")
)

// Scanner performs vulnerability scans on pods in a Kubernetes cluster and
// saves the results as a VulnerabilityReport resource
type Scanner struct {
	kubeClient      kubernetes.Interface
	podInformer     cache.SharedIndexInformer
	vulnInformer    cache.SharedIndexInformer
	vulnClient      versioned.Interface
	queue           workqueue.RateLimitingInterface
	ns              string
	scanAdapter     adapter.Interface
	rescanThreshold time.Duration
	resyncPeriod    time.Duration
}

// New returns a new Scanner
func New(ns string, scanAdapter adapter.Interface, rescanThreshold, resyncPeriod time.Duration) (*Scanner, error) {
	// Kubernetes config
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	)
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, err
	}

	// Kubernetes clients
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	vulnClientSet, err := versioned.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	// Scanner
	scanner := &Scanner{
		kubeClient:      clientset,
		vulnClient:      vulnClientSet,
		ns:              ns,
		scanAdapter:     scanAdapter,
		rescanThreshold: rescanThreshold,
		resyncPeriod:    resyncPeriod,
	}
	scanner.queue = workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "scanner")

	// Pod informer
	podListWatcher := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return scanner.kubeClient.CoreV1().Pods(ns).List(context.Background(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return scanner.kubeClient.CoreV1().Pods(ns).Watch(context.Background(), options)
		},
	}
	scanner.podInformer = cache.NewSharedIndexInformer(
		podListWatcher,
		&corev1.Pod{},
		resyncPeriod,
		cache.Indexers{},
	)
	scanner.podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    scanner.handleAddPod,
		DeleteFunc: scanner.handleDeletePod,
		UpdateFunc: scanner.handleUpdatePod,
	})

	// VulnerabilityReport informer
	vulnListWatcher := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return scanner.vulnClient.SecscanV1alpha1().VulnerabilityReports(ns).List(context.Background(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return scanner.vulnClient.SecscanV1alpha1().VulnerabilityReports(ns).Watch(context.Background(), options)
		},
	}
	scanner.vulnInformer = cache.NewSharedIndexInformer(
		vulnListWatcher,
		&secscanv1alpha1.VulnerabilityReport{},
		resyncPeriod,
		cache.Indexers{},
	)
	scanner.vulnInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    scanner.handleAddVulnerabilityReport,
		DeleteFunc: scanner.handleDeleteVulnerabilityReport,
		UpdateFunc: scanner.handleUpdateVulnerabilityReport,
	})

	return scanner, nil
}

// Run runs the scanner
func (s *Scanner) Run(stop <-chan struct{}) error {
	defer s.queue.ShutDown()

	go s.podInformer.Run(stop)
	go s.vulnInformer.Run(stop)

	// Wait for the cache to sync with kube before starting the worker
	if err := s.waitForCacheSync(stop); err != nil {
		return err
	}
	go s.worker()

	<-stop
	log.Println("Stopping scanner...")

	return nil
}

func (s *Scanner) worker() {
	for s.processNextItem() {
	}
}

func (s *Scanner) processNextItem() bool {
	prometheus.PromQueueSize.Set(float64(s.queue.Len()))

	key, quit := s.queue.Get()
	if quit {
		return false
	}
	defer s.queue.Done(key)

	err := s.Reconcile(key.(string))
	if err == nil {
		s.queue.Forget(key)
		return true
	}

	// Don't print running/not ready errors. They're an expected part of
	// pods starting and stopping
	if err != errPodNotRunningOrReady {
		log.Println(err)
		log.Println("Requeued item", key)

	}

	s.queue.AddRateLimited(key)

	return true
}

func (s *Scanner) handleAddVulnerabilityReport(obj interface{}) {
	s.updateMetrics()
}

func (s *Scanner) handleDeleteVulnerabilityReport(obj interface{}) {
	s.updateMetrics()
}

func (s *Scanner) handleUpdateVulnerabilityReport(oldObj, newObj interface{}) {
	s.updateMetrics()
}

func (s *Scanner) handleAddPod(obj interface{}) {
	pod := obj.(*corev1.Pod)

	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(pod)
	if err != nil {
		log.Println(err)
		return
	}

	prometheus.PromPodEventsTotal.WithLabelValues("add", pod.Namespace).Inc()
	s.queue.Add(key)
}

func (s *Scanner) handleDeletePod(obj interface{}) {
	pod := obj.(*corev1.Pod)

	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(pod)
	if err != nil {
		log.Println(err)
		return
	}

	prometheus.PromPodEventsTotal.WithLabelValues("delete", pod.Namespace).Inc()
	s.queue.Add(key)
}

func (s *Scanner) handleUpdatePod(oldObj, newObj interface{}) {
	pod := newObj.(*corev1.Pod)

	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(pod)
	if err != nil {
		log.Println(err)
		return
	}

	prometheus.PromPodEventsTotal.WithLabelValues("update", pod.Namespace).Inc()
	s.queue.Add(key)
}

func (s *Scanner) waitForCacheSync(stopc <-chan struct{}) error {
	ok := true
	informers := []struct {
		name     string
		informer cache.SharedIndexInformer
	}{
		{"Pod", s.podInformer},
		{"VulnerabilityReport", s.vulnInformer},
	}
	for _, inf := range informers {
		if !cache.WaitForCacheSync(stopc, inf.informer.HasSynced) {
			log.Printf("Failed to sync %s cache", inf.name)
			ok = false
		} else {
			log.Printf("Successfully synced %s cache", inf.name)
		}
	}
	if !ok {
		return errors.New("Failed to sync caches")
	}
	log.Println("Successfully synced all caches")
	return nil
}

func (s *Scanner) Reconcile(key string) error {
	defer prometheus.ObserveReconciliationDuration()()

	keyParts := strings.Split(key, "/")

	ns := keyParts[0]
	podName := keyParts[1]

	vulnReportClient := s.vulnClient.SecscanV1alpha1().VulnerabilityReports(ns)
	podClient := s.kubeClient.CoreV1().Pods(ns)

	defer func() {
		// Garbage collect reports with no pods and remove dangling
		// pods from existing manifests
		if err := garbageCollectVulnerabilityReports(podClient, vulnReportClient); err != nil {
			log.Printf("Failed to garbage collect reports in %s", ns)
		}
	}()

	// Check if the pod exists
	obj, exists, err := s.podInformer.GetIndexer().GetByKey(key)
	if err != nil {
		return err
	}
	if !exists {
		// Remove the pod from the status of any reports it appears in
		vulnReportList, err := vulnReportClient.List(context.Background(), metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("Failed to list VulnerabilityReport: %w", err)
		}
		for _, vulnReport := range vulnReportList.Items {
			if vulnReport.RemovePod(podName) {
				_, err := vulnReportClient.Update(context.Background(), &vulnReport, metav1.UpdateOptions{})
				if err != nil {
					return fmt.Errorf("Failed to update VulnerabilityReport: %w", err)
				}
				log.Printf("Updated VulnerabilityReport: %s/%s", vulnReport.Namespace, vulnReport.Name)
			}
		}

		return nil
	}

	pod := obj.(*corev1.Pod)

	// Only operate on running and ready pods
	running := false
	ready := false
	if pod.Status.Phase == corev1.PodRunning {
		running = true
		for _, cond := range pod.Status.Conditions {
			if cond.Type == corev1.PodReady {
				ready = cond.Status == corev1.ConditionTrue
			}
		}
	}
	if !running || !ready {
		return errPodNotRunningOrReady
	}

	// Scan pod containers
	for _, containerStatus := range pod.Status.ContainerStatuses {
		img := containerStatus.Image

		var vulnReport *secscanv1alpha1.VulnerabilityReport

		// Parse the image into a registry and artifact
		registry, artifact, err := parseImage(containerStatus)
		if err != nil {
			return fmt.Errorf("Failed to parse reference: %w", err)
		}

		// The unique name of a vulnReport is a SHA1 of the registry +
		// repository + tag + digest
		h := sha1.New()
		h.Write([]byte(registry.URL + artifact.Repository + artifact.Digest + artifact.Tag))
		vulnReportName := hex.EncodeToString(h.Sum(nil))

		// Find an existing report, if there is one
		vulnReportKey := fmt.Sprintf("%s/%s", pod.Namespace, vulnReportName)
		obj, exists, err := s.vulnInformer.GetIndexer().GetByKey(vulnReportKey)
		if err != nil {
			continue
		}

		// Controls whether the image is scanned or not
		scan := false

		// If a vulnerability report doesn't already exist for this
		// image then create it
		if !exists {
			// Define the report
			vulnReport = &secscanv1alpha1.VulnerabilityReport{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      make(map[string]string),
					Annotations: make(map[string]string),
					Name:        vulnReportName,
					Namespace:   ns,
				},
				Spec: secscanv1alpha1.VulnerabilityReportSpec{
					Artifact: *artifact,
					Registry: *registry,
				},
			}
			scan = true
		} else {
			vulnReport = obj.(*secscanv1alpha1.VulnerabilityReport)

			// Rescan the image if it's been at least rescanTheshold
			// amount of time since the last update
			lastUpdateTime, err := time.Parse("2006-01-02 15:04:05 -0700 MST", vulnReport.Status.LastUpdate)
			if err != nil {
				log.Printf("Error parsing VulnerabilityReport's lastUpdate for %s: %s", vulnReportKey, err)
			}
			if time.Now().UTC().Sub(lastUpdateTime) > s.rescanThreshold || err != nil {
				log.Printf("Scheduled rescan for: %s", vulnReportKey)
				scan = true
			}
		}

		if scan {
			scanImage := strings.Split(containerStatus.ImageID, "://")[1]

			prometheus.PromScansTotal.WithLabelValues(ns).Inc()
			log.Printf("Scanning: %s", scanImage)
			vulnerabilities, err := s.scan(scanImage)
			if err != nil {
				log.Printf("Error scanning image %s: %s", scanImage, err)
				return err
			}
			log.Printf("Scan finished for: %s", scanImage)

			vulnReport.Spec.Vulnerabilities = vulnerabilities
			vulnReport.Status.LastUpdate = time.Now().UTC().String()
		}

		// Add/update the pod on the status
		changed := vulnReport.AddPod(podName, img)

		// Create/Update the report
		if !exists {
			// Create report
			_, err = vulnReportClient.Create(context.Background(), vulnReport, metav1.CreateOptions{})
			if err != nil {
				log.Printf("Error creating VulnerabilityReport for %s: %s", vulnReportKey, err)
				return err
			}
			log.Printf("Created VulnerabilityReport: %s", vulnReportKey)
		} else if changed {
			if _, err = vulnReportClient.Update(context.Background(), vulnReport, metav1.UpdateOptions{}); err != nil {
				log.Printf("Error updating VulnerabilityReport for %s: %s", vulnReportKey, err)
				return err
			}
			log.Printf("Updated VulnerabilityReport: %s", vulnReportKey)
		}
	}

	return nil
}

func (s *Scanner) scan(img string) ([]secscanv1alpha1.VulnerabilityItem, error) {
	defer prometheus.ObserveScanDuration()()
	return s.scanAdapter.Scan(img)
}

func (s *Scanner) updateMetrics() {
	prometheus.PromVulnerabilityReports.Reset()
	prometheus.PromVulnerabilities.Reset()
	prometheus.PromVulnerableImages.Reset()

	var uniqueVulnerabilities []string
	var uniqueImages []string
	for _, vulnReport := range s.vulnInformer.GetIndexer().List() {
		if vr, ok := vulnReport.(*secscanv1alpha1.VulnerabilityReport); ok {
			// Count up vulnerability reports by namespace and
			// severity
			prometheus.PromVulnerabilityReports.WithLabelValues(vr.Namespace, vr.Spec.Summary.HighestSeverity).Inc()

			// Find unique vulnerabilities
			for _, vuln := range vr.Spec.Vulnerabilities {
				if !contains(uniqueVulnerabilities, vuln.VulnerabilityID) {
					uniqueVulnerabilities = append(uniqueVulnerabilities, vuln.VulnerabilityID)
					prometheus.PromVulnerabilities.WithLabelValues(vuln.Severity).Inc()
				}
			}

			// Find unique images
			if !contains(uniqueImages, vr.Spec.Artifact.Digest) && vr.Spec.Summary.HighestSeverity != "" {
				uniqueImages = append(uniqueImages, vr.Spec.Artifact.Digest)
				prometheus.PromVulnerableImages.WithLabelValues(vr.Spec.Summary.HighestSeverity).Inc()
			}

		}
	}

	return
}

func contains(s []string, i string) bool {
	for _, val := range s {
		if i == val {
			return true
		}
	}
	return false
}

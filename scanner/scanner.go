package scanner

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/ribbybibby/kube-container-security-operator/adapter"
	secscanv1alpha1 "github.com/ribbybibby/kube-container-security-operator/apis/secscan/v1alpha1"
	"github.com/ribbybibby/kube-container-security-operator/generated/versioned"
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

// Scanner performs vulnerability scans on pods in a Kubernetes cluster and
// saves the results as a VulnerabilityReport resource
type Scanner struct {
	kubeClient   kubernetes.Interface
	podInformer  cache.SharedIndexInformer
	vulnInformer cache.SharedIndexInformer
	vulnClient   versioned.Interface
	queue        workqueue.RateLimitingInterface
	ns           string
	scanAdapter  adapter.Interface
}

// New returns a new Scanner
func New(ns string, scanAdapter adapter.Interface) (*Scanner, error) {
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
		kubeClient:  clientset,
		vulnClient:  vulnClientSet,
		ns:          ns,
		scanAdapter: scanAdapter,
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
		60*time.Minute,
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
		60*time.Minute,
		cache.Indexers{},
	)

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

	log.Println(err)

	s.queue.AddRateLimited(key)

	log.Println("Requeued item", key)

	return true
}

func (s *Scanner) handleAddPod(obj interface{}) {
	pod := obj.(*corev1.Pod)

	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(pod)
	if err != nil {
		log.Println(err)
		return
	}

	s.queue.Add(key)
}

func (s *Scanner) handleDeletePod(obj interface{}) {
	pod := obj.(*corev1.Pod)

	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(pod)
	if err != nil {
		log.Println(err)
		return
	}

	s.queue.Add(key)
}

func (s *Scanner) handleUpdatePod(oldObj, newObj interface{}) {
	pod := newObj.(*corev1.Pod)

	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(pod)
	if err != nil {
		log.Println(err)
		return
	}

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
	keyParts := strings.Split(key, "/")

	ns := keyParts[0]
	podName := keyParts[1]

	vulnReportClient := s.vulnClient.SecscanV1alpha1().VulnerabilityReports(ns)
	podClient := s.kubeClient.CoreV1().Pods(ns)

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
			if vulnReport.Status.RemovePod(podName) {
				_, err := vulnReportClient.Update(context.Background(), &vulnReport, metav1.UpdateOptions{})
				if err != nil {
					return fmt.Errorf("Failed to update VulnerabilityReport: %w", err)
				}
				log.Printf("Updated VulnerabilityReport: %s/%s", vulnReport.Namespace, vulnReport.Name)
			}
		}

		// Garbage collect reports with no pods and remove dangling
		// pods from existing manifests
		if err := garbageCollectVulnerabilityReports(podClient, vulnReportClient); err != nil {
			return fmt.Errorf("Failed to garbage collect unreferenced VulnerabilityReports: %w", err)
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
		return fmt.Errorf("Pod not running or ready")
	}

	// Garbage collect reports with no pods and remove dangling
	// pods from existing manifests
	if err := garbageCollectVulnerabilityReports(podClient, vulnReportClient); err != nil {
		return fmt.Errorf("Failed to garbage collect unreferenced VulnerabilityReports: %w", err)
	}

	// Find images to scan
	for _, containerStatus := range pod.Status.ContainerStatuses {
		img := containerStatus.Image

		var vulnReport *secscanv1alpha1.VulnerabilityReport

		// Generate a sha1 of the image and the resolved imageID we're
		// scanning for use as the unique identifier for this report
		h := sha1.New()
		h.Write([]byte(containerStatus.Image + containerStatus.ImageID))
		vulnReportName := hex.EncodeToString(h.Sum(nil))

		vulnReportKey := fmt.Sprintf("%s/%s", pod.Namespace, vulnReportName)

		obj, exists, err := s.vulnInformer.GetIndexer().GetByKey(vulnReportKey)
		if err != nil {
			continue
		}

		// If a vulnerability report doesn't already exist for this
		// image then create it
		if !exists {
			// TODO: Don't scan the digest if we've already scanned it but
			// it didn't produce any vulnerabilities
			scanImage := strings.Split(containerStatus.ImageID, "://")[1]

			// Scan the image and return vulnerabilities
			log.Printf("Scanning: %s", scanImage)
			vulnerabilities, err := s.scanAdapter.Scan(scanImage)
			if err != nil {
				log.Printf("Error scanning image %s: %s", scanImage, err)
				return err
			}
			log.Printf("Scan finished for: %s", scanImage)

			// If there aren't any vulnerabilities then we don't
			// need to create the VulnerabilityReport
			if len(vulnerabilities) == 0 {
				continue
			}

			// Parse the image into an Artifact reference
			ref, err := name.ParseReference(img)
			if err != nil {
				return fmt.Errorf("Failed to parse reference: %w", err)
			}
			registry := secscanv1alpha1.Registry{
				URL: ref.Context().RegistryStr(),
			}
			artifact := secscanv1alpha1.Artifact{
				Repository: ref.Context().RepositoryStr(),
			}
			switch t := ref.(type) {
			case name.Tag:
				artifact.Tag = t.TagStr()
				imageDigestParts := strings.Split(containerStatus.ImageID, "@")
				if len(imageDigestParts) != 2 {
					continue
				}
				artifact.Digest = imageDigestParts[1]
			case name.Digest:
				artifact.Digest = t.DigestStr()
			}

			//

			// Define the report
			vulnReport = &secscanv1alpha1.VulnerabilityReport{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      make(map[string]string),
					Annotations: make(map[string]string),
					Name:        vulnReportName,
					Namespace:   ns,
				},
				Spec: secscanv1alpha1.VulnerabilityReportSpec{
					Registry:        registry,
					Artifact:        artifact,
					Vulnerabilities: vulnerabilities,
				},
			}

			// Add pod to status
			vulnReport.Status.AddPod(podName, img)

			// Create report
			_, err = vulnReportClient.Create(context.Background(), vulnReport, metav1.CreateOptions{})
			if err != nil {
				log.Printf("Error creating vulnerability report for %s: %s", vulnReportKey, err)
				continue
			}
			log.Printf("Created VulnerabilityReport: %s", vulnReportKey)

			// Done
			continue
		}

		// If a report already exists for this image then add the pod
		// to the status
		vulnReport = obj.(*secscanv1alpha1.VulnerabilityReport)
		if vulnReport.Status.AddPod(podName, img) {
			_, err = vulnReportClient.Update(context.Background(), vulnReport, metav1.UpdateOptions{})
			if err != nil {
				log.Printf("Error updating VulnerabilityReport for %s: %s", vulnReportKey, err)
			}
		}
	}

	return nil
}

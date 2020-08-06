/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/ribbybibby/kube-container-security-operator/adapter"
	secscanv1alpha1 "github.com/ribbybibby/kube-container-security-operator/apis/secscan/v1alpha1"
	"github.com/ribbybibby/kube-container-security-operator/prometheus"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"strings"
	"time"
)

// PodScanner scans pods and creates the corresponding vulnerabilityreports for
// the vulnerabilities it finds
type PodScanner struct {
	client.Client
	Log             logr.Logger
	Options         controller.Options
	RescanThreshold time.Duration
	Adapter         adapter.Interface
}

// Reconcile scans the image on a pod and creates/updates the corresponding
// vulnerabilityreports
func (ps *PodScanner) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	_ = ps.Log.WithValues("podscanner", req.NamespacedName)

	// Reconcile the pods attached to report statuses with the pods that
	// actially exist
	defer func() {
		if err := ps.garbageCollectVulnerabilityReports(ctx); err != nil && !errors.IsConflict(err) {
			ps.Log.Error(err, "Error garbage collecting vulnerabilityreports")
		}
	}()

	// Check if this pod exists
	pod := &corev1.Pod{}
	err := ps.Client.Get(ctx, req.NamespacedName, pod)
	if err != nil && errors.IsNotFound(err) {
		return ctrl.Result{}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// Requeue pods that aren't running or ready yet
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
		return ctrl.Result{Requeue: true}, nil
	}

	// Iterate over the pod's containers
	for _, containerStatus := range pod.Status.ContainerStatuses {
		// Parse the image into a registry and artifact
		registry, artifact, err := parseImage(containerStatus)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("Failed to parse reference: %w", err)
		}

		// The unique name of a vulnReport is a SHA1 of the registry +
		// repository + tag + digest
		h := sha1.New()
		h.Write([]byte(registry.URL + artifact.Repository + artifact.Digest + artifact.Tag))
		vulnReportName := hex.EncodeToString(h.Sum(nil))

		// Find an existing report, if there is one
		exists := true
		vulnReport := &secscanv1alpha1.VulnerabilityReport{}
		err = ps.Client.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: vulnReportName}, vulnReport)
		if err != nil && errors.IsNotFound(err) {
			exists = false
		} else if err != nil {
			return ctrl.Result{}, err
		}

		// Controls whether the image is scanned or not
		scan := false

		if !exists {
			vulnReport = &secscanv1alpha1.VulnerabilityReport{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      make(map[string]string),
					Annotations: make(map[string]string),
					Name:        vulnReportName,
					Namespace:   pod.Namespace,
				},
				Spec: secscanv1alpha1.VulnerabilityReportSpec{
					Artifact: *artifact,
					Registry: *registry,
				},
			}
			scan = true
		} else {
			// Rescan the image if it's been at least rescanTheshold
			// amount of time since the last update
			lastUpdateTime, err := time.Parse("2006-01-02 15:04:05 -0700 MST", vulnReport.Status.LastUpdate)
			if err != nil {
				ps.Log.Error(err, "Error parsing vulnerabilityreport's lastUpdate", "namespace", vulnReport.Namespace, "report", vulnReportName)
			}
			if time.Now().UTC().Sub(lastUpdateTime) > ps.RescanThreshold || err != nil {
				ps.Log.Info("Scheduled rescan", "namespace", vulnReport.Namespace, "report", vulnReportName)
				scan = true
			}

		}

		// Scan the image
		if scan {
			prometheus.PromScans.WithLabelValues(pod.Namespace).Inc()

			// Use the underlying image ID which pulls by digest,
			// rather than tag.
			scanImage := strings.Split(containerStatus.ImageID, "://")[1]

			ps.Log.Info("Scanning", "image", scanImage)
			vulnerabilities, err := ps.scan(scanImage)
			if err != nil {
				ps.Log.Error(err, "Error scanning image", "image", scanImage)
				return ctrl.Result{}, err
			}
			ps.Log.Info("Scanned", "image", scanImage)

			vulnReport.Spec.Vulnerabilities = vulnerabilities
			vulnReport.Status.LastUpdate = time.Now().UTC().String()
		}

		podsChanged := vulnReport.AddPod(pod.Name, containerStatus.Image)

		if !exists {
			if err := ps.Client.Create(ctx, vulnReport); err != nil {
				return ctrl.Result{}, err
			}
			ps.Log.Info("Created vulnerabilityreport", "report", vulnReport.Name)
		} else if podsChanged || scan {
			if err := ps.Client.Update(ctx, vulnReport); err != nil && errors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			} else if err != nil {
				return ctrl.Result{}, err
			}
			ps.Log.Info("Updated vulnerabilityreport", "report", vulnReport.Name)
		}

	}

	return ctrl.Result{}, nil
}

// scan scans an image with the configured scan adapter
func (ps *PodScanner) scan(img string) ([]secscanv1alpha1.VulnerabilityItem, error) {
	defer prometheus.ObserveScanDuration()()
	return ps.Adapter.Scan(img)
}

func (ps *PodScanner) garbageCollectVulnerabilityReports(ctx context.Context) error {
	// List the pods that are currently running
	podList := &corev1.PodList{}
	err := ps.Client.List(ctx, podList)
	if err != nil {
		return fmt.Errorf("Failed to list pods: %w", err)
	}
	currentPods := []string{}
	for _, pod := range podList.Items {
		currentPods = append(currentPods, pod.Name)
	}

	// Iterate over the reports and remove pods from the status field that
	// are no longer present in the cluster
	vulnReportList := &secscanv1alpha1.VulnerabilityReportList{}
	if err := ps.Client.List(ctx, vulnReportList); err != nil {
		return fmt.Errorf("Faled to list vulnerabilityreports: %w", err)
	}
	for _, vulnReport := range vulnReportList.Items {
		podsRemoved := vulnReport.RemoveDanglingPods(currentPods)

		// If there aren't any pods left in the status then the report
		// should be deleted
		if len(vulnReport.Status.Pods) == 0 {
			if err := ps.Client.Delete(ctx, &vulnReport); err != nil {
				return err
			}
			ps.Log.Info("Deleted vulnerabilityreport", "name", vulnReport.Name, "namespace", vulnReport.Namespace)
			continue
		}

		// If the pods on the report have changed, update it
		if podsRemoved {
			// Update the report with the new status
			if err := ps.Client.Update(ctx, &vulnReport); err != nil {
				return err
			}
			ps.Log.Info("Updated vulnerabilityreport", "name", vulnReport.Name, "namespace", vulnReport.Namespace)
		}
	}

	return nil
}

func (ps *PodScanner) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		WithOptions(ps.Options).
		Complete(ps)
}

func contains(s []string, i string) bool {
	for _, val := range s {
		if i == val {
			return true
		}
	}
	return false
}

func parseImage(containerStatus v1.ContainerStatus) (*secscanv1alpha1.Registry, *secscanv1alpha1.Artifact, error) {
	// Parse the image into an Artifact reference
	ref, err := name.ParseReference(containerStatus.Image)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse reference: %w", err)
	}
	registry := &secscanv1alpha1.Registry{
		URL: ref.Context().RegistryStr(),
	}
	artifact := &secscanv1alpha1.Artifact{
		Repository: ref.Context().RepositoryStr(),
	}
	switch t := ref.(type) {
	case name.Tag:
		artifact.Tag = t.TagStr()
		digestParts := strings.Split(containerStatus.ImageID, "@")
		if len(digestParts) != 2 {
			return registry, artifact, nil
		}
		artifact.Digest = digestParts[1]

	case name.Digest:
		artifact.Digest = t.DigestStr()
	}

	return registry, artifact, nil
}

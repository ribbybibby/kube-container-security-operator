package scanner

import (
	"context"
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	secscanv1alpha1 "github.com/ribbybibby/kube-container-security-operator/apis/secscan/v1alpha1"
	secscanv1alpha1client "github.com/ribbybibby/kube-container-security-operator/generated/versioned/typed/secscan/v1alpha1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"log"
	"strings"
)

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
func garbageCollectVulnerabilityReports(podClient corev1.PodInterface, vulnReportClient secscanv1alpha1client.VulnerabilityReportInterface) error {
	// List the pods that are currently running
	podList, err := podClient.List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("Failed to list pods: %w", err)
	}
	currentPods := []string{}
	for _, pod := range podList.Items {
		currentPods = append(currentPods, pod.Name)
	}

	// Iterate over the VulnerabilityReports and remove pods from the status
	// field that are no longer present in the cluster
	vulnReportList, err := vulnReportClient.List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("Failed to list VulnerabilityReports: %w", err)
	}
	for _, vulnReport := range vulnReportList.Items {
		if vulnReport.RemoveDanglingPods(currentPods) {
			// If there aren't any pods left in the status then the
			// report should be deleted
			if len(vulnReport.Status.Pods) == 0 {
				if err := vulnReportClient.Delete(context.Background(), vulnReport.Name, metav1.DeleteOptions{}); err != nil {
					return fmt.Errorf("Failed to delete VulnerabilityReport: %w", err)
				}
				log.Printf("Deleted VulnerabilityReport: %s", vulnReport.Name)
				continue
			}

			// Update the report with the new status
			if _, err := vulnReportClient.Update(context.Background(), &vulnReport, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("Failed to update VulnerabilityReport: %w", err)
			}
		}
	}

	return nil
}

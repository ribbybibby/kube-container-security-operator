package scanner

import (
	"context"
	"fmt"
	secscanv1alpha1client "github.com/ribbybibby/kube-container-security-operator/generated/versioned/typed/secscan/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

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
		if vulnReport.Status.RemoveDanglingPods(currentPods) {
			// If there aren't any pods left in the status then the
			// report should be deleted
			if len(vulnReport.Status.Pods) == 0 {
				if err := vulnReportClient.Delete(context.Background(), vulnReport.Name, metav1.DeleteOptions{}); err != nil {
					return fmt.Errorf("Failed to delete VulnerabilityReport: %w", err)
				}
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

package adapter

import (
	secscanv1alpha1 "github.com/ribbybibby/kube-container-security-operator/apis/secscan/v1alpha1"
)

// Interface scans an image and returns vulnerabilities
type Interface interface {
	Scan(image string) ([]secscanv1alpha1.VulnerabilityItem, error)
}

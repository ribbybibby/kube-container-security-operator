package v1alpha1

import (
	"encoding/json"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	SeverityCritical string = "CRITICAL"
	SeverityHigh     string = "HIGH"
	SeverityMedium   string = "MEDIUM"
	SeverityLow      string = "LOW"
	SeverityNone     string = "NONE"
	SeverityUnknown  string = "UNKNOWN"
)

type Registry struct {
	URL string `json:"url"`
}

type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	Tag        string `json:"tag,omitempty"`
	MimeType   string `json:"mimeType,omitempty"`
}

type VulnerabilitySummary struct {
	HighestSeverity string `json:"highestSeverity"`
	CriticalCount   int    `json:"criticalCount"`
	HighCount       int    `json:"highCount"`
	MediumCount     int    `json:"mediumCount"`
	LowCount        int    `json:"lowCount"`
	NoneCount       int    `json:"noneCount"`
	UnknownCount    int    `json:"unknownCount"`
}

// VulnerabilityItem is the spec for a vulnerability record.
type VulnerabilityItem struct {
	VulnerabilityID  string   `json:"vulnerabilityID"`
	Resource         string   `json:"resource"`
	InstalledVersion string   `json:"installedVersion"`
	FixedVersion     string   `json:"fixedVersion"`
	Severity         string   `json:"severity"`
	LayerID          string   `json:"layerID"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Links            []string `json:"links"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:printcolumn:name="Registry",type=string,JSONPath=`.spec.registry.url`
// +kubebuilder:printcolumn:name="Repository",type=string,JSONPath=`.spec.artifact.repository`
// +kubebuilder:printcolumn:name="Highest Severity",type=string,JSONPath=`.spec.summary.highestSeverity`
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.spec.summary.criticalCount`,priority=1
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.spec.summary.highCount`,priority=1
// +kubebuilder:printcolumn:name="Medium",type=integer,JSONPath=`.spec.summary.mediumCount`,priority=1
// +kubebuilder:printcolumn:name="Low",type=integer,JSONPath=`.spec.summary.lowCount`,priority=1
// +kubebuilder:printcolumn:name="None",type=integer,JSONPath=`.spec.summary.noneCount`,priority=1
// +kubebuilder:printcolumn:name="Unknown",type=integer,JSONPath=`.spec.summary.unknownCount`,priority=1
type VulnerabilityReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VulnerabilityReportSpec   `json:"spec,omitempty"`
	Status VulnerabilityReportStatus `json:"status,omitempty"`
}

// VulnerabilityReportSpec defines the desired state of VulnerabilityReport
type VulnerabilityReportSpec struct {
	Registry        Registry             `json:"registry"`
	Artifact        Artifact             `json:"artifact"`
	Summary         VulnerabilitySummary `json:"summary"`
	Vulnerabilities []VulnerabilityItem  `json:"vulnerabilities"`
}

// MarshalJSON generates the summary fields based on the list of
// vulnerabilities. This means that no matter how the spec is generated, the
// summary is always computed in the same way.
func (vrs *VulnerabilityReportSpec) MarshalJSON() ([]byte, error) {
	var vs VulnerabilitySummary

	for _, vuln := range vrs.Vulnerabilities {
		switch vuln.Severity {
		case "UNKNOWN":
			vs.UnknownCount++
		case "LOW":
			vs.LowCount++
		case "MEDIUM":
			vs.MediumCount++
		case "HIGH":
			vs.HighCount++
		case "CRITICAL":
			vs.CriticalCount++
		}
	}

	if vs.CriticalCount > 0 {
		vs.HighestSeverity = SeverityCritical
	} else if vs.HighCount > 0 {
		vs.HighestSeverity = SeverityHigh
	} else if vs.MediumCount > 0 {
		vs.HighestSeverity = SeverityMedium
	} else if vs.LowCount > 0 {
		vs.HighestSeverity = SeverityLow
	} else if vs.NoneCount > 0 {
		vs.HighestSeverity = SeverityNone
	} else if vs.UnknownCount > 0 {
		vs.HighestSeverity = SeverityUnknown
	}

	type Alias VulnerabilityReportSpec
	return json.Marshal(&struct {
		Summary VulnerabilitySummary `json:"summary"`
		*Alias
	}{
		Summary: vs,
		Alias:   (*Alias)(vrs),
	})
}

// VulnerabilityReportStatus defines the observed state of VulnerabilityReport
type VulnerabilityReportStatus struct {
	// Map from pod's path to container ids
	Pods map[string][]string `json:"pods,omitempty"`
}

// AddPod adds a pod to the status. Returns true if it added the pod and false
// if the pod was already present
func (vrs *VulnerabilityReportStatus) AddPod(pod, img string) bool {
	changed := false

	if images, ok := vrs.Pods[pod]; ok {
		if !contains(images, img) {
			images = append(images, img)
			vrs.Pods[pod] = images
			changed = true
		}
		return changed
	}

	if vrs.Pods == nil {
		vrs.Pods = make(map[string][]string)
	}
	vrs.Pods[pod] = append(vrs.Pods[pod], img)

	changed = true

	return changed
}

// RemovePod removes a pod from the status. Returns true if it added the pod and
// false if the pod was already present
func (vrs *VulnerabilityReportStatus) RemovePod(pod string) bool {
	changed := false

	if _, ok := vrs.Pods[pod]; ok {
		delete(vrs.Pods, pod)
		changed = true
	}

	return changed
}

func (vrs *VulnerabilityReportStatus) RemoveDanglingPods(pods []string) bool {
	changed := false

	for p := range vrs.Pods {
		if !contains(pods, p) {
			var updated bool
			updated = vrs.RemovePod(p)
			changed = changed || updated
		}
	}

	return changed
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VulnerabilityReportList contains a list of VulnerabilityReport
type VulnerabilityReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VulnerabilityReport `json:"items"`
}

func contains(s []string, i string) bool {
	for _, val := range s {
		if i == val {
			return true
		}
	}
	return false
}

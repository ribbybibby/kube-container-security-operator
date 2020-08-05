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
// +kubebuilder:printcolumn:name="Tag",type=string,JSONPath=`.spec.artifact.tag`
// +kubebuilder:printcolumn:name="Highest Severity",type=string,JSONPath=`.spec.summary.highestSeverity`
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.spec.summary.criticalCount`,priority=1
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.spec.summary.highCount`,priority=1
// +kubebuilder:printcolumn:name="Medium",type=integer,JSONPath=`.spec.summary.mediumCount`,priority=1
// +kubebuilder:printcolumn:name="Low",type=integer,JSONPath=`.spec.summary.lowCount`,priority=1
// +kubebuilder:printcolumn:name="None",type=integer,JSONPath=`.spec.summary.noneCount`,priority=1
// +kubebuilder:printcolumn:name="Unknown",type=integer,JSONPath=`.spec.summary.unknownCount`,priority=1
// +kubebuilder:printcolumn:name="Digest",type=string,JSONPath=`.spec.artifact.digest`,priority=1
// +kubebuilder:printcolumn:name="Last Update",type=string,JSONPath=`.status.lastUpdate`,priority=1
type VulnerabilityReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VulnerabilityReportSpec   `json:"spec,omitempty"`
	Status VulnerabilityReportStatus `json:"status,omitempty"`
}

// MarshalJSON generates the summary fields and labels based on the list of
// vulnerabilities and the status of the report.
func (vr *VulnerabilityReport) MarshalJSON() ([]byte, error) {
	vrs := vr.Spec

	for _, vuln := range vrs.Vulnerabilities {
		switch vuln.Severity {
		case "UNKNOWN":
			vrs.Summary.UnknownCount++
		case "LOW":
			vrs.Summary.LowCount++
		case "MEDIUM":
			vrs.Summary.MediumCount++
		case "HIGH":
			vrs.Summary.HighCount++
		case "CRITICAL":
			vrs.Summary.CriticalCount++
		}
	}

	if vrs.Summary.CriticalCount > 0 {
		vrs.Summary.HighestSeverity = SeverityCritical
	} else if vrs.Summary.HighCount > 0 {
		vrs.Summary.HighestSeverity = SeverityHigh
	} else if vrs.Summary.MediumCount > 0 {
		vrs.Summary.HighestSeverity = SeverityMedium
	} else if vrs.Summary.LowCount > 0 {
		vrs.Summary.HighestSeverity = SeverityLow
	} else if vrs.Summary.NoneCount > 0 {
		vrs.Summary.HighestSeverity = SeverityNone
	} else if vrs.Summary.UnknownCount > 0 {
		vrs.Summary.HighestSeverity = SeverityUnknown
	}

	metadata := vr.ObjectMeta

	if metadata.Labels == nil {
		metadata.Labels = make(map[string]string)
	}

	metadata.Labels["severity"] = vrs.Summary.HighestSeverity

	for pod := range vr.Status.Pods {
		// Labels can only be 63 characters long but pod names can be
		// longer
		if len(pod) < 64 {
			metadata.Labels[pod] = "true"
		}
	}

	type Alias VulnerabilityReport
	return json.Marshal(&struct {
		ObjectMeta metav1.ObjectMeta       `json:"metadata,omitempty"`
		Spec       VulnerabilityReportSpec `json:"spec"`
		*Alias
	}{
		ObjectMeta: metadata,
		Spec:       vrs,
		Alias:      (*Alias)(vr),
	})
}

// AddPod adds a pod to the status and the labels. Returns true if it added the pod and false
// if the pod was already present
func (vr *VulnerabilityReport) AddPod(pod, img string) bool {
	changed := false

	if images, ok := vr.Status.Pods[pod]; ok {
		if !contains(images, img) {
			images = append(images, img)
			vr.Status.Pods[pod] = images
			changed = true
		}
		return changed
	}

	if vr.Status.Pods == nil {
		vr.Status.Pods = make(map[string][]string)
	}

	vr.Status.Pods[pod] = append(vr.Status.Pods[pod], img)
	changed = true

	return changed
}

// RemovePod removes a pod from the status and labels. Returns true if it added the pod and
// false if the pod was already present
func (vr *VulnerabilityReport) RemovePod(pod string) bool {
	changed := false

	if _, ok := vr.Status.Pods[pod]; ok {
		delete(vr.Status.Pods, pod)
		changed = true
	}

	return changed
}

// RemoveDanglingPods removes pods from the status and labels that aren't in the provided
// list of pods
func (vr *VulnerabilityReport) RemoveDanglingPods(pods []string) bool {
	changed := false

	for p := range vr.Status.Pods {
		if !contains(pods, p) {
			var updated bool
			updated = vr.RemovePod(p)
			changed = changed || updated
		}
	}

	return changed
}

// VulnerabilityReportSpec defines the desired state of VulnerabilityReport
type VulnerabilityReportSpec struct {
	Registry        Registry             `json:"registry"`
	Artifact        Artifact             `json:"artifact"`
	Summary         VulnerabilitySummary `json:"summary"`
	Vulnerabilities []VulnerabilityItem  `json:"vulnerabilities,omitempty"`
}

// VulnerabilityReportStatus defines the observed state of VulnerabilityReport
type VulnerabilityReportStatus struct {
	LastUpdate string              `json:"lastUpdate,omitempty"`
	Pods       map[string][]string `json:"pods,omitempty"`
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

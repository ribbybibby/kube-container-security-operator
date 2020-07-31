package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityNone     Severity = "NONE"
	SeverityUnknown  Severity = "UNKNOWN"
)

type VulnerabilitySummary struct {
	HighestSeverity Severity `json:"highestSeverity"`
	CriticalCount   int      `json:"criticalCount"`
	HighCount       int      `json:"highCount"`
	MediumCount     int      `json:"mediumCount"`
	LowCount        int      `json:"lowCount"`
	NoneCount       int      `json:"noneCount"`
	UnknownCount    int      `json:"unknownCount"`
}

// VulnerabilityItem is the spec for a vulnerability record.
type VulnerabilityItem struct {
	VulnerabilityID string `json:"vulnerabilityID"`
	Resource        string `json:"resource"`
	// TODO Add ResourceType enum property to distinguish between OS packages and application dependencies
	InstalledVersion string   `json:"installedVersion"`
	FixedVersion     string   `json:"fixedVersion"`
	Severity         Severity `json:"severity"`
	LayerID          string   `json:"layerID"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Links            []string `json:"links"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type VulnerabilityReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VulnerabilityReportSpec   `json:"spec,omitempty"`
	Status VulnerabilityReportStatus `json:"status,omitempty"`
}

// VulnerabilityReportSpec defines the desired state of VulnerabilityReport
type VulnerabilityReportSpec struct {
	Summary         VulnerabilitySummary `json:"summary"`
	Vulnerabilities []VulnerabilityItem
}

// VulnerabilityReportStatus defines the observed state of VulnerabilityReport
type VulnerabilityReportStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VulnerabilityReportList contains a list of VulnerabilityReport
type VulnerabilityReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VulnerabilityReport `json:"items"`
}

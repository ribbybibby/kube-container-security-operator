package trivy

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/report"
	secscanv1alpha1 "github.com/ribbybibby/kube-container-security-operator/apis/secscan/v1alpha1"
	"net/url"
	"os/exec"
)

// Client is a relatively thin wrapper around the trivy client
type Client struct {
	Client bool
	Remote *url.URL
}

// Scan scans a target image with trivy and returns the vulnerabilities it finds
func (c *Client) Scan(target string) ([]secscanv1alpha1.VulnerabilityItem, error) {
	var (
		vulnerabilities []secscanv1alpha1.VulnerabilityItem
		args            []string
	)

	args = []string{"-q"}
	if c.Client {
		args = append(args, "client")

		if c.Remote != nil {
			args = append(args, []string{"--remote", c.Remote.String()}...)
		}
	} else {
		args = append(args, "image")
	}
	args = append(args, []string{"-f", "json", target}...)

	cmd := exec.Command("trivy", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return vulnerabilities, fmt.Errorf("Error scanning %s: %s %s", target, string(out), err)
	}

	var results report.Results

	if err = json.Unmarshal(out, &results); err != nil {
		return vulnerabilities, err
	}

	for _, result := range results {
		for _, vuln := range result.Vulnerabilities {
			v := secscanv1alpha1.VulnerabilityItem{
				VulnerabilityID:  vuln.VulnerabilityID,
				Resource:         vuln.PkgName,
				InstalledVersion: vuln.InstalledVersion,
				LayerID:          vuln.Layer.Digest,
				FixedVersion:     vuln.FixedVersion,
				Severity:         vuln.Severity,
				Title:            vuln.Title,
				Description:      vuln.Description,
				Links:            []string{},
			}

			if len(vuln.References) > 0 {
				v.Links = vuln.References
			}

			vulnerabilities = append(vulnerabilities, v)
		}
	}

	return vulnerabilities, nil
}

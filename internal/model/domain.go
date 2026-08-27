package model

// Domain is a validated input hostname and the registrable apex used for DNS
// lookups. Hostname is also the stable key written to the required JSON output.
type Domain struct {
	Hostname string `json:"hostname"`
	Apex     string `json:"apex"`
}

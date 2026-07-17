package exporter

import "strings"

// vulsResult is the subset of a Vuls scan result we read in order to resolve
// each CVE. A full Vuls result also carries references, CPEs, CWEs, CVSS2 data,
// exploits, mitigations and the package inventory — all skipped when decoding
// into this struct.
type vulsResult struct {
	ServerName  string             `json:"serverName"`
	Family      string             `json:"family"`
	ScannedCves map[string]vulsCVE `json:"scannedCves"`
}

type vulsCVE struct {
	AffectedPackages []vulsAffectedPackage       `json:"affectedPackages"`
	CveContents      map[string][]vulsCveContent `json:"cveContents"`
}

type vulsAffectedPackage struct {
	Name        string `json:"name"`
	NotFixedYet bool   `json:"notFixedYet"`
	FixState    string `json:"fixState"`
}

type vulsCveContent struct {
	Cvss3Score    float64 `json:"cvss3Score"`
	Cvss3Severity string  `json:"cvss3Severity"`
	Summary       string  `json:"summary"`
}

// reportResult is the resolved payload posted to the API. Every distro-aware
// choice (which advisory wins the severity, score and link) is already made, so
// the API stores these values verbatim.
type reportResult struct {
	ServerName  string               `json:"serverName"`
	ScannedCves map[string]reportCVE `json:"scannedCves,omitempty"`
}

type reportCVE struct {
	Score            float64                 `json:"score"`
	Severity         string                  `json:"severity"`
	Summary          string                  `json:"summary,omitempty"`
	Link             string                  `json:"link"`
	AffectedPackages []reportAffectedPackage `json:"affectedPackages,omitempty"`
}

type reportAffectedPackage struct {
	Name        string `json:"name"`
	NotFixedYet bool   `json:"notFixedYet,omitempty"`
	FixState    string `json:"fixState,omitempty"`
}

// Vuls CveContents source keys. Each distro exposes a security-API feed and an
// OVAL/CVRF feed; both count as the host's own advisory.
const (
	sourceNVD           = "nvd"
	sourceRedHatAPI     = "redhat_api"
	sourceRedHat        = "redhat"
	sourceUbuntuAPI     = "ubuntu_api"
	sourceUbuntu        = "ubuntu"
	sourceDebianTracker = "debian_security_tracker"
	sourceDebian        = "debian"
	sourceSUSE          = "suse"
)

// cveVendor is a coarse classification of the host distro, driving both the
// advisory source list and the reference link.
type cveVendor int

const (
	vendorUnknown cveVendor = iota
	vendorUbuntu
	vendorDebian
	vendorRedHat
	vendorSUSE
)

// classifyVendor maps a Vuls family (ubuntu, debian, redhat, centos, rocky,
// amazon, suse.linux.enterprise.server, …) to a vendor. Substring matching
// tolerates Vuls's dotted family names.
func classifyVendor(family string) cveVendor {
	f := strings.ToLower(family)
	switch {
	case strings.Contains(f, "ubuntu"):
		return vendorUbuntu
	case strings.Contains(f, "debian"):
		return vendorDebian
	case strings.Contains(f, "redhat"), strings.Contains(f, "centos"),
		strings.Contains(f, "rocky"), strings.Contains(f, "alma"),
		strings.Contains(f, "oracle"), strings.Contains(f, "fedora"),
		strings.Contains(f, "amazon"):
		return vendorRedHat
	case strings.Contains(f, "suse"):
		return vendorSUSE
	}
	return vendorUnknown
}

// distroSources returns the host distro's own advisory source keys, most
// authoritative first. Returns nil for unknown families, which disables distro
// filtering (all CVEs kept, scored from NVD).
func distroSources(family string) []string {
	switch classifyVendor(family) {
	case vendorUbuntu:
		return []string{sourceUbuntuAPI, sourceUbuntu}
	case vendorDebian:
		return []string{sourceDebianTracker, sourceDebian}
	case vendorRedHat:
		return []string{sourceRedHatAPI, sourceRedHat}
	case vendorSUSE:
		return []string{sourceSUSE}
	}
	return nil
}

// cveReferenceLink returns the vendor advisory URL for the CVE on the host
// distro, deterministic from the CVE ID, falling back to NVD when unknown.
func cveReferenceLink(family, cveID string) string {
	switch classifyVendor(family) {
	case vendorUbuntu:
		return "https://ubuntu.com/security/" + cveID
	case vendorDebian:
		return "https://security-tracker.debian.org/tracker/" + cveID
	case vendorRedHat:
		return "https://access.redhat.com/security/cve/" + cveID
	case vendorSUSE:
		return "https://www.suse.com/security/cve/" + cveID + ".html"
	}
	return "https://nvd.nist.gov/vuln/detail/" + cveID
}

// buildReport resolves every CVE in the Vuls result into the API's payload,
// dropping CVEs the host distro's own advisory never flagged (Vuls
// cross-references other vendors for the same CVE ID). Hosts with an unknown
// family are not filtered.
func buildReport(r *vulsResult) reportResult {
	sources := distroSources(r.Family)

	out := reportResult{
		ServerName:  r.ServerName,
		ScannedCves: make(map[string]reportCVE, len(r.ScannedCves)),
	}
	for id, cve := range r.ScannedCves {
		if !appliesToDistro(cve, sources) {
			continue
		}
		score, severity, summary := resolveCVE(cve, sources)
		out.ScannedCves[id] = reportCVE{
			Score:            score,
			Severity:         severity,
			Summary:          summary,
			Link:             cveReferenceLink(r.Family, id),
			AffectedPackages: affectedPackages(cve.AffectedPackages),
		}
	}
	return out
}

// appliesToDistro reports whether the CVE was flagged by the host distro's own
// advisory. Hosts with no known sources (unknown family) are never filtered.
func appliesToDistro(cve vulsCVE, sources []string) bool {
	if len(sources) == 0 {
		return true
	}
	for _, src := range sources {
		if len(cve.CveContents[src]) > 0 {
			return true
		}
	}
	return false
}

// resolveCVE picks the CVE's score, severity and summary. Severity comes from
// the distro's own advisory (the vendor's contextual triage), falling back to
// NVD only when the distro feed carries no label. The score prefers the distro's
// contextual score, then NVD, then the highest across any source. Summary
// prefers NVD's prose.
func resolveCVE(cve vulsCVE, sources []string) (score float64, severity, summary string) {
	severity = firstSeverity(cve, sources)
	if severity == "" {
		severity = firstSeverity(cve, []string{sourceNVD})
	}

	score = firstScore(cve, sources)
	if score == 0 {
		score = firstScore(cve, []string{sourceNVD})
	}
	if score == 0 {
		score = maxScore(cve)
	}

	summary = firstSummary(cve, []string{sourceNVD})
	if summary == "" {
		summary = firstSummary(cve, sources)
	}

	return score, strings.ToLower(severity), summary
}

func firstSeverity(cve vulsCVE, sources []string) string {
	for _, src := range sources {
		for _, entry := range cve.CveContents[src] {
			if entry.Cvss3Severity != "" {
				return entry.Cvss3Severity
			}
		}
	}
	return ""
}

func firstScore(cve vulsCVE, sources []string) float64 {
	for _, src := range sources {
		var best float64
		for _, entry := range cve.CveContents[src] {
			if entry.Cvss3Score > best {
				best = entry.Cvss3Score
			}
		}
		if best > 0 {
			return best
		}
	}
	return 0
}

func maxScore(cve vulsCVE) float64 {
	var best float64
	for _, entries := range cve.CveContents {
		for _, entry := range entries {
			if entry.Cvss3Score > best {
				best = entry.Cvss3Score
			}
		}
	}
	return best
}

func firstSummary(cve vulsCVE, sources []string) string {
	for _, src := range sources {
		for _, entry := range cve.CveContents[src] {
			if entry.Summary != "" {
				return entry.Summary
			}
		}
	}
	return ""
}

func affectedPackages(pkgs []vulsAffectedPackage) []reportAffectedPackage {
	if len(pkgs) == 0 {
		return nil
	}
	out := make([]reportAffectedPackage, len(pkgs))
	for i, p := range pkgs {
		out[i] = reportAffectedPackage(p)
	}
	return out
}

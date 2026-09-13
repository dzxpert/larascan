package recon

import (
	"fmt"
	"net"
	"strings"
	"time"

	"larascan/internal/common"
)

type SubdomainEnumScan struct{}

func NewSubdomainEnumScan() *SubdomainEnumScan {
	return &SubdomainEnumScan{}
}

func (ses *SubdomainEnumScan) Run(target string) []common.ScanResult {
	domain := extractDomain(target)
	subdomains := []string{"www", "api", "admin", "dev", "test"}
	foundSubdomains := []string{}

	for _, sub := range subdomains {
		fullDomain := fmt.Sprintf("%s.%s", sub, domain)
		_, err := net.LookupHost(fullDomain)
		if err == nil {
			foundSubdomains = append(foundSubdomains, fullDomain)
		}
		// Respectful delay between requests
		time.Sleep(500 * time.Millisecond)
	}

	var results []common.ScanResult

	if len(foundSubdomains) > 0 {
		results = append(results, common.ScanResult{
			ScanName:    ses.Name(),
			Category:    "Recon",
			Description: "Found subdomains",
			Path:        target,
			StatusCode:  0, // Subdomain enumeration doesn't involve HTTP status codes
			Detail:      strings.Join(foundSubdomains, ", "),
		})
	} else {
		results = append(results, common.ScanResult{
			ScanName:    ses.Name(),
			Category:    "Recon",
			Description: "No common subdomains found",
			Path:        target,
			StatusCode:  0,
		})
	}

	return results
}

func extractDomain(urlStr string) string {
	parts := strings.Split(urlStr, "//")
	if len(parts) > 1 {
		urlStr = parts[1]
	}
	parts = strings.Split(urlStr, "/")
	host := strings.Split(parts[0], ":")[0]

	// Check if host is an IP address
	if net.ParseIP(host) != nil || host == "localhost" {
		return host
	}

	// Extract root/apex domain (e.g., app.chargily.net -> chargily.net)
	hostParts := strings.Split(host, ".")
	if len(hostParts) > 2 {
		secondLast := strings.ToLower(hostParts[len(hostParts)-2])
		// Check for multi-part ccTLDs like .co.uk, .com.au, .com.dz
		if (secondLast == "co" || secondLast == "com" || secondLast == "org" || secondLast == "net" || secondLast == "gov" || secondLast == "edu") && len(hostParts) > 3 {
			return strings.Join(hostParts[len(hostParts)-3:], ".")
		}
		return strings.Join(hostParts[len(hostParts)-2:], ".")
	}

	return host
}

func (pvs *SubdomainEnumScan) Name() string {
	return "Subdomain Enumeration"
}

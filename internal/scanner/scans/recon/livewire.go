package recon

import (
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
	"larascan/internal/common"
	"larascan/pkg/httpclient"
)

// LivewireScan is a struct that contains an HTTP client
type LivewireScan struct {
	client *httpclient.Client
}

// NewLivewireScan initializes and returns a new LivewireScan instance
func NewLivewireScan() *LivewireScan {
	return &LivewireScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Run checks if Livewire is used on the target site and attempts to determine the version
func (lws *LivewireScan) Run(target string) []common.ScanResult {
	var results []common.ScanResult
	cleanTarget := strings.TrimRight(target, "/")

	// Candidate paths to test
	pathsToCheck := []string{
		"/livewire/livewire.js",
		"/livewire/livewire.min.js",
		"/vendor/livewire/livewire.js",
		"/vendor/livewire/livewire.min.js",
	}

	htmlDomVersion := ""
	htmlLivewireFound := false

	// Target pages to inspect (the provided target and its root URL if different)
	targetsToInspect := []string{cleanTarget}
	if parsedURL, parseErr := url.Parse(cleanTarget); parseErr == nil && parsedURL.Host != "" {
		rootURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		if rootURL != cleanTarget {
			targetsToInspect = append(targetsToInspect, rootURL)
		}
	}

	// Fetch pages to look for dynamically loaded Livewire scripts or DOM markers
	scriptRe := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']*livewire[^"']*)["']`)
	for _, inspectTarget := range targetsToInspect {
		targetResp, err := lws.client.Get(inspectTarget, nil)
		if err == nil && targetResp.StatusCode == 200 {
			bodyBytes, readErr := io.ReadAll(io.LimitReader(targetResp.Body, 512*1024))
			targetResp.Body.Close()

			if readErr == nil {
				bodyStr := string(bodyBytes)

				matches := scriptRe.FindAllStringSubmatch(bodyStr, -1)
				for _, match := range matches {
					if len(match) > 1 {
						scriptPath := match[1]
						pathsToCheck = append([]string{scriptPath}, pathsToCheck...)
						htmlLivewireFound = true
					}
				}

				if strings.Contains(bodyStr, "wire:snapshot") {
					htmlLivewireFound = true
					htmlDomVersion = "3.x"
				} else if strings.Contains(bodyStr, "wire:initial-data") {
					htmlLivewireFound = true
					htmlDomVersion = "2.x"
				} else if strings.Contains(bodyStr, "wire:id") {
					htmlLivewireFound = true
				}
			}
		} else if targetResp != nil {
			targetResp.Body.Close()
		}
	}

	testedUrls := make(map[string]bool)

	for _, path := range pathsToCheck {
		var checkURL string
		if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
			checkURL = path
		} else if strings.HasPrefix(path, "/") {
			checkURL = cleanTarget + path
		} else {
			checkURL = cleanTarget + "/" + path
		}

		if testedUrls[checkURL] {
			continue
		}
		testedUrls[checkURL] = true

		resp, err := lws.client.Get(checkURL, nil)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			continue
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}
		body := string(bodyBytes)

		// Determine the version based on script content
		if strings.Contains(body, "window.livewireScriptConfig") ||
			strings.Contains(body, "Livewire 3") ||
			strings.Contains(body, "window.Livewire") && strings.Contains(body, "snapshot") {
			results = append(results, common.ScanResult{
				ScanName:    lws.Name(),
				Category:    "Recon",
				Description: fmt.Sprintf("Livewire detected: Version 3.x at %s", checkURL),
				Path:        checkURL,
				StatusCode:  resp.StatusCode,
				Detail:      lws.getVulnerabilitiesForV3(),
			})
			break
		} else if strings.Contains(body, "window.livewire_token") ||
			strings.Contains(body, "Livewire 2") {
			results = append(results, common.ScanResult{
				ScanName:    lws.Name(),
				Category:    "Recon",
				Description: lws.renderStyled(fmt.Sprintf("Livewire detected: Version 2.x at %s", checkURL), "success"),
				Path:        checkURL,
				StatusCode:  resp.StatusCode,
				Detail:      lws.getVulnerabilitiesForV2(),
			})
			break
		} else if strings.Contains(body, "Livewire") || strings.Contains(body, "livewire") {
			versionText := "unable to determine version"
			if htmlDomVersion != "" {
				versionText = fmt.Sprintf("Version %s (inferred from DOM markers)", htmlDomVersion)
			}
			results = append(results, common.ScanResult{
				ScanName:    lws.Name(),
				Category:    "Recon",
				Description: fmt.Sprintf("Livewire detected at %s (%s)", checkURL, versionText),
				Path:        checkURL,
				StatusCode:  resp.StatusCode,
			})
			break
		}
	}

	// If script wasn't directly accessible but HTML had Livewire DOM markers
	if len(results) == 0 && htmlLivewireFound {
		desc := "Livewire detected via HTML DOM markers (wire:id)"
		detail := ""
		if htmlDomVersion == "3.x" {
			desc = "Livewire detected: Version 3.x (via wire:snapshot DOM marker)"
			detail = lws.getVulnerabilitiesForV3()
		} else if htmlDomVersion == "2.x" {
			desc = "Livewire detected: Version 2.x (via wire:initial-data DOM marker)"
			detail = lws.getVulnerabilitiesForV2()
		}

		results = append(results, common.ScanResult{
			ScanName:    lws.Name(),
			Category:    "Recon",
			Description: desc,
			Path:        target,
			StatusCode:  200,
			Detail:      detail,
		})
	}

	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    lws.Name(),
			Category:    "Recon",
			Description: "Livewire not detected",
			Path:        target,
			StatusCode:  200,
		})
	}

	return results
}

// getVulnerabilitiesForV2 returns a formatted list of known CVEs and vulnerabilities for Livewire v2.x
func (lws *LivewireScan) getVulnerabilitiesForV2() string {
	vulnerabilities := []string{
		"Improper Input Validation >=2.2.4, <2.2.6: https://github.com/livewire/livewire/pull/1659",
	}

	result := ""
	for _, vuln := range vulnerabilities {
		result += fmt.Sprintf("  - %s ", vuln)
	}

	return result
}

// getVulnerabilitiesForV3 returns a formatted list of known CVEs and vulnerabilities for Livewire v3.x
func (lws *LivewireScan) getVulnerabilitiesForV3() string {
	vulnerabilities := []string{
		"Cross-site Scripting (XSS) >=3.3.5, <3.4.9: https://www.cve.org/CVERecord?id=CVE-2024-21504",
	}

	result := ""
	for _, vuln := range vulnerabilities {
		result += fmt.Sprintf("  - %s\n", vuln)
	}

	return result
}

func (pvs *LivewireScan) Name() string {
	return "Livewire Scan"
}

// renderStyled applies ANSI styles to the given message based on its type
func (lws *LivewireScan) renderStyled(message, messageType string) string {
	var styledMessage string

	switch messageType {
	case "success":
		styledMessage = color.GreenString(message)
	case "error":
		styledMessage = color.RedString(message)
	case "warning":
		styledMessage = color.YellowString(message)
	default:
		styledMessage = message
	}

	return styledMessage
}

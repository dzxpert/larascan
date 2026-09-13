package recon

import (
	"fmt"
	"io"
	"net/url"
	"larascan/internal/common"
	"larascan/pkg/httpclient"
	"strings"
	"time"
)

// FrameworkDetectionScan is a struct that contains an HTTP client
type FrameworkDetectionScan struct {
	client *httpclient.Client
}

// NewFrameworkDetectionScan initializes and returns a new FrameworkDetectionScan instance
func NewFrameworkDetectionScan() *FrameworkDetectionScan {
	return &FrameworkDetectionScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Run checks for signs of the Laravel framework in the response
func (fds *FrameworkDetectionScan) Run(target string) []common.ScanResult {
	headers := map[string]string{
		"User-Agent": "LaravelScanner/1.0",
	}

	resp, err := fds.client.Get(target, headers)
	if err != nil {
		return []common.ScanResult{
			{
				ScanName:    fds.Name(),
				Category:    "Recon",
				Description: "Failed to make request",
				Path:        target,
				StatusCode:  0,
				Detail:      err.Error(),
			},
		}
	}
	defer resp.Body.Close()

	var results []common.ScanResult
	var indicators []string

	// Check for Laravel-specific headers
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" && strings.Contains(poweredBy, "PHP") {
		indicators = append(indicators, fmt.Sprintf("X-Powered-By header (%s)", poweredBy))
	}

	// Check for Laravel-specific cookies
	hasXsrf := false
	for _, cookie := range resp.Cookies() {
		if strings.EqualFold(cookie.Name, "XSRF-TOKEN") {
			hasXsrf = true
			indicators = append(indicators, "XSRF-TOKEN cookie (standard Laravel CSRF cookie)")
		} else if strings.Contains(strings.ToLower(cookie.Name), "laravel") {
			indicators = append(indicators, fmt.Sprintf("Laravel-specific cookie (%s)", cookie.Name))
		} else if strings.HasSuffix(strings.ToLower(cookie.Name), "_session") {
			indicators = append(indicators, fmt.Sprintf("Session cookie (%s)", cookie.Name))
		}
	}

	// Read response body to check for HTML markers
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err == nil {
		body := string(bodyBytes)
		if strings.Contains(body, `name="csrf-token"`) || strings.Contains(body, `name='csrf-token'`) {
			indicators = append(indicators, "CSRF token meta tag (<meta name=\"csrf-token\">)")
		}
		if strings.Contains(body, "window.Laravel") {
			indicators = append(indicators, "window.Laravel JavaScript object")
		}
		if strings.Contains(body, "wire:snapshot") || strings.Contains(body, "wire:id") || strings.Contains(body, "wire:initial-data") {
			indicators = append(indicators, "Livewire component attributes (wire:)")
		}
		if strings.Contains(body, `data-page="`) || strings.Contains(body, "window.__inertia") {
			indicators = append(indicators, "Inertia.js SPA attributes")
		}
	}

	// If not detected on the provided path, check the root URL as fallback
	if len(indicators) == 0 {
		if parsedURL, parseErr := url.Parse(target); parseErr == nil && parsedURL.Host != "" {
			rootURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
			if rootURL != strings.TrimRight(target, "/") {
				rootResp, rootErr := fds.client.Get(rootURL, headers)
				if rootErr == nil && rootResp.StatusCode == 200 {
					for _, cookie := range rootResp.Cookies() {
						if strings.EqualFold(cookie.Name, "XSRF-TOKEN") {
							hasXsrf = true
							indicators = append(indicators, "XSRF-TOKEN cookie on root domain")
						} else if strings.Contains(strings.ToLower(cookie.Name), "laravel") {
							indicators = append(indicators, fmt.Sprintf("Laravel cookie on root domain (%s)", cookie.Name))
						}
					}
					rootBodyBytes, rootReadErr := io.ReadAll(io.LimitReader(rootResp.Body, 128*1024))
					rootResp.Body.Close()
					if rootReadErr == nil {
						rootBody := string(rootBodyBytes)
						if strings.Contains(rootBody, `name="csrf-token"`) || strings.Contains(rootBody, `name='csrf-token'`) {
							indicators = append(indicators, "CSRF token meta tag on root domain")
						}
						if strings.Contains(rootBody, "window.Laravel") {
							indicators = append(indicators, "window.Laravel on root domain")
						}
						if strings.Contains(rootBody, "wire:snapshot") || strings.Contains(rootBody, "wire:id") || strings.Contains(rootBody, "livewire") {
							indicators = append(indicators, "Livewire markers on root domain")
						}
					}
				} else if rootResp != nil && rootResp.Body != nil {
					rootResp.Body.Close()
				}
			}
		}
	}

	if len(indicators) > 0 {
		desc := "Laravel framework detected"
		if len(indicators) == 1 && strings.HasPrefix(indicators[0], "X-Powered-By") {
			desc = "Possible Laravel/PHP framework detected via X-Powered-By header"
		} else if !hasXsrf && len(indicators) == 1 && strings.HasPrefix(indicators[0], "Session cookie") {
			desc = "Possible PHP/Laravel framework detected via session cookie"
		}

		results = append(results, common.ScanResult{
			ScanName:    fds.Name(),
			Category:    "Recon",
			Description: desc,
			Path:        target,
			StatusCode:  resp.StatusCode,
			Detail:      strings.Join(indicators, ", "),
		})
	} else {
		results = append(results, common.ScanResult{
			ScanName:    fds.Name(),
			Category:    "Recon",
			Description: "Laravel framework not detected",
			Path:        target,
			StatusCode:  resp.StatusCode,
		})
	}

	return results
}

func (pvs *FrameworkDetectionScan) Name() string {
	return "Framework Detection"
}

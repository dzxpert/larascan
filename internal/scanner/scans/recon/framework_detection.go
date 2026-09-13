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
		if strings.Contains(body, "/js/filament/") || strings.Contains(body, "filament") {
			indicators = append(indicators, "Filament Admin panel (Laravel)")
		}
	}

	// If not detected on the provided path, check common application endpoints as fallback
	if len(indicators) == 0 {
		cleanTarget := strings.TrimRight(target, "/")
		originBaseURL := cleanTarget
		if parsedURL, parseErr := url.Parse(cleanTarget); parseErr == nil && parsedURL.Host != "" {
			originBaseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		}

		fallbackPages := []string{
			originBaseURL + "/admin/login",
			originBaseURL + "/admin",
			originBaseURL + "/login",
			originBaseURL,
		}

		seen := make(map[string]bool)
		for _, pageURL := range fallbackPages {
			if seen[pageURL] || pageURL == cleanTarget {
				continue
			}
			seen[pageURL] = true

			fResp, fErr := fds.client.Get(pageURL, headers)
			if fErr != nil || fResp.StatusCode != 200 {
				if fResp != nil && fResp.Body != nil {
					fResp.Body.Close()
				}
				continue
			}

			for _, cookie := range fResp.Cookies() {
				if strings.EqualFold(cookie.Name, "XSRF-TOKEN") {
					hasXsrf = true
					indicators = append(indicators, fmt.Sprintf("XSRF-TOKEN cookie on %s", pageURL))
				} else if strings.Contains(strings.ToLower(cookie.Name), "laravel") {
					indicators = append(indicators, fmt.Sprintf("Laravel cookie on %s (%s)", pageURL, cookie.Name))
				}
			}

			fBodyBytes, fReadErr := io.ReadAll(io.LimitReader(fResp.Body, 128*1024))
			fResp.Body.Close()
			if fReadErr == nil {
				fBody := string(fBodyBytes)
				if strings.Contains(fBody, "/js/filament/") {
					indicators = append(indicators, fmt.Sprintf("Filament Admin panel assets on %s", pageURL))
				}
				if strings.Contains(fBody, "livewire") {
					indicators = append(indicators, fmt.Sprintf("Livewire markers on %s", pageURL))
				}
				if strings.Contains(fBody, `name="csrf-token"`) || strings.Contains(fBody, `name='csrf-token'`) {
					indicators = append(indicators, fmt.Sprintf("CSRF token meta tag on %s", pageURL))
				}
				if strings.Contains(fBody, "window.Laravel") {
					indicators = append(indicators, fmt.Sprintf("window.Laravel on %s", pageURL))
				}
			}

			if len(indicators) > 0 {
				break
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

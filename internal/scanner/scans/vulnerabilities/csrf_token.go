package vulnerabilities

import (
	"fmt"
	"io"
	"larascan/internal/common"
	"larascan/pkg/httpclient"
	"strings"
	"time"
)

type CsrfTokenScan struct {
	client *httpclient.Client
}

func NewCsrfTokenScan() *CsrfTokenScan {
	return &CsrfTokenScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

func (c *CsrfTokenScan) Run(target string) []common.ScanResult {
	// List of paths to check for CSRF tokens
	paths := []string{
		"/",
		"/login",
		"/register",
	}

	var results []common.ScanResult
	vulnerableCount := 0

	for _, path := range paths {
		url := strings.TrimRight(target, "/") + path
		resp, err := c.client.Get(url, nil)
		if err != nil {
			continue // Skip unreachable paths
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}

		// If the endpoint does not return 200 (e.g. 404 Not Found, 405 Method Not Allowed),
		// it is not an accessible HTML form and should not be reported as missing CSRF.
		if resp.StatusCode != 200 {
			continue
		}

		body := string(bodyBytes)
		lowerBody := strings.ToLower(body)

		// Check if page contains an HTML form
		hasForm := strings.Contains(lowerBody, "<form")
		hasPostForm := hasForm && (strings.Contains(lowerBody, `method="post"`) || strings.Contains(lowerBody, `method='post'`) || strings.Contains(lowerBody, "method=post"))

		// Check for CSRF protections:
		// 1. Hidden form input _token / csrf_token
		hasTokenInput := strings.Contains(body, `name="_token"`) ||
			strings.Contains(body, `name='_token'`) ||
			strings.Contains(body, `name="csrf_token"`) ||
			strings.Contains(body, `name='csrf_token'`)

		// 2. CSRF meta tag
		hasMetaTag := strings.Contains(lowerBody, `name="csrf-token"`) || strings.Contains(lowerBody, `name='csrf-token'`)

		// 3. XSRF-TOKEN cookie in response cookies
		hasXsrfCookie := false
		for _, cookie := range resp.Cookies() {
			if strings.EqualFold(cookie.Name, "XSRF-TOKEN") {
				hasXsrfCookie = true
				break
			}
		}

		// 4. Livewire / Alpine CSRF markers
		hasLivewireCsrf := strings.Contains(body, "data-csrf") || strings.Contains(body, "wire:initial-data")

		if hasTokenInput || hasMetaTag || hasXsrfCookie || hasLivewireCsrf {
			var details []string
			if hasTokenInput {
				details = append(details, "form _token input")
			}
			if hasMetaTag {
				details = append(details, "meta csrf-token tag")
			}
			if hasXsrfCookie {
				details = append(details, "XSRF-TOKEN cookie")
			}
			if hasLivewireCsrf {
				details = append(details, "Livewire token")
			}

			results = append(results, common.ScanResult{
				ScanName:    c.Name(),
				Category:    "Vulnerabilities",
				Description: "CSRF protection found",
				Path:        url,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("Protected via: %s", strings.Join(details, ", ")),
			})
		} else if hasPostForm {
			// POST form with NO CSRF protection is a potential vulnerability
			vulnerableCount++
			results = append(results, common.ScanResult{
				ScanName:    c.Name(),
				Category:    "Vulnerabilities",
				Description: "POST form without CSRF token detected",
				Path:        url,
				StatusCode:  resp.StatusCode,
				Detail:      "An HTML form with method=POST was found but does not contain a CSRF token or meta tag.",
			})
		}
	}

	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    c.Name(),
			Category:    "Vulnerabilities",
			Description: "No accessible HTML forms found missing CSRF tokens",
			Path:        target,
			StatusCode:  200,
		})
	} else if vulnerableCount == 0 {
		// All scanned forms had CSRF protection
	}

	return results
}

func (pvs *CsrfTokenScan) Name() string {
	return "CSRF Token"
}

package vulnerabilities

import (
	"fmt"
	"io"
	"larascan/internal/common"
	"larascan/pkg/httpclient"
	"strings"
	"time"
)

type DebugModeScan struct {
	client *httpclient.Client
}

func NewDebugModeScan() *DebugModeScan {
	return &DebugModeScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Run checks if the Laravel debug mode is enabled by triggering an error page
func (d *DebugModeScan) Run(target string) []common.ScanResult {
	// Intentionally trigger an error/404 to check for debug mode
	errorURL := strings.TrimRight(target, "/") + "/nonexistentpage"

	resp, err := d.client.Get(errorURL, nil)
	if err != nil {
		return []common.ScanResult{
			{
				ScanName:    d.Name(),
				Category:    "Vulnerabilities",
				Description: "Request to trigger error page failed",
				Path:        errorURL,
				StatusCode:  0,
				Detail:      err.Error(),
			},
		}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return []common.ScanResult{
			{
				ScanName:    d.Name(),
				Category:    "Vulnerabilities",
				Description: "Failed to read response body from error page",
				Path:        errorURL,
				StatusCode:  resp.StatusCode,
				Detail:      err.Error(),
			},
		}
	}
	body := string(bodyBytes)

	// Check for signatures of debug mode (Ignition, Whoops, stack traces)
	isDebugEnabled := strings.Contains(body, "Whoops, looks like something went wrong.") ||
		strings.Contains(body, "Whoops\\Exception") ||
		strings.Contains(body, "window.ignite") ||
		strings.Contains(body, "ignition-app") ||
		strings.Contains(body, "flare-client") ||
		strings.Contains(body, "NotFoundHttpException") ||
		strings.Contains(body, "MethodNotAllowedHttpException") ||
		strings.Contains(body, "vendor/laravel/framework") ||
		(strings.Contains(body, "stack-trace") && strings.Contains(body, "exception"))

	var results []common.ScanResult

	if isDebugEnabled {
		results = append(results, common.ScanResult{
			ScanName:    d.Name(),
			Category:    "Vulnerabilities",
			Description: "Debug mode is enabled!",
			Path:        errorURL,
			StatusCode:  resp.StatusCode,
			Detail:      "The application displayed a detailed error/debug page with stack trace or Ignition interface, indicating that debug mode is active.",
		})
	} else {
		results = append(results, common.ScanResult{
			ScanName:    d.Name(),
			Category:    "Vulnerabilities",
			Description: "Debug mode is disabled.",
			Path:        errorURL,
			StatusCode:  resp.StatusCode,
			Detail:      fmt.Sprintf("Status %d returned without exposing stack traces or debug information.", resp.StatusCode),
		})
	}

	return results
}

// Name returns the name of the scan
func (d *DebugModeScan) Name() string {
	return "Debug Mode"
}

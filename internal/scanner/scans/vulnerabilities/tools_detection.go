// internal/scanner/scans/vulnerabilities/tools_detection.go
package vulnerabilities

import (
	"fmt"
	"io"
	"larascan/pkg/httpclient"
	"strings"
	"time"

	"larascan/internal/common"
)

// ToolsDetectionScan is a struct that contains an HTTP client
type ToolsDetectionScan struct {
	client *httpclient.Client
}

// NewToolsDetectionScan initializes and returns a new ToolsDetectionScan instance
func NewToolsDetectionScan() *ToolsDetectionScan {
	return &ToolsDetectionScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

type toolDefinition struct {
	path       string
	name       string
	checkBody  func(body string) bool
	allowLogin bool
}

// Run checks for publicly exposed tools and admin interfaces on the target server
func (tds *ToolsDetectionScan) Run(target string) []common.ScanResult {
	tools := []toolDefinition{
		{
			path: "/_debugbar",
			name: "Laravel Debugbar",
			checkBody: func(body string) bool {
				b := strings.ToLower(body)
				return strings.Contains(b, "phpdebugbar") || strings.Contains(b, "laravel debugbar")
			},
		},
		{
			path: "/telescope",
			name: "Laravel Telescope",
			checkBody: func(body string) bool {
				return strings.Contains(body, "Telescope") && (strings.Contains(body, "telescope-data") || strings.Contains(body, "window.Telescope"))
			},
		},
		{
			path: "/horizon",
			name: "Laravel Horizon",
			checkBody: func(body string) bool {
				return strings.Contains(body, "Laravel Horizon") || strings.Contains(body, "window.Horizon")
			},
		},
		{
			path:       "/nova",
			name:       "Laravel Nova",
			allowLogin: true,
			checkBody: func(body string) bool {
				return strings.Contains(body, "Laravel Nova") || strings.Contains(body, "Nova.config")
			},
		},
		{
			path:       "/admin",
			name:       "Admin Panel",
			allowLogin: true,
			checkBody: func(body string) bool {
				b := strings.ToLower(body)
				return strings.Contains(b, "dashboard") || strings.Contains(b, "admin panel")
			},
		},
		{
			path: "/phpmyadmin",
			name: "phpMyAdmin",
			checkBody: func(body string) bool {
				return strings.Contains(body, "pma_username") || strings.Contains(body, "phpMyAdmin")
			},
		},
		{
			path: "/_ignition/execute-solution",
			name: "Ignition Execute Solution",
			checkBody: func(body string) bool {
				return strings.Contains(body, "solution") || strings.Contains(body, "ignition")
			},
		},
		{
			path: "/_ignition/health-check",
			name: "Ignition Health Check",
			checkBody: func(body string) bool {
				return strings.Contains(body, "can_execute_commands") || strings.Contains(body, "ignition")
			},
		},
	}

	var exposedTools []string
	var existingTools []string
	var loginPanels []string

	for _, tool := range tools {
		url := strings.TrimRight(target, "/") + tool.path
		resp, err := tds.client.Get(url, nil)
		if err != nil {
			continue // Skip if the request fails
		}

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		bodyStr := string(bodyBytes)
		finalURL := ""
		if resp.Request != nil && resp.Request.URL != nil {
			finalURL = resp.Request.URL.String()
		}
		resp.Body.Close()

		isLogin := strings.Contains(strings.ToLower(finalURL), "/login") ||
			strings.Contains(strings.ToLower(finalURL), "/auth") ||
			strings.Contains(strings.ToLower(finalURL), "/signin") ||
			strings.Contains(strings.ToLower(bodyStr), `type="password"`) ||
			strings.Contains(strings.ToLower(bodyStr), `type='password'`)

		if resp.StatusCode == 200 {
			if tool.allowLogin && isLogin {
				loginPanels = append(loginPanels, fmt.Sprintf("%s (redirected to %s)", tool.path, finalURL))
			} else if tool.checkBody(bodyStr) {
				exposedTools = append(exposedTools, tool.path)
			}
		} else if resp.StatusCode == 403 || resp.StatusCode == 401 {
			existingTools = append(existingTools, fmt.Sprintf("%s (Status: %d)", tool.path, resp.StatusCode))
		}
	}

	var results []common.ScanResult

	if len(exposedTools) > 0 {
		results = append(results, common.ScanResult{
			ScanName:    tds.Name(),
			Category:    "Vulnerabilities",
			Description: "Publicly exposed tools and admin interfaces detected",
			Path:        strings.Join(exposedTools, ", "),
			StatusCode:  200,
		})
	} else {
		results = append(results, common.ScanResult{
			ScanName:    tds.Name(),
			Category:    "Vulnerabilities",
			Description: "No publicly exposed tools or admin interfaces detected",
			Path:        target,
			StatusCode:  200,
		})
	}

	if len(loginPanels) > 0 {
		results = append(results, common.ScanResult{
			ScanName:    tds.Name(),
			Category:    "Recon",
			Description: "Protected admin/management login interfaces found",
			Path:        strings.Join(loginPanels, ", "),
			StatusCode:  200,
		})
	}

	if len(existingTools) > 0 {
		results = append(results, common.ScanResult{
			ScanName:    tds.Name(),
			Category:    "Recon",
			Description: "Tools and admin interfaces exist but are access-restricted",
			Path:        strings.Join(existingTools, ", "),
			StatusCode:  403,
		})
	}

	return results
}

func (tds *ToolsDetectionScan) Name() string {
	return "laravel Tools"
}

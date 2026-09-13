package vulnerabilities

import (
	"fmt"
	"io"
	"larascan/internal/common"
	"larascan/pkg/httpclient"
	"strings"
	"time"
)

// SensitiveFilesScan is a struct that contains an HTTP client
type SensitiveFilesScan struct {
	client *httpclient.Client
}

// NewSensitiveFilesScan initializes and returns a new SensitiveFilesScan instance
func NewSensitiveFilesScan() *SensitiveFilesScan {
	return &SensitiveFilesScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Run checks for the presence of sensitive files and directories on the target server
func (sfs *SensitiveFilesScan) Run(target string) []common.ScanResult {
	// List of potentially sensitive files and directories to check
	paths := []string{
		"/.env",
		"/.env.local",
		"/.env.production",
		"/.env.staging",
		"/.env.backup",
		"/.env.old",
		"/.env.bak",
		"/.env.save",
		"/.git/config",
		"/.svn/wc.db",
		"/.DS_Store",
		"/.htaccess",
		"/.bash_history",
		"/.bashrc",
		"/.ssh/id_rsa",
		"/.ssh/known_hosts",
		"/composer.json",
		"/composer.lock",
		"/storage/logs/laravel.log",
		"/vendor/",
		"/node_modules/",
	}

	var exposed []string
	var results []common.ScanResult

	for _, path := range paths {
		url := strings.TrimRight(target, "/") + path
		resp, err := sfs.client.Get(url, nil)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			continue
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		resp.Body.Close()
		if err != nil || len(bodyBytes) == 0 {
			continue
		}

		bodyStr := string(bodyBytes)
		lowerBody := strings.ToLower(bodyStr)

		// Filter out SPA / HTML fallback responses (custom 404s returning 200 OK)
		isHTML := strings.Contains(lowerBody, "<!doctype html") ||
			strings.Contains(lowerBody, "<html") ||
			strings.Contains(lowerBody, "<head")

		isLegitExposure := false

		if strings.HasPrefix(path, "/.env") {
			// Real .env files contain key=value pairs, not full HTML documents
			if !isHTML && (strings.Contains(bodyStr, "APP_KEY=") ||
				strings.Contains(bodyStr, "APP_NAME=") ||
				strings.Contains(bodyStr, "DB_CONNECTION=") ||
				strings.Contains(bodyStr, "DB_HOST=") ||
				strings.Contains(bodyStr, "APP_ENV=")) {
				isLegitExposure = true
			}
		} else if path == "/.git/config" {
			if !isHTML && (strings.Contains(bodyStr, "[core]") || strings.Contains(bodyStr, "[remote")) {
				isLegitExposure = true
			}
		} else if path == "/composer.json" {
			if !isHTML && (strings.Contains(bodyStr, `"require"`) || strings.Contains(bodyStr, `"autoload"`)) {
				isLegitExposure = true
			}
		} else if path == "/composer.lock" {
			if !isHTML && strings.Contains(bodyStr, `"packages"`) {
				isLegitExposure = true
			}
		} else if path == "/storage/logs/laravel.log" {
			if !isHTML && (strings.Contains(bodyStr, ".INFO:") || strings.Contains(bodyStr, ".ERROR:") || strings.Contains(bodyStr, "Stack trace:")) {
				isLegitExposure = true
			}
		} else if !isHTML {
			// For other non-HTML files
			isLegitExposure = true
		}

		if isLegitExposure {
			exposed = append(exposed, url)
			results = append(results, common.ScanResult{
				ScanName:    sfs.Name(),
				Category:    "Vulnerabilities",
				Description: "Sensitive file or directory exposed",
				Path:        url,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("Exposed path: %s", url),
			})
		}
	}

	if len(exposed) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    sfs.Name(),
			Category:    "Vulnerabilities",
			Description: "No sensitive files or directories detected",
			Path:        target,
			StatusCode:  200,
		})
	}

	return results
}

func (pvs *SensitiveFilesScan) Name() string {
	return "Sensitive Files"
}

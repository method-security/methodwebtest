package general

import (
	"context"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

func PerformHeaderMisconfigurationEscape(ctx context.Context, config *methodwebtest.HeaderMisconfigurationConfig) *methodwebtest.Report {
	targetHeaderPayloadsList := [][]map[string]string{}
	for range config.Targets {
		targetHeaderPayloadsList = append(targetHeaderPayloadsList, generateEscapeHeaders())
	}

	headerMisconfigurationConfig := methodwebtest.HeaderMisconfigurationEngineConfig{
		Targets:         config.Targets,
		Method:          methodwebtest.HttpMethodGet,
		Payloads:        targetHeaderPayloadsList,
		EventType:       methodwebtest.NewEventTypeFromHeaderEvent(methodwebtest.HeaderEventEscape),
		FollowRedirects: false,
		Timeout:         config.Timeout,
	}

	report := utils.RunHeaderMisconfigurationEngine(ctx, &headerMisconfigurationConfig)
	detectHeaderMisconfigurationEscape(report)
	return report
}

func generateEscapeHeaders() []map[string]string {
	return []map[string]string{
		// Injection of additional headers within a single header value.
		// Positive hit: The server accepts and interprets the injected header (`X-Injected-Header:
		// injected-value`) as a separate header.
		{"X-Custom-Header": "injected\r\nX-Injected-Header: injected-value"},

		// Content-Type header injection with Content-Length.
		// Positive hit: The server interprets the injected `Content-Length: 0` header,
		// potentially causing issues like ignoring payload data.
		{"Content-Type": "application/json\r\nContent-Length: 0"},

		// Header values with escaped characters and special formatting.
		// Positive hit: The server mishandles escaped backslashes and quotes, either including them in responses
		// or causing misinterpretation of header data.
		{"X-User\\Name": "User\\Value", "X-Custom-Header": "value with \"quotes\" and \\backslashes\\"},
	}
}

func detectHeaderMisconfigurationEscape(report *methodwebtest.Report) {
	for _, target := range report.Targets {
		for _, attempt := range target.Attempts {
			finding := false

			if attempt.Request == nil || attempt.Request.ResponseHeaders == nil {
				continue
			}
			headers := attempt.Request.ResponseHeaders

			// Check if injected headers are present in the response.
			if injectedHeader, exists := headers["X-Injected-Header"]; exists {
				if injectedHeader == "injected-value" {
					finding = true
				}
			}

			// Check if Content-Length header injection is reflected or interpreted.
			if contentLength, exists := headers["Content-Length"]; exists {
				if contentLength == "0" {
					finding = true
				}
			}

			// Check for escaped characters mishandling.
			for key, value := range headers {
				if strings.Contains(key, "\\") || strings.Contains(value, "\\") || strings.Contains(value, "\"") {
					finding = true
					break
				}
			}

			attempt.Finding = &finding
		}
	}
}

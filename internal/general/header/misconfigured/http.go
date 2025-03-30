package general

import (
	"context"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

func PerformHeaderMisconfigurationHTTP(ctx context.Context, config *methodwebtest.HeaderMisconfigurationConfig) *methodwebtest.Report {
	targetHeaderPayloadsList := [][]map[string]string{}
	for _, target := range config.Targets {
		targetHeaderPayloadsList = append(targetHeaderPayloadsList, generateHTTPHeaders(target))
	}

	headerMisconfigurationConfig := methodwebtest.HeaderMisconfigurationEngineConfig{
		Targets:         config.Targets,
		Method:          methodwebtest.HttpMethodOptions,
		Payloads:        targetHeaderPayloadsList,
		EventType:       methodwebtest.NewEventTypeFromHeaderEvent(methodwebtest.HeaderEventHttp),
		FollowRedirects: false,
		Timeout:         config.Timeout,
	}

	report := utils.RunHeaderMisconfigurationEngine(ctx, &headerMisconfigurationConfig)
	detectHTTPMethodInjection(report)
	return report
}

func generateHTTPHeaders(target string) []map[string]string {
	return []map[string]string{
		// Empty Options request
		{"": ""},

		// Overly permissive HTTP methods.
		// Positive hit: The server allows `TRACE` and `TRACK` methods, which can enable dangerous actions
		// like Cross-Site Tracing (XST).
		{"Access-Control-Allow-Methods": "GET, POST, DELETE, TRACE, TRACK"},

		// Overly permissive HTTP methods.
		// Positive hit: The server allows `TRACE` and `TRACK` methods, which can enable dangerous actions
		// like Cross-Site Tracing (XST).
		{
			"Origin":                       target,
			"Access-Control-Allow-Methods": "GET, POST, DELETE, TRACE, TRACK",
		},
	}
}

func detectHTTPMethodInjection(report *methodwebtest.Report) {
	for _, target := range report.Targets {
		if target.Attempts == nil {
			continue
		}
		for _, attempt := range target.Attempts {
			finding := false

			if attempt.Request == nil || attempt.Request.ResponseHeaders == nil {
				continue
			}
			headers := attempt.Request.ResponseHeaders

			// Check if "Access-Control-Allow-Methods" includes unsafe methods.
			if methods, exists := headers["Access-Control-Allow-Methods"]; exists {
				unsafeMethods := []string{"TRACE", "TRACK", "DELETE"}
				for _, method := range unsafeMethods {
					if strings.Contains(methods, method) {
						finding = true
						break
					}
				}
			}

			attempt.Finding = &finding
		}
	}
}

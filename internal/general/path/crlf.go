package general

import (
	"context"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

func PerformPathCrlfInjection(ctx context.Context, config *methodwebtest.PathCrlfConfig) *methodwebtest.Report {
	engineConfig := methodwebtest.PathTraversalEngineConfig{
		Targets:           config.Targets,
		Paths:             []string{generateClrfInjectionParams(config.HeaderName, config.HeaderValue)},
		ResponseCodes:     "200-299",
		IgnoreBaseContent: true,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
		SuccessfulOnly:    false,
	}

	report := utils.RunPathTraversalEngine(ctx, &engineConfig)
	detectCrlfInjection(config.HeaderName, config.HeaderValue, report)
	report.Config = methodwebtest.NewEngineConfigFromPathTraversalEngineConfig(&engineConfig)
	return report
}

func generateClrfInjectionParams(headerName string, headerValue string) string {
	return "/\r\n" + headerName + ": " + headerValue
}

func detectCrlfInjection(headerName string, headerValue string, report *methodwebtest.Report) {
	for _, target := range report.Targets {
		for _, attempt := range target.Attempts {
			attempt.Request.EventType = []*methodwebtest.EventType{methodwebtest.NewEventTypeFromPathEvent(methodwebtest.PathEventCrlf)}
			finding := false

			// Check if the injected header is in the response headers
			if attempt.Request.ResponseHeaders != nil {
				if _, exists := attempt.Request.ResponseHeaders[headerName]; exists {
					finding = true
				}
			}

			// Check if the response body contains evidence of the injection
			if attempt.Request.ResponseBody != nil {
				body := *attempt.Request.ResponseBody
				if strings.Contains(body, headerValue) {
					finding = true
				}
			}

			attempt.Finding = &finding
		}
	}
}

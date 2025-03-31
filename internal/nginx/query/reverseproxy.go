package nginx

import (
	"context"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

func PerformQueryReverseProxyInjection(ctx context.Context, config *methodwebtest.QueryReverseProxyConfig) *methodwebtest.Report {
	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            methodwebtest.HttpMethodGet,
		Paths:             []string{"/"},
		BaselinePayload:   map[string]string{"": ""},
		InjectedPayloads:  generateReverseProxyQueryInjectionParams(config.RedirectAddress),
		InjectionLocation: methodwebtest.InjectionLocationQuery,
		EventType:         methodwebtest.NewEventTypeFromQueryEvent(methodwebtest.QueryEventRedirect),
		FollowRedirects:   false,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	detectRedirectWithResponseInfo(report, config.RedirectAddress)
	return report
}

func generateReverseProxyQueryInjectionParams(redirectAddress string) []map[string]string {
	return []map[string]string{
		{"url": redirectAddress},
		{"redirect": redirectAddress},
	}
}

func detectRedirectWithResponseInfo(report *methodwebtest.Report, redirectAddress string) {
	// Check for redirection status codes (3xx)
	for _, target := range report.Targets {
		for _, attempt := range target.Attempts {
			finding := false
			if attempt.Request.StatusCode != nil && *attempt.Request.StatusCode >= 300 && *attempt.Request.StatusCode < 400 {
				// Check if the responseHeaders contain a "Location" header
				if attempt.Request.ResponseHeaders != nil {
					if location, exists := attempt.Request.ResponseHeaders["Location"]; exists && location != "" {
						finding = strings.Contains(redirectAddress, location)
					}
				}
			}
			attempt.Finding = &finding
		}
	}
}

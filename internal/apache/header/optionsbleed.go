package header

import (
	"context"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

func PerformApacheHeaderOptionsBleedInjection(ctx context.Context, config *methodwebtest.HeaderOptionsBleedConfig) *methodwebtest.Report {
	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            methodwebtest.HttpMethodOptions,
		Paths:             []string{""},
		InjectedPayloads:  []map[string]string{{"Access-Control-Request-Method": "GET"}},
		InjectionLocation: methodwebtest.InjectionLocationHeader,
		EventType:         methodwebtest.NewEventTypeFromHeaderEvent(methodwebtest.HeaderEventOptionsbleed),
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	detectOptionsBleed(report)
	report.Config = methodwebtest.NewEngineConfigFromInjectionEngineConfig(&injectionConfig)
	return report
}

func detectOptionsBleed(report *methodwebtest.Report) {
	corruptedIndicators := []string{
		"@@@@", "???", "\x00", "\xff", "�",
	}
	for _, target := range report.Targets {
		if target.Attempts == nil {
			continue
		}
		for _, attempt := range target.Attempts {
			finding := false
			allowHeader := ""
			exists := false
			// Normalize headers to check case-insensitively
			for headerKey, headerValue := range attempt.Request.ResponseHeaders {
				if strings.ToLower(headerKey) == "allow" {
					allowHeader = headerValue
					exists = true
					break
				}
			}
			// If "Allow" header is missing, it's suspicious
			if !exists {
				finding = true
			} else {
				// Look for corrupted indicators
				for _, indicator := range corruptedIndicators {
					if strings.Contains(allowHeader, indicator) {
						finding = true
						break
					}
				}
			}
			attempt.Finding = &finding
		}
	}
}

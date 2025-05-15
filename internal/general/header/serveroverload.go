package general

import (
	"context"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

func PerformHeaderServerOverloadInjection(ctx context.Context, config *methodwebtest.HeaderServerOverloadConfig) *methodwebtest.Report {
	generatedPayloads := generateServerOverloadHeaders(config.HeaderNames, config.PayloadSize)

	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            methodwebtest.HttpMethodGet,
		Paths:             []string{"/"},
		BaselinePayload:   map[string]string{"": ""},
		InjectedPayloads:  generatedPayloads,
		InjectionLocation: methodwebtest.InjectionLocationHeader,
		EventType:         methodwebtest.NewEventTypeFromHeaderEvent(methodwebtest.HeaderEventServeroverload),
		FollowRedirects:   false,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	detectServerOverload(report)
	return report
}

func generateServerOverloadHeaders(headerNames []string, payloadSize int) []map[string]string {
	headers := []map[string]string{}
	payload := strings.Repeat("A", payloadSize)

	for _, headerName := range headerNames {
		headers = append(headers, map[string]string{headerName: payload})
	}

	return headers
}

func detectServerOverload(report *methodwebtest.Report) {
	for _, target := range report.Targets {
		baselineError := false

		if target.BaselineAttempt != nil && target.BaselineAttempt.Request.StatusCode != nil && *target.BaselineAttempt.Request.StatusCode > 400 {
			baselineError = true
		}
		for _, attempt := range target.Attempts {
			finding := false
			if attempt.Request.StatusCode != nil && *attempt.Request.StatusCode >= 500 && *attempt.Request.StatusCode < 600 && !baselineError {
				finding = true
			}
			if attempt.Request.ResponseBody != nil {
				body := *attempt.Request.ResponseBody
				if strings.Contains(body, "internal server error") ||
					strings.Contains(body, "service unavailable") ||
					strings.Contains(body, "stack trace") && !baselineError {
					finding = true
				}
			}
			attempt.Finding = &finding
		}
	}
}

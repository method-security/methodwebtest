package general

import (
	"context"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

// SQL error-based payloads
var sqliBooleanPayloads = []string{
	`'--`,
	`' OR 'a'='a`,
	`' OR 1=1`,
	`' OR TRUE`,
}

func PerformSqliBooleanInjection(ctx context.Context, config *methodwebtest.MultiInjectionConfig) *methodwebtest.Report {
	generatedInjectionPayloads := utils.GenerateInjectionPayloads(sqliBooleanPayloads, config.VariableData)
	generatedBaselinePayloads := utils.GenerateBaselinePayloads(config.VariableData)

	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            config.Method,
		Paths:             []string{"/"},
		BaselinePayload:   generatedBaselinePayloads,
		InjectedPayloads:  generatedInjectionPayloads,
		InjectionLocation: config.InjectionLocation,
		EventType:         methodwebtest.NewEventTypeFromMultiEvent(methodwebtest.MultiEventSqliboolean),
		FollowRedirects:   true,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	checkForSqliBooleanBased(report)
	return report
}

func checkForSqliBooleanBased(report *methodwebtest.Report) {
	for _, target := range report.Targets {
		if target.Attempts == nil {
			continue
		}
		if target.BaselineAttempt == nil ||
			target.BaselineAttempt.Request == nil ||
			target.BaselineAttempt.Request.ResponseBody == nil {
			continue
		}
		baselineBodySize := len(*target.BaselineAttempt.Request.ResponseBody)

		for _, attempt := range target.Attempts {
			finding := false
			if attempt.Request == nil {
				continue
			}
			if attempt.Request.ResponseBody == nil {
				continue
			}
			responseBody := *attempt.Request.ResponseBody
			if float64(len(responseBody)) > float64(baselineBodySize)*1.2 {
				finding = true
			}
			attempt.Finding = &finding
		}
	}
}

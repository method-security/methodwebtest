package general

import (
	"context"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

var SSTIPayloads = []string{
	"${7*7}",
	"{{7*7}}",
	"<%= 7 * 7 %>",
	"#{ 7 * 7 }",
	"${{7*7}}",
}

func PerformSSTIInjection(ctx context.Context, config *methodwebtest.MultiInjectionConfig) *methodwebtest.Report {
	generatedPayloads := utils.GenerateInjectionPayloads(SSTIPayloads, config.VariableData)

	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            config.Method,
		Paths:             []string{"/"},
		InjectedPayloads:  generatedPayloads,
		InjectionLocation: config.InjectionLocation,
		EventType:         methodwebtest.NewEventTypeFromMultiEvent(methodwebtest.MultiEventSsti),
		FollowRedirects:   true,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	checkForSSTI(report)
	return report
}

func checkForSSTI(report *methodwebtest.Report) {
	for _, target := range report.Targets {
		if target.Attempts == nil {
			continue
		}
		for _, attempt := range target.Attempts {
			if attempt.Request == nil || attempt.Request.ResponseBody == nil {
				continue
			}
			finding := false
			if strings.Contains(*attempt.Request.ResponseBody, "49") {
				finding = true
			}
			if !finding && attempt.Request.ResponseHeaders != nil {
				for _, headerValue := range attempt.Request.ResponseHeaders {
					if strings.Contains(headerValue, "49") {
						finding = true
					}
				}
			}
			attempt.Finding = &finding
		}
	}
}

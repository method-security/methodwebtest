package general

import (
	"context"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

var commandEchoPayloads = []string{
	`&& echo "cmd injection"`, // Basic echo command
	`| echo "cmd injection"`,  // Pipe to echo
	`; echo "cmd injection"`,  // Semicolon to chain echo
	`|| echo "cmd injection"`, // Logical OR with echo
	`& echo "cmd injection"`,  // Background echo
	`$(echo "cmd injection")`, // Command substitution echo
}

func PerformCommandEchoInjection(ctx context.Context, config *methodwebtest.MultiInjectionConfig) *methodwebtest.Report {
	generatedInjectionPayloads := utils.GenerateInjectionPayloads(commandEchoPayloads, config.VariableData)

	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            config.Method,
		Paths:             []string{"/"},
		InjectedPayloads:  generatedInjectionPayloads,
		InjectionLocation: config.InjectionLocation,
		EventType:         methodwebtest.NewEventTypeFromMultiEvent(methodwebtest.MultiEventCommandecho),
		FollowRedirects:   true,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	checkForCommandEcho(report)
	return report
}

func checkForCommandEcho(report *methodwebtest.Report) {
	for _, target := range report.Targets {
		if target.Attempts == nil {
			continue
		}
		for _, attempt := range target.Attempts {
			if attempt.Request == nil || attempt.Request.ResponseBody == nil {
				continue
			}
			responseBody := *attempt.Request.ResponseBody

			finding := false
			// Check if the response body contains the expected echoed string
			if strings.Contains(responseBody, "cmd injection") {
				finding = true
			}
			attempt.Finding = &finding

		}
	}
}

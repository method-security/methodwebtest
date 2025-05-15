package general

import (
	"context"
	"time"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

var commandTimeDelayPayloads = []string{
	`&& sleep 5`, // Basic sleep command
	`| sleep 5`,  // Pipe to sleep
	`; sleep 5`,  // Semicolon to chain sleep
	`|| sleep 5`, // Logical OR with sleep
	`& sleep 5`,  // Background sleep
	`$(sleep 5)`, // Command substitution sleep
}

func PerformCommandTimeDelayInjection(ctx context.Context, config *methodwebtest.MultiInjectionConfig) *methodwebtest.Report {
	generatedInjectionPayloads := utils.GenerateInjectionPayloads(commandTimeDelayPayloads, config.VariableData)

	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            config.Method,
		Paths:             []string{"/"},
		InjectedPayloads:  generatedInjectionPayloads,
		InjectionLocation: config.InjectionLocation,
		EventType:         methodwebtest.NewEventTypeFromMultiEvent(methodwebtest.MultiEventCommandtimedelay),
		FollowRedirects:   true,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	checkForCommandTimeDelay(report, 4000)
	return report
}

func checkForCommandTimeDelay(report *methodwebtest.Report, delayThreshold time.Duration) {
	for _, target := range report.Targets {
		if target.Attempts == nil {
			continue
		}
		for _, attempt := range target.Attempts {
			if attempt.Request == nil || attempt.Request.StatusCode == nil {
				continue
			}
			finding := false
			if *attempt.Request.StatusCode >= 500 {
				finding = false
				attempt.Finding = &finding
				continue
			}
			startTime := attempt.TimeSent
			endTime := attempt.TimeReceived
			responseTime := endTime.Sub(startTime)
			finding = responseTime > delayThreshold*time.Millisecond
			attempt.Finding = &finding

		}
	}
}

package general

import (
	"context"
	"time"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

var sqliTimeDelayPayloads = []string{
	`'OR SLEEP(5)--`,
	`'OR pg_sleep(5)--`,
	`'WAITFOR DELAY '00:00:05'--`,
	`'OR IF(1=1, SLEEP(5), 0)--`,
}

func PerformSQLiTimeDelayInjection(ctx context.Context, config *methodwebtest.MultiInjectionConfig) *methodwebtest.Report {
	generatedInjectionPayloads := utils.GenerateInjectionPayloads(sqliTimeDelayPayloads, config.VariableData)

	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            config.Method,
		Paths:             []string{"/"},
		InjectedPayloads:  generatedInjectionPayloads,
		InjectionLocation: config.InjectionLocation,
		EventType:         methodwebtest.NewEventTypeFromMultiEvent(methodwebtest.MultiEventSqlitimedelay),
		FollowRedirects:   true,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	checkForSQLiTimeDelay(report, 4000)
	return report
}

func checkForSQLiTimeDelay(report *methodwebtest.Report, delayThreshold time.Duration) {
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

package general

import (
	"context"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

// Escape character payloads
var escapeCharacterPayloads = []string{
	`'`,
	`;`,
	`\\`,
	`\'`,
	`\"`,
}

var errorPhrases = []string{
	"error",
	"syntax error",
	"unclosed quotation mark",
	"unknown column",
	"near",
	"unexpected token",
	"error in your SQL syntax",
	"missing right parenthesis",
	"quoted string not properly terminated",
	"Internal Server Error",
}

func PerformSqliEscapeCharacterInjection(ctx context.Context, config *methodwebtest.MultiInjectionConfig) *methodwebtest.Report {
	//generate baseline payloads
	generatedBaselinePayloads := utils.GenerateBaselinePayloads(config.VariableData)
	generatedInjectionPayloads := utils.GenerateInjectionPayloads(escapeCharacterPayloads, config.VariableData)

	// Configure the injection engine
	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            config.Method,
		Paths:             []string{"/"},
		BaselinePayload:   generatedBaselinePayloads,
		InjectedPayloads:  generatedInjectionPayloads,
		InjectionLocation: config.InjectionLocation,
		EventType:         methodwebtest.NewEventTypeFromMultiEvent(methodwebtest.MultiEventSqliescape),
		FollowRedirects:   true,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	// Run the injection engine
	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	checkForEscapeCharacterHandling(report)
	return report
}

func checkForEscapeCharacterHandling(report *methodwebtest.Report) {
	for _, target := range report.Targets {
		if target.Attempts == nil {
			continue
		}
		baselineError := false

		if target.BaselineAttempt != nil && target.BaselineAttempt.Request.StatusCode != nil && *target.BaselineAttempt.Request.StatusCode > 400 {
			baselineError = true
		} else {
			if target.BaselineAttempt != nil {
				responseBody := *target.BaselineAttempt.Request.ResponseBody
				for _, phrase := range errorPhrases {
					if containsPhrase(responseBody, phrase) {
						baselineError = true
					}
				}
			}
		}
		for _, attempt := range target.Attempts {
			if attempt.Request == nil || attempt.Request.StatusCode == nil {
				continue
			}

			finding := false
			if !baselineError {
				// Check for error status code
				if *attempt.Request.StatusCode >= 400 {
					finding = true
				}
				// Check response body for error phrases
				if !finding && attempt.Request.ResponseBody != nil {
					responseBody := *attempt.Request.ResponseBody
					for _, phrase := range errorPhrases {
						if containsPhrase(responseBody, phrase) {
							finding = true
							break
						}
					}
				}
			}

			attempt.Finding = &finding
		}
	}

}

// Helper function to check if a response contains any of the error phrases
func containsPhrase(responseBody string, phrase string) bool {
	return strings.Contains(strings.ToLower(responseBody), strings.ToLower(phrase))
}

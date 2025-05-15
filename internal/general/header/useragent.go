package general

import (
	"context"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

func PerformHeaderUserAgentInjection(ctx context.Context, config *methodwebtest.HeaderUserAgentConfig) *methodwebtest.Report {
	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            methodwebtest.HttpMethodGet,
		Paths:             []string{"/"},
		InjectedPayloads:  []map[string]string{{"User-Agent": config.AgentHeader}},
		InjectionLocation: methodwebtest.InjectionLocationHeader,
		EventType:         methodwebtest.NewEventTypeFromHeaderEvent(methodwebtest.HeaderEventUseragent),
		FollowRedirects:   true,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	return report
}

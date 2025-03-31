package general

import (
	"context"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

func PerformHeaderMisconfigurationSensitiveExposed(ctx context.Context, config *methodwebtest.HeaderMisconfigurationConfig) *methodwebtest.Report {
	targetHeaderPayloadsList := [][]map[string]string{}
	for _, target := range config.Targets {
		targetHeaderPayloadsList = append(targetHeaderPayloadsList, generateSensitiveExposedHeaders(target))
	}

	headerMisconfigurationConfig := methodwebtest.HeaderMisconfigurationEngineConfig{
		Targets:         config.Targets,
		Method:          methodwebtest.HttpMethodGet,
		Payloads:        targetHeaderPayloadsList,
		EventType:       methodwebtest.NewEventTypeFromHeaderEvent(methodwebtest.HeaderEventSensitiveexposed),
		FollowRedirects: false,
		Timeout:         config.Timeout,
	}

	report := utils.RunHeaderMisconfigurationEngine(ctx, &headerMisconfigurationConfig)
	return report
}

func generateSensitiveExposedHeaders(target string) []map[string]string {
	return []map[string]string{
		// Empty Request
		{"": ""},

		// Exposing sensitive headers to all origins.
		// Positive hit: The server allows `Authorization` and `Set-Cookie` headers to be
		// accessed by all origins, exposing credentials.
		{"Access-Control-Expose-Headers": "Authorization, Set-Cookie", "Access-Control-Allow-Origin": "*"},

		// Exposing a wide range of sensitive headers.
		// Positive hit: The server exposes headers such as `Authorization` and `Set-Cookie`, enabling
		// all origins to view potentially sensitive information.
		{"Access-Control-Allow-Headers": "X-Custom-Header, X-Requested-With, Authorization, Set-Cookie"},

		// Malicious site origin with exposed sensitive headers.
		// Positive hit: The server responds with `Access-Control-Expose-Headers: Authorization, Cookie,
		// Set-Cookie`, allowing the target access to sensitive headers.
		{
			"Origin":                        target,
			"Access-Control-Expose-Headers": "Authorization, Cookie, Set-Cookie",
		},
	}
}

package general

import (
	"context"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

func PerformHeaderMisconfigurationCORS(ctx context.Context, config *methodwebtest.HeaderMisconfigurationConfig) *methodwebtest.Report {
	targetHeaderPayloadsList := [][]map[string]string{}
	for _, target := range config.Targets {
		targetHeaderPayloadsList = append(targetHeaderPayloadsList, generateCORSHeaders(target))
	}

	headerMisconfigurationConfig := methodwebtest.HeaderMisconfigurationEngineConfig{
		Targets:         config.Targets,
		Method:          methodwebtest.HttpMethodGet,
		Payloads:        targetHeaderPayloadsList,
		EventType:       methodwebtest.NewEventTypeFromHeaderEvent(methodwebtest.HeaderEventCors),
		FollowRedirects: false,
		Timeout:         config.Timeout,
	}

	report := utils.RunHeaderMisconfigurationEngine(ctx, &headerMisconfigurationConfig)
	detectCORSInjection(report)
	return report
}

func generateCORSHeaders(target string) []map[string]string {
	return []map[string]string{
		// Empty Request
		{"": ""},

		// Malicious origin with a spoofed referer.
		// Positive hit: The server treats the request from `malicious-site.com` as if it came
		// from `trusted-site.com`, allowing access.
		{"Origin": "https://untrusted-site.com", "Referer": target},

		// Wildcard origin to test overly permissive CORS.
		// Positive hit: The server responds with `Access-Control-Allow-Origin: *`, allowing access
		// from any origin.
		{"Origin": "*"},

		// Valid origin with credential inclusion.
		// Positive hit: The server includes `Access-Control-Allow-Credentials: true` in its response,
		// allowing cookies or credentials to be sent cross-origin.
		{"Origin": target, "Access-Control-Allow-Credentials": "true"},

		// Exposing sensitive headers to all origins.
		// Positive hit: The server includes `Access-Control-Expose-Headers: Authorization, Set-Cookie`,
		// allowing all origins to see sensitive headers.
		{"Access-Control-Expose-Headers": "Authorization, Set-Cookie", "Access-Control-Allow-Origin": "*"},

		// Trusted origin with wildcard CORS.
		// Positive hit: The server sets `Access-Control-Allow-Origin: *` for requests from `trusted-site.com`,
		// allowing unintended origins to access the resource.
		{"Origin": target, "Access-Control-Allow-Origin": "*"},

		// Null origin, often sent by local files or sandboxed requests.
		// Positive hit: The server accepts the null origin, allowing requests from sandboxed or local
		// files to access the API.
		{"Origin": "null", "Referer": "https://untrusted-site.com"},

		// Cross-origin spoofing by setting trusted-site origin for an untrusted site.
		// Positive hit: The server allows `untrusted-site.com` access by setting
		// `Access-Control-Allow-Origin` to `trusted-site.com`.
		{"Origin": "https://untrusted-site.com", "Access-Control-Allow-Origin": target},

		// Trusted-site origin with credentials.
		// Positive hit: The server includes `Access-Control-Allow-Credentials: true`
		// and `Access-Control-Allow-Origin: https://trusted-site.com`, allowing cross-origin
		// credentialed access.
		{"Access-Control-Allow-Credentials": "true", "Access-Control-Allow-Origin": target},
	}
}

func detectCORSInjection(report *methodwebtest.Report) {
	for _, target := range report.Targets {
		if target.Attempts == nil {
			continue
		}
		for _, attempt := range target.Attempts {
			finding := false
			if attempt.Request == nil || attempt.Request.ResponseHeaders == nil {
				continue
			}
			headers := attempt.Request.ResponseHeaders

			// Check if "Access-Control-Allow-Origin" is overly permissive (e.g., "*").
			if origin, exists := headers["Access-Control-Allow-Origin"]; exists {
				if origin == "*" {
					finding = true
				}
			}

			// Check if credentials are allowed in cross-origin requests.
			if creds, exists := headers["Access-Control-Allow-Credentials"]; exists {
				if creds == "true" {
					finding = true
				}
			}

			// Check if sensitive headers are exposed.
			if exposedHeaders, exists := headers["Access-Control-Expose-Headers"]; exists {
				if strings.Contains(exposedHeaders, "Authorization") || strings.Contains(exposedHeaders, "Set-Cookie") {
					finding = true
				}
			}

			// Check if null origin was allowed.
			if origin, exists := headers["Access-Control-Allow-Origin"]; exists {
				if origin == "null" {
					finding = true
				}
			}

			attempt.Finding = &finding
		}
	}
}

package header

import (
	"context"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

var luaPaths = []string{
	// lua handler paths
	"/lua-handler",

	// Common Lua script endpoints
	"/lua",
	"/lua/index.lua",
	"/scripts/lua",
	"/cgi-bin/lua",
	"/handlers/lua",
	"/modules/lua",

	// API endpoints often implemented in Lua
	"/api/upload",
	"/api/v1/proxy",
	"/api/v1/gateway",
	"/api/gateway",
	"/api/transform",
	"/api/lua/execute",
	"/api/v1/lua-handler",
	"/api/v1/process-data",
	"/api/parse-body",
	"/lua-api",

	// Control panel/admin interfaces
	"/admin/scripts",
	"/admin/lua",
	"/dashboard/lua",
	"/control/execute",
	"/manager/lua-config",

	// Common extensions
	"/handler.lua",
	"/script.lua",
	"/execute.lua",
	"/process.lp",
	"/index.luac",
}

func PerformApacheHeaderLuaBufferOverflowInjection(ctx context.Context, config *methodwebtest.HeaderLuaBufferOverflowConfig) *methodwebtest.Report {
	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            methodwebtest.HttpMethodGet,
		Paths:             luaPaths,
		BaselinePayload:   map[string]string{},
		InjectedPayloads:  generatePayloads(config.MisconfiguredHeaderSize),
		InjectionLocation: methodwebtest.InjectionLocationHeader,
		EventType:         methodwebtest.NewEventTypeFromHeaderEvent(methodwebtest.HeaderEventLuabufferoverflow),
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	detectLuaBufferOverflow(report)
	report.Config = methodwebtest.NewEngineConfigFromInjectionEngineConfig(&injectionConfig)
	return report
}

// generatePayloads generates payloads for the lua buffer overflow test
func generatePayloads(misconfiguredHeaderSize int) []map[string]string {
	return []map[string]string{
		{"User-Agent": strings.Repeat("A", misconfiguredHeaderSize)},
		{"User-Agent": strings.Repeat("A", misconfiguredHeaderSize/2) + "\x00\x41\x42\x00" + strings.Repeat("B", misconfiguredHeaderSize/2)},
	}
}

// detectLuaBufferOverflow scans the report for Lua buffer overflow errors, case-insensitively.
func detectLuaBufferOverflow(report *methodwebtest.Report) {
	// Indicators of Lua buffer overflow issues (case-insensitive)
	luaOverflowIndicators := []string{
		"attempt to index a nil value", // Common Lua runtime error
		"bad argument",                 // Argument parsing failure
		"invalid memory access",        // Possible memory corruption
		"stack overflow",               // Lua stack overflow error
		"panic",                        // Lua panic state
		"segmentation fault",           // Apache crash due to Lua bug
		"core dumped",                  // Fatal error causing Apache to dump core
	}

	for _, target := range report.Targets {
		if target.Attempts == nil || target.BaselineAttempt == nil {
			continue
		}

		// Skip targets that don't have a baseline attempt or have a baseline attempt with a not 200 status code
		if target.BaselineAttempt.Request == nil || target.BaselineAttempt.Request.StatusCode == nil || *target.BaselineAttempt.Request.StatusCode != 200 {
			continue
		}

		for _, attempt := range target.Attempts {
			finding := false
			// Check response body for Lua-specific errors (case-insensitive)
			if attempt.Request != nil && attempt.Request.ResponseBody != nil {
				// Baseline attempt is 200, but the attempt is 500 or higher suggests a buffer overflow
				if attempt.Request.StatusCode == nil || *attempt.Request.StatusCode >= 500 {
					finding = true
				}
				if !finding {
					lowerResponseBody := strings.ToLower(*attempt.Request.ResponseBody) // Convert response body to lowercase
					for _, indicator := range luaOverflowIndicators {
						if strings.Contains(lowerResponseBody, strings.ToLower(indicator)) {
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

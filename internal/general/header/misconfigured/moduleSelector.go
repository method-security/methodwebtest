package general

import (
	"context"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
)

func RunModuleSelector(ctx context.Context, config *methodwebtest.HeaderMisconfigurationConfig) *methodwebtest.Report {
	if config.HeaderEvent == methodwebtest.HeaderEventHttp {
		return PerformHeaderMisconfigurationHTTP(ctx, config)
	}
	if config.HeaderEvent == methodwebtest.HeaderEventEscape {
		return PerformHeaderMisconfigurationEscape(ctx, config)
	}
	if config.HeaderEvent == methodwebtest.HeaderEventCors {
		return PerformHeaderMisconfigurationCORS(ctx, config)
	}
	if config.HeaderEvent == methodwebtest.HeaderEventSensitiveexposed {
		return PerformHeaderMisconfigurationSensitiveExposed(ctx, config)
	}
	return nil
}

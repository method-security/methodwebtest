package general

import (
	"context"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	command "github.com/Method-Security/methodwebtest/internal/general/multi/command"
	sqli "github.com/Method-Security/methodwebtest/internal/general/multi/sqli"
	ssti "github.com/Method-Security/methodwebtest/internal/general/multi/ssti"
	xss "github.com/Method-Security/methodwebtest/internal/general/multi/xss"
)

func RunModuleSelector(ctx context.Context, config *methodwebtest.MultiInjectionConfig) *methodwebtest.Report {
	if config.EventType == methodwebtest.MultiEventSqliboolean {
		return sqli.PerformSqliBooleanInjection(ctx, config)
	}
	if config.EventType == methodwebtest.MultiEventSqliescape {
		return sqli.PerformSqliEscapeCharacterInjection(ctx, config)
	}
	if config.EventType == methodwebtest.MultiEventSqlitimedelay {
		return sqli.PerformSQLiTimeDelayInjection(ctx, config)
	}
	if config.EventType == methodwebtest.MultiEventXssalert {
		return xss.PerformXSSAlertInjection(ctx, config)
	}
	if config.EventType == methodwebtest.MultiEventCommandtimedelay {
		return command.PerformCommandTimeDelayInjection(ctx, config)
	}
	if config.EventType == methodwebtest.MultiEventCommandecho {
		return command.PerformCommandEchoInjection(ctx, config)
	}
	if config.EventType == methodwebtest.MultiEventSsti {
		return ssti.PerformSSTIInjection(ctx, config)
	}
	return &methodwebtest.Report{Errors: []string{"No module found for event type"}}
}

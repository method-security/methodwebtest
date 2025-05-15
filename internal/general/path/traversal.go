package general

import (
	"context"
	"time"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

func PerformGeneralPathTraversal(ctx context.Context, config *methodwebtest.PathTraversalConfig) *methodwebtest.Report {
	engineConfig := methodwebtest.PathTraversalEngineConfig{
		Targets:           config.Targets,
		Paths:             config.Paths,
		PathFiles:         config.PathLists,
		QueryParam:        config.QueryParam,
		ResponseCodes:     config.ResponseCodes,
		IgnoreBaseContent: config.IgnoreBaseContent,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
		SuccessfulOnly:    config.SuccessfulOnly,
		Threshold:         &config.Threshold,
		MaxRunTime:        config.MaxRunTime,
	}

	// If MaxRunTime is set, create a context with a timeout
	if config.MaxRunTime != nil && *config.MaxRunTime > 0 {
		var cancel context.CancelFunc
		maxTime := *config.MaxRunTime
		ctx, cancel = context.WithTimeout(ctx, time.Duration(maxTime)*time.Second)
		defer cancel()
	}

	report := utils.RunPathTraversalEngine(ctx, &engineConfig)
	report.Config = methodwebtest.NewEngineConfigFromPathTraversalEngineConfig(&engineConfig)
	return report
}

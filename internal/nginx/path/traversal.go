package nginx

import (
	"context"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

var commonExposedPaths = []string{
	"/.env",
	"/.git",
	"/admin",
	"/api../",
	"/backup",
	"/config",
	"/etc/nginx/nginx.conf",
	"/etc/shadow",
	"/public",
	"/server-status",
	"/usr/local/nginx/conf/nginx.conf",
	"/usr/share/nginx/html",
	"/var/log/nginx/access.log",
	"/var/log/nginx/error.log",
	"/var/wwww/html",
}

func PerformNginxPathTraversal(ctx context.Context, config *methodwebtest.PathTraversalConfig) *methodwebtest.Report {
	config.Paths = commonExposedPaths
	engineConfig := methodwebtest.PathTraversalEngineConfig{
		Targets:           config.Targets,
		Paths:             config.Paths,
		PathFiles:         []string{},
		ResponseCodes:     config.ResponseCodes,
		IgnoreBaseContent: config.IgnoreBaseContent,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
		SuccessfulOnly:    config.SuccessfulOnly,
		Threshold:         &config.Threshold,
	}
	report := utils.RunPathTraversalEngine(ctx, &engineConfig)
	report.Config = methodwebtest.NewEngineConfigFromPathTraversalEngineConfig(&engineConfig)
	return report
}

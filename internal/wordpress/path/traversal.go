package wordpress

import (
	"context"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

var commonExposedPaths = []string{
	"/xmlrpc.php",                       // Often exploited for brute-force attacks
	"/wp-config.php",                    // Contains database credentials and secrets
	"/wp-content/debug.log",             // Can leak sensitive debug info
	"/wp-includes/",                     // Core WordPress files, can expose version info
	"/wp-json/",                         // REST API, potential user enumeration
	"/wp-json/wp/v2/users",              // Enumerate users, especially admin usernames
	"/wp-json/wp/v2/settings",           // Enumerate settings, potential sensitive information
	"/wp-json/wp/v2/revisions",          // Enumerate revisions, potential sensitive information
	"/wp-cron.php",                      // Can be abused for DoS or forced execution
	"/readme.html",                      // Leaks WordPress version
	"/.htaccess",                        // Might expose security configurations
	"/.htpasswd",                        // Can leak password-protected directories
	"/license.txt",                      // Leaks installation details
	"/wp-admin/install.php",             // Can be exposed on unconfigured sites
	"/wp-admin/admin-ajax.php",          // Used in many plugins, potential data leaks
	"/wp-admin/admin-post.php",          // Can expose admin-related operations
	"/wp-admin/setup-config.php",        // Can be accessed if setup is incomplete
	"/wp-config.bak",                    // Backup of wp-config.php, may still have credentials
	"/wp-config.old",                    // Old versions often left after updates
	"/wp-content/uploads/db-backup.sql", // Database dump file, may contain sensitive data
	"/wp-content/uploads/error_log",     // PHP error log, may expose system paths
	"/wp-sitemap.xml",                   // Can provide a list of indexed URLs for reconnaissance
	"/wp-content/plugins/wp-file-manager/lib/files/",       // Misconfigured file manager plugin
	"/wp-admin/admin-ajax.php?action=revslider_show_image", // Revslider LFI vulnerability
}

func PerformWordpressPathTraversal(ctx context.Context, config *methodwebtest.PathTraversalConfig) *methodwebtest.Report {
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

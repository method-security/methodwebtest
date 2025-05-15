package cmd

import (
	"errors"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	header "github.com/Method-Security/methodwebtest/internal/nginx/header"
	path "github.com/Method-Security/methodwebtest/internal/nginx/path"
	query "github.com/Method-Security/methodwebtest/internal/nginx/query"
	"github.com/spf13/cobra"
)

// InitNginxCommand initializes the nginx command for the methodwebtest CLI.
func (a *MethodWebTest) InitNginxCommand() {
	nginxCmd := &cobra.Command{
		Use:   "nginx",
		Short: "Perform nginx specific injection tests against a target",
		Long:  `Perform nginx specific injection tests against a target`,
	}

	nginxCmd.PersistentFlags().StringSlice("targets", []string{}, "The URL of target")
	nginxCmd.PersistentFlags().Int("timeout", 30, "Timeout per request (seconds)")
	nginxCmd.PersistentFlags().Int("sleep", 0, "Sleep time between requests (seconds)")
	nginxCmd.PersistentFlags().Int("retries", 0, "Number of attempts per credential pair")

	// headerCmd holds the subcommands for header injection tests
	headerCmd := &cobra.Command{
		Use:   "header",
		Short: "Perform injection tests in the headers of a target",
		Long:  `Perform injection tests in the headers of a target`,
	}

	bufferoverflowContentCmd := &cobra.Command{
		Use:   "bufferoverflow",
		Short: "Perform a buffer overflow test in the content header of a target",
		Long:  `Perform a buffer overflow test in the content header of a target`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flags
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if len(targets) == 0 {
				a.OutputSignal.AddError(errors.New("no targets provided"))
				return
			}

			// Configuration flags
			bodySize, err := cmd.Flags().GetInt("bodysize")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			sleep, err := cmd.Flags().GetInt("sleep")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			retries, err := cmd.Flags().GetInt("retries")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Load configuration
			config := LoadHeaderBufferOverflowConfig(targets, bodySize, timeout, sleep, retries)

			// Generate report
			report := header.PerformNginxHeaderBufferOverflowInjection(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	bufferoverflowContentCmd.Flags().Int("bodysize", 5000, "The size of the body to send")

	headerCmd.AddCommand(bufferoverflowContentCmd)

	nginxCmd.AddCommand(headerCmd)

	// pathCmd holds the subcommands for path injection tests
	pathCmd := &cobra.Command{
		Use:   "path",
		Short: "Perform injection tests in the path of a target",
		Long:  `Perform injection tests in the path of a target`,
	}

	traversalCmd := &cobra.Command{
		Use:   "traversal",
		Short: "Perform a Nginx specific path traversal for common file locations",
		Long:  `Perform a Nginx specific path traversal for common file locations`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flags
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if len(targets) == 0 {
				a.OutputSignal.AddError(errors.New("no targets provided"))
				return
			}

			// Configuration flags
			responseCodes, err := cmd.Flags().GetString("responsecodes")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			ignoreBase, err := cmd.Flags().GetBool("ignorebasecontentmatch")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			sleep, err := cmd.Flags().GetInt("sleep")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			retries, err := cmd.Flags().GetInt("retries")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			successfulOnly, err := cmd.Flags().GetBool("successfulonly")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			threshold, err := cmd.Flags().GetFloat64("threshold")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Load configuration
			config := LoadPathTraversalConfig(targets, []string{}, []string{}, "", responseCodes, ignoreBase, timeout, sleep, retries, successfulOnly, threshold, nil)

			// Generate report
			report := path.PerformNginxPathTraversal(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	traversalCmd.Flags().String("responsecodes", "200-299", "Response codes to consider as valid responses")
	traversalCmd.Flags().Bool("ignorebasecontentmatch", true, "Ignores valid responses with identical size and word length to the base path, typically signifying a web backend redirect")
	traversalCmd.Flags().Bool("successfulonly", false, "Only show successful attempts")
	traversalCmd.Flags().Float64("threshold", 0.10, "Threshold for a negitive finding that represents the percentage difference between the size of the response body in question and the baseline response (0.0 is an exact match, with .05 being a 5 percent difference)")

	_ = traversalCmd.MarkFlagRequired("targets")

	pathCmd.AddCommand(traversalCmd)

	nginxCmd.AddCommand(pathCmd)

	// queryCmd holds the subcommands for query injection tests
	queryCmd := &cobra.Command{
		Use:   "query",
		Short: "Perform injection tests in the query of a target",
		Long:  `Perform injection tests in the query of a target`,
	}

	reverseproxyCmd := &cobra.Command{
		Use:   "reverseproxy",
		Short: "Perform injection tests in the reverse proxy of a target",
		Long:  `Perform injection tests in the reverse proxy of a target`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flags
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if len(targets) == 0 {
				a.OutputSignal.AddError(errors.New("no targets provided"))
				return
			}

			// Configuration flags
			redirectAddress, err := cmd.Flags().GetString("redirectaddress")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			retries, err := cmd.Flags().GetInt("retries")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			sleep, err := cmd.Flags().GetInt("sleep")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Load configuration
			config := LoadQueryReverseProxyConfig(targets, redirectAddress, timeout, retries, sleep)

			// Generate report
			report := query.PerformQueryReverseProxyInjection(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	reverseproxyCmd.Flags().String("redirectaddress", "127.0.0.1", "Specifies the target address for redirection")

	queryCmd.AddCommand(reverseproxyCmd)

	nginxCmd.AddCommand(queryCmd)

	a.RootCmd.AddCommand(nginxCmd)
}

func LoadHeaderBufferOverflowConfig(targets []string, bodySize int, timeout int, sleep int, retries int) *methodwebtest.HeaderBufferOverflowConfig {
	config := &methodwebtest.HeaderBufferOverflowConfig{
		Targets:  targets,
		BodySize: bodySize,
		Timeout:  timeout,
		Retries:  retries,
		Sleep:    sleep,
	}

	if config.Timeout < 1 {
		config.Timeout = 0
	}
	if config.Retries < 0 {
		config.Retries = 0
	}
	if config.Sleep < 0 {
		config.Sleep = 0
	}

	return config
}

func LoadQueryReverseProxyConfig(targets []string, redirectAddress string, timeout int, retries int, sleep int) *methodwebtest.QueryReverseProxyConfig {
	config := &methodwebtest.QueryReverseProxyConfig{
		Targets:         targets,
		RedirectAddress: redirectAddress,
		Timeout:         timeout,
		Retries:         retries,
		Sleep:           sleep,
	}

	if config.Timeout < 1 {
		config.Timeout = 0
	}
	if config.Retries < 0 {
		config.Retries = 0
	}
	if config.Sleep < 0 {
		config.Sleep = 0
	}

	return config
}

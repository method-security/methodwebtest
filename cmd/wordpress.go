package cmd

import (
	"errors"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	body "github.com/Method-Security/methodwebtest/internal/wordpress/body/xmlrpc"
	path "github.com/Method-Security/methodwebtest/internal/wordpress/path"
	"github.com/spf13/cobra"
)

// InitWordpressCommand initializes the apache command for the methodwebtest CLI.
func (a *MethodWebTest) InitWordpressCommand() {
	wordpressCmd := &cobra.Command{
		Use:   "wordpress",
		Short: "Perform wordpress specific injection tests against a target",
		Long:  `Perform wordpress specific injection tests against a target`,
	}

	wordpressCmd.PersistentFlags().StringSlice("targets", []string{}, "The URL of target")
	wordpressCmd.PersistentFlags().Int("timeout", 30, "Timeout per request (seconds)")
	wordpressCmd.PersistentFlags().Int("sleep", 0, "Sleep time between requests (seconds)")
	wordpressCmd.PersistentFlags().Int("retries", 0, "Number of attempts per credential pair")

	// pathCmd holds the subcommands for path injection tests
	pathCmd := &cobra.Command{
		Use:   "path",
		Short: "Perform path injection tests against a target",
		Long:  `Perform path injection tests against a target`,
	}

	traversalCmd := &cobra.Command{
		Use:   "traversal",
		Short: "Perform a Wordpress specific path traversal for common file locations",
		Long:  `Perform a Wordpress specific path traversal for common file locations`,
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
			report := path.PerformWordpressPathTraversal(cmd.Context(), config)
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

	pathCmd.AddCommand(traversalCmd)

	wordpressCmd.AddCommand(pathCmd)

	// pathCmd holds the subcommands for path injection tests
	bodyCmd := &cobra.Command{
		Use:   "body",
		Short: "Perform body injection tests against a target",
		Long:  `Perform body injection tests against a target`,
	}

	xmlrpcCmd := &cobra.Command{
		Use:   "xmlrpc",
		Short: "Perform xmlrpc injection tests against a target",
		Long:  `Perform xmlrpc injection tests against a target`,
	}

	functionAuthCmd := &cobra.Command{
		Use:   "functionauth",
		Short: "Perform xmlrpc function authentication injection tests against a target",
		Long:  `Perform xmlrpc function authentication injection tests against a target`,
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
			config := LoadBodyXMLRPCFunctionAuthConfig(targets, timeout, retries, sleep)

			// Generate report
			report := body.PerformBodyXMLRPCFunctionAuthInjection(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}
	xmlrpcCmd.AddCommand(functionAuthCmd)

	bodyCmd.AddCommand(xmlrpcCmd)

	wordpressCmd.AddCommand(bodyCmd)

	a.RootCmd.AddCommand(wordpressCmd)
}

func LoadBodyXMLRPCFunctionAuthConfig(targets []string, timeout int, retries int, sleep int) *methodwebtest.BodyXmlRpcFunctionAuthConfig {
	config := &methodwebtest.BodyXmlRpcFunctionAuthConfig{
		Targets: targets,
		Timeout: timeout,
		Retries: retries,
		Sleep:   sleep,
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

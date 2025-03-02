package cmd

import (
	"errors"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	header "github.com/Method-Security/methodwebtest/internal/apache/header"
	path "github.com/Method-Security/methodwebtest/internal/apache/path"
	"github.com/spf13/cobra"
)

// InitApacheCommand initializes the apache command for the methodwebtest CLI.
func (a *MethodWebTest) InitApacheCommand() {
	apacheCmd := &cobra.Command{
		Use:   "apache",
		Short: "Perform apache specific injection tests against a target",
		Long:  `Perform apache specific injection tests against a target`,
	}

	apacheCmd.PersistentFlags().StringSlice("targets", []string{}, "The URL of target")
	apacheCmd.PersistentFlags().Int("timeout", 30, "Timeout per request (seconds)")
	apacheCmd.PersistentFlags().Int("sleep", 0, "Sleep time between requests (seconds)")
	apacheCmd.PersistentFlags().Int("retries", 0, "Number of attempts per credential pair")

	headerCmd := &cobra.Command{
		Use:   "header",
		Short: "Perform header injection tests against a target",
		Long:  `Perform header injection tests against a target`,
	}

	optionsBleedCmd := &cobra.Command{
		Use:   "optionsbleed",
		Short: "Perform options bleed tests against a target",
		Long:  `Perform options bleed tests against a target`,
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
			config := LoadHeaderOptionsBleedConfig(targets, timeout, sleep, retries)

			// Generate report
			report := header.PerformApacheHeaderOptionsBleedInjection(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	headerCmd.AddCommand(optionsBleedCmd)

	// pathCmd holds the subcommands for path injection tests
	pathCmd := &cobra.Command{
		Use:   "path",
		Short: "Perform path injection tests against a target",
		Long:  `Perform path injection tests against a target`,
	}

	modfileCmd := &cobra.Command{
		Use:   "modfile",
		Short: "Perform modfile injection tests in the path of a target",
		Long:  `Perform modfile injection tests in the path of a target`,
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
			config := LoadPathModFileConfig(targets, timeout, sleep, retries)

			// Generate report
			report := path.PerformApachePathModFileInjection(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	pathCmd.AddCommand(modfileCmd)

	traversalCmd := &cobra.Command{
		Use:   "traversal",
		Short: "Perform a Apache specific path traversal for common file locations",
		Long:  `Perform a Apache specific path traversal for common file locations`,
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
			report := path.PerformApachePathTraversal(cmd.Context(), config)
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

	apacheCmd.AddCommand(headerCmd)
	apacheCmd.AddCommand(pathCmd)

	a.RootCmd.AddCommand(apacheCmd)
}

func LoadHeaderOptionsBleedConfig(targets []string, timeout int, sleep int, retries int) *methodwebtest.HeaderOptionsBleedConfig {
	config := &methodwebtest.HeaderOptionsBleedConfig{
		Targets: targets,
		Timeout: timeout,
		Sleep:   sleep,
		Retries: retries,
	}

	if config.Timeout < 1 {
		config.Timeout = 0
	}

	return config
}

func LoadPathModFileConfig(targets []string, timeout int, sleep int, retries int) *methodwebtest.PathModFileConfig {
	config := &methodwebtest.PathModFileConfig{
		Targets: targets,
		Timeout: timeout,
		Sleep:   sleep,
		Retries: retries,
	}

	if config.Timeout < 1 {
		config.Timeout = 0
	}

	return config
}

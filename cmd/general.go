package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	header "github.com/Method-Security/methodwebtest/internal/general/header"
	misconfigured "github.com/Method-Security/methodwebtest/internal/general/header/misconfigured"
	multi "github.com/Method-Security/methodwebtest/internal/general/multi"
	path "github.com/Method-Security/methodwebtest/internal/general/path"
	"github.com/spf13/cobra"
)

// InitGeneralCommand initializes the general command for the methodwebtest CLI.
func (a *MethodWebTest) InitGeneralCommand() {
	generalCmd := &cobra.Command{
		Use:   "general",
		Short: "Perform general injection tests against a target",
		Long:  `Perform general injection tests against a target`,
	}

	generalCmd.PersistentFlags().StringSlice("targets", []string{}, "The URL of target")
	generalCmd.PersistentFlags().Int("timeout", 30, "Timeout per request (seconds)")
	generalCmd.PersistentFlags().Int("sleep", 0, "Sleep time between requests (seconds)")
	generalCmd.PersistentFlags().Int("retries", 0, "Number of attempts per credential pair")

	// headerCmd holds the subcommands for header injection tests
	headerCmd := &cobra.Command{
		Use:   "header",
		Short: "Perform injection tests in the headers of a target",
		Long:  `Perform injection tests in the headers of a target`,
	}

	misconfiguredCmd := &cobra.Command{
		Use:   "misconfigured",
		Short: "Header misconfiguration tests.",
		Long: `Perform header tests to detect misconfigurations such as overly permissive CORS, 
		vulnerable HTTP methods, improper escape charecter handling, and Sensitive value exposure.`,
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
			event, err := cmd.Flags().GetString("event")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			headerEvent, err := methodwebtest.NewHeaderEventFromString(strings.ToUpper(event))
			if err != nil {
				a.OutputSignal.AddError(errors.New("invalid header event provided"))
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
			config := LoadHeaderMisconfigurationConfig(targets, headerEvent, timeout, sleep, retries)

			// Generate report
			report := misconfigured.RunModuleSelector(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}
	misconfiguredCmd.Flags().String("event", "", "Specifies the header event to run: CORS, HTTP, ESCAPE, SENSITIVEEXPOSE")

	_ = misconfiguredCmd.MarkFlagRequired("event")

	headerCmd.AddCommand(misconfiguredCmd)
	headerCmd.AddCommand(misconfiguredCmd)

	serverOverloadCmd := &cobra.Command{
		Use:   "serveroverload",
		Short: "Server overload header requests.",
		Long:  `Define the Header name and value length for server overload requests.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
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
			headerNames, err := cmd.Flags().GetStringSlice("headernames")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			headerSize, err := cmd.Flags().GetInt("headersize")
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
			config := LoadHeaderServerOverloadConfig(targets, headerNames, headerSize, timeout, sleep, retries)

			// Generate report
			report := header.PerformHeaderServerOverloadInjection(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}
	serverOverloadCmd.Flags().StringSlice("headernames", []string{"test"}, "Specifies Header keys to use in request.")
	serverOverloadCmd.Flags().Int("headersize", 5000, "Specifies the length of header values to include in requests.")

	headerCmd.AddCommand(serverOverloadCmd)

	userAgentCmd := &cobra.Command{
		Use:   "useragent",
		Short: "Preform User-Agent header requests.",
		Long:  `Preform User-Agent header requests.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if len(targets) == 0 {
				a.OutputSignal.AddError(errors.New("no targets provided"))
				return
			}

			userAgentHeader, err := cmd.Flags().GetString("useragent")
			if err != nil {
				a.OutputSignal.AddError(err)
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
			config := LoadHeaderUserAgentConfig(targets, userAgentHeader, timeout, sleep, retries)

			// Generate report
			report := header.PerformHeaderUserAgentInjection(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	userAgentCmd.Flags().String("useragent", "", "Value of the 'User-Agent' header to use in request.")

	_ = userAgentCmd.MarkFlagRequired("useragent")

	headerCmd.AddCommand(userAgentCmd)

	generalCmd.AddCommand(headerCmd)

	// pathCmd holds the subcommands for path injection tests
	pathCmd := &cobra.Command{
		Use:   "path",
		Short: "Perform injection tests in the path of a target",
		Long:  `Perform injection tests in the path of a target`,
	}

	crlfCmd := &cobra.Command{
		Use:   "crlf",
		Short: "Perform CRLF injection tests in the path of a target",
		Long:  `Perform CRLF injection tests in the path of a target`,
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
			headerName, err := cmd.Flags().GetString("headername")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			headerValue, err := cmd.Flags().GetString("headervalue")
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
			config := LoadPathCrlfConfig(targets, headerName, headerValue, timeout, sleep, retries)

			// Generate report
			report := path.PerformPathCrlfInjection(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	crlfCmd.Flags().String("headername", "", "The name of the header to inject")
	crlfCmd.Flags().String("headervalue", "", "The value of the header to inject")

	_ = crlfCmd.MarkFlagRequired("headername")
	_ = crlfCmd.MarkFlagRequired("headervalue")

	pathCmd.AddCommand(crlfCmd)

	traversalCmd := &cobra.Command{
		Use:   "traversal",
		Short: "Perform a path traversal against a URL target",
		Long:  `Perform a path traversal against a URL target`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if len(targets) == 0 {
				a.OutputSignal.AddError(errors.New("no targets provided"))
				return
			}
			paths, err := cmd.Flags().GetStringSlice("paths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			pathlists, err := cmd.Flags().GetStringSlice("pathlists")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if len(pathlists) == 0 && len(paths) == 0 {
				a.OutputSignal.AddError(errors.New("no paths provided"))
				return
			}

			// Configuration flags
			queryParam, err := cmd.Flags().GetString("queryparam")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
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
			maxTime, err := cmd.Flags().GetInt("maxruntime")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Load configuration
			config := LoadPathTraversalConfig(targets, paths, pathlists, queryParam, responseCodes, ignoreBase, timeout, sleep, retries, successfulOnly, threshold, &maxTime)

			// Generate report
			report := path.PerformGeneralPathTraversal(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	traversalCmd.Flags().StringSlice("paths", []string{}, "Paths to use in attack")
	traversalCmd.Flags().StringSlice("pathlists", []string{}, "Path to a file that contains a new line delimited list of paths to fuzz")
	traversalCmd.Flags().String("queryparam", "", "Optional query parameter to use in path traversal")
	traversalCmd.Flags().String("responsecodes", "200-299", "Response codes to consider as valid responses")
	traversalCmd.Flags().Bool("ignorebasecontentmatch", true, "Ignores valid responses with identical size and word length to the base path, typically signifying a web backend redirect")
	traversalCmd.Flags().Bool("successfulonly", false, "Only show successful attempts")
	traversalCmd.Flags().Float64("threshold", 0.10, "Threshold for a negitive finding that represents the percentage difference between the size of the response body in question and the baseline response (0.0 is an exact match, with .05 being a 5 percent difference)")
	traversalCmd.Flags().Int("maxruntime", 0, "Maximum time to run the engagement (seconds) (Default is 0, which will run indefinitely)")

	pathCmd.AddCommand(traversalCmd)

	generalCmd.AddCommand(pathCmd)

	// queryCmd holds the subcommands for query injection tests
	multiCmd := &cobra.Command{
		Use:   "multi",
		Short: "Perform injection tests in the multiple locations of a target",
		Long:  `Perform injection tests in the multiple locations of a target`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
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
			method, err := cmd.Flags().GetString("method")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			methodEnum, err := methodwebtest.NewHttpMethodFromString(strings.ToUpper(method))
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			injectionLocation, err := cmd.Flags().GetString("injectionlocation")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			injectionLocationEnum, err := methodwebtest.NewInjectionLocationFromString(strings.ToUpper(injectionLocation))
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			variableData, err := cmd.Flags().GetString("variabledata")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			eventType, err := cmd.Flags().GetString("event")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			eventTypeEnum, err := methodwebtest.NewMultiEventFromString(strings.ToUpper(eventType))
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			variableDataMap := map[string]string{}
			decodedData, err := base64.StdEncoding.DecodeString(variableData)
			if err != nil {
				a.OutputSignal.AddError(fmt.Errorf("failed to decode base64 variable data: %v", err))
				return
			}
			variableData = string(decodedData)
			if variableData != "" {
				err = json.Unmarshal([]byte(variableData), &variableDataMap)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("failed to parse variable data json: %v", err))
					return
				}
			}
			if len(variableDataMap) == 0 {
				a.OutputSignal.AddError(errors.New("no variable data provided"))
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
			config := LoadMultiInjectionConfig(targets, methodEnum, injectionLocationEnum, eventTypeEnum, variableDataMap, timeout, retries, sleep)

			// Generate report
			report := multi.RunModuleSelector(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	multiCmd.Flags().String("method", "", "The HTTP method to use for the request")
	multiCmd.Flags().String("event", "", "The event to test: XSSALERT, SQLIBOOLEAN, SQLIESCAPE, SQLITIMEDELAY, SSTI")
	multiCmd.Flags().String("variabledata", "", "Base64 encoded Json string of variable names and base values to add to injects")
	multiCmd.Flags().String("injectionlocation", "", "The injection location to test: HEADER, PATH, QUERY, BODY, FORM, MULTIPART")

	_ = multiCmd.MarkFlagRequired("method")
	_ = multiCmd.MarkFlagRequired("event")
	_ = multiCmd.MarkFlagRequired("variabledata")
	_ = multiCmd.MarkFlagRequired("injectionlocation")

	generalCmd.AddCommand(multiCmd)

	a.RootCmd.AddCommand(generalCmd)
}

// LoadHeaderMisconfigurationConfig loads the configuration for a path-based fuzzing run.
func LoadHeaderMisconfigurationConfig(targets []string, HeaderEvent methodwebtest.HeaderEvent, timeout int, sleep int, retries int) *methodwebtest.HeaderMisconfigurationConfig {
	config := &methodwebtest.HeaderMisconfigurationConfig{
		Targets:     targets,
		Timeout:     timeout,
		HeaderEvent: HeaderEvent,
		Sleep:       sleep,
		Retries:     retries,
	}

	if config.Timeout < 1 {
		config.Timeout = 0
	}
	if config.Sleep < 0 {
		config.Sleep = 0
	}
	if config.Retries < 0 {
		config.Retries = 0
	}

	return config
}

// LoadHeaderUserAgentConfig loads the configuration for a path-based fuzzing run.
func LoadHeaderUserAgentConfig(targets []string, agentheader string, timeout int, sleep int, retries int) *methodwebtest.HeaderUserAgentConfig {
	config := &methodwebtest.HeaderUserAgentConfig{
		Targets:     targets,
		AgentHeader: agentheader,
		Timeout:     timeout,
		Sleep:       sleep,
		Retries:     retries,
	}

	if config.Timeout < 1 {
		config.Timeout = 0
	}
	if config.Sleep < 0 {
		config.Sleep = 0
	}
	if config.Retries < 0 {
		config.Retries = 0
	}

	return config
}

// LoadHeaderServerOverloadConfig loads the configuration for a path-based fuzzing run.
func LoadHeaderServerOverloadConfig(targets, headerNames []string, payloadSize int, timeout int, sleep int, retries int) *methodwebtest.HeaderServerOverloadConfig {
	config := &methodwebtest.HeaderServerOverloadConfig{
		Targets:     targets,
		HeaderNames: headerNames,
		PayloadSize: payloadSize,
		Timeout:     timeout,
		Sleep:       sleep,
		Retries:     retries,
	}

	if config.Timeout < 1 {
		config.Timeout = 0
	}
	if config.Sleep < 0 {
		config.Sleep = 0
	}
	if config.Retries < 0 {
		config.Retries = 0
	}

	return config
}

// LoadPathCrlfConfig loads the configuration for a path-based fuzzing run.
func LoadPathCrlfConfig(targets []string, headerName string, headerValue string, timeout int, sleep int, retries int) *methodwebtest.PathCrlfConfig {
	config := &methodwebtest.PathCrlfConfig{
		HeaderName:  headerName,
		HeaderValue: headerValue,
		Targets:     targets,
		Timeout:     timeout,
		Sleep:       sleep,
		Retries:     retries,
	}

	if config.Timeout < 1 {
		config.Timeout = 0
	}
	if config.Sleep < 0 {
		config.Sleep = 0
	}
	if config.Retries < 0 {
		config.Retries = 0
	}

	return config
}

// LoadPathTraversalConfig loads the configuration for a path-based fuzzing run.
func LoadPathTraversalConfig(targets, paths []string, pathlists []string, queryParam string, responseCodes string, ignoreBaseContent bool, timeout, sleep, retries int, successfulOnly bool, threshold float64, maxRunTime *int) *methodwebtest.PathTraversalConfig {
	config := &methodwebtest.PathTraversalConfig{
		Targets:           targets,
		Paths:             paths,
		PathLists:         pathlists,
		ResponseCodes:     responseCodes,
		IgnoreBaseContent: ignoreBaseContent,
		Timeout:           timeout,
		Sleep:             sleep,
		Retries:           retries,
		SuccessfulOnly:    successfulOnly,
		Threshold:         threshold,
		MaxRunTime:        maxRunTime,
	}
	if queryParam != "" {
		config.QueryParam = &queryParam
	}

	if config.Timeout < 1 {
		config.Timeout = 0
	}
	if config.Sleep < 0 {
		config.Sleep = 0
	}
	if config.Retries < 0 {
		config.Retries = 0
	}

	return config
}

// LoadMultiInjectionConfig loads the configuration for a multi location injection run.
func LoadMultiInjectionConfig(targets []string, method methodwebtest.HttpMethod, injectionLocation methodwebtest.InjectionLocation, eventType methodwebtest.MultiEvent, variableData map[string]string, timeout int, retries int, sleep int) *methodwebtest.MultiInjectionConfig {
	config := &methodwebtest.MultiInjectionConfig{
		Targets:           targets,
		Method:            method,
		InjectionLocation: injectionLocation,
		EventType:         eventType,
		VariableData:      variableData,
		Timeout:           timeout,
		Retries:           retries,
		Sleep:             sleep,
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

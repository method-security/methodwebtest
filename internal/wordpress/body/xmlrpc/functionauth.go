package body

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	"github.com/Method-Security/methodwebtest/utils"
)

var xmlrpcPath = "/xmlrpc.php"

func PerformBodyXMLRPCFunctionAuthInjection(ctx context.Context, config *methodwebtest.BodyXmlRpcFunctionAuthConfig) methodwebtest.Report {
	report := methodwebtest.Report{}
	var allErrors []string

	var targets []*methodwebtest.TargetInfo
	for _, target := range config.Targets {
		targetInfo := methodwebtest.TargetInfo{Target: target, StartTimestamp: time.Now()}

		// Split target
		baseURL, parsedPath, err := utils.SplitTarget(target)
		if err != nil {
			allErrors = append(allErrors, err.Error())
			continue
		}
		xmlrpcPathParsedPath := parsedPath + xmlrpcPath

		// Base request -  Gather xmlrpc functions
		startTime := time.Now()
		grabXMLRPCFunctionsRequest := utils.PerformRequestScan(
			baseURL,
			xmlrpcPathParsedPath,
			methodwebtest.HttpMethodPost,
			methodwebtest.RequestParams{BodyParams: "<?xml version=\"1.0\" encoding=\"utf-8\"?><methodCall><methodName>system.listMethods</methodName></methodCall>"},
			[]*methodwebtest.EventType{},
			config.Timeout, true)
		endTime := time.Now()

		// Marshal base attempt
		baselineAttempt := methodwebtest.AttemptInfo{
			Request:      &grabXMLRPCFunctionsRequest,
			TimeSent:     startTime,
			TimeReceived: &endTime,
		}
		if !detectSuccessfulXmlrpcGrab(grabXMLRPCFunctionsRequest) {
			targetInfo.RequestCount = 0
			targetInfo.BaselineAttempt = &baselineAttempt
			targetInfo.EndTimestamp = time.Now()
			targets = append(targets, &targetInfo)
			allErrors = append(allErrors, "Failed to grab xmlrpc functions")
			continue
		}

		passedXMLRPCFunctions := parseXMLRPCFunctions(grabXMLRPCFunctionsRequest.ResponseBody)

		attempts := []*methodwebtest.AttemptInfo{}
		for _, function := range passedXMLRPCFunctions {
			attempt := methodwebtest.AttemptInfo{}

			// Generate xmlrpc payload
			bodyParams := generateFunctionAuthBodyInjectionParam(function)

			// Send request
			startTime := time.Now()
			request := utils.PerformRequestScan(
				baseURL,
				xmlrpcPathParsedPath,
				methodwebtest.HttpMethodPost,
				methodwebtest.RequestParams{BodyParams: bodyParams},
				[]*methodwebtest.EventType{methodwebtest.NewEventTypeFromBodyEvent(methodwebtest.BodyEventXmlrpcfunctionauth)},
				config.Timeout, true)
			endTime := time.Now()

			// Marshal attempt info
			attempt.Finding = detectSuccessfulFunctionAuth(&request)
			attempt.TimeSent = startTime
			attempt.TimeReceived = &endTime
			attempt.Request = &request
			attempts = append(attempts, &attempt)
		}

		// Marshal target info
		targetInfo.RequestCount = len(passedXMLRPCFunctions)
		targetInfo.BaselineAttempt = &baselineAttempt
		targetInfo.Attempts = attempts
		targetInfo.EndTimestamp = time.Now()
		targets = append(targets, &targetInfo)
	}
	report.Targets = targets
	report.Errors = allErrors
	return report
}

func detectSuccessfulXmlrpcGrab(requestInfo methodwebtest.RequestInfo) bool {
	// Check if the response contains a valid XML-RPC response
	if requestInfo.ResponseBody == nil {
		return false
	}
	body := *requestInfo.ResponseBody
	return strings.Contains(body, "<methodResponse>") && strings.Contains(body, "<params>")
}

func parseXMLRPCFunctions(responseBody *string) []string {
	if responseBody == nil {
		return []string{}
	}

	// Extract function names from XML response
	var functions []string
	re := regexp.MustCompile(`<value><string>([^<]+)</string></value>`)
	matches := re.FindAllStringSubmatch(*responseBody, -1)

	for _, match := range matches {
		if len(match) > 1 {
			functions = append(functions, match[1])
		}
	}

	return functions
}

func generateFunctionAuthBodyInjectionParam(function string) string {
	// Generate an unauthenticated XML-RPC request for the function
	payload := fmt.Sprintf(`<?xml version="1.0"?>
		<methodCall>
			<methodName>%s</methodName>
			<params>
			</params>
		</methodCall>`, function)

	return payload
}

func detectSuccessfulFunctionAuth(requestInfo *methodwebtest.RequestInfo) *bool {
	success := false
	if requestInfo == nil || requestInfo.ResponseBody == nil {
		return &success
	}

	if requestInfo.StatusCode == nil || *requestInfo.StatusCode != 200 {
		return &success
	}

	body := *requestInfo.ResponseBody
	success = strings.Contains(body, "<param>") &&
		!strings.Contains(body, "Invalid method parameters") &&
		!strings.Contains(body, "<fault>") &&
		!strings.Contains(body, "<name>faultCode</name>")
	return &success
}

package utils

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"strconv"
	"strings"
	"time"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	"github.com/Method-Security/methodwebtest/utils"
)

func RunPathTraversalEngine(ctx context.Context, config *methodwebtest.PathTraversalEngineConfig) *methodwebtest.Report {
	// Initialize report
	report := methodwebtest.Report{}
	var allErrors []string

	// Gather all paths
	allPaths, err := gatherPaths(config.Paths, config.PathFiles)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return &report
	}

	// Parse response codes
	validCodes, err := parseResponseCodes(config.ResponseCodes)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return &report
	}

	var targets []*methodwebtest.TargetInfo
	for _, target := range config.Targets {
		// Check if context has expired
		if ctx.Err() != nil {
			report.Errors = append(report.Errors, "Path traversal engine timeout exceeded")
			break
		}

		targetInfo := methodwebtest.TargetInfo{Target: target, StartTimestamp: time.Now()}
		// Split target
		baseURL, parsedTargetPath, err := utils.SplitTarget(target)
		if err != nil {
			allErrors = append(allErrors, err.Error())
			continue
		}

		// Get baseline size and word count
		baselineSize, baselineWords, err := baseLine(baseURL, parsedTargetPath, false, config.Timeout)
		if err != nil {
			allErrors = append(allErrors, err.Error())
			continue
		}
		log.Println("[info] Baseline size:", baselineSize, "words:", baselineWords)

		baselineSizeRandomPath, baselineWordsRandomPath, err := baseLine(baseURL, "xxxx", false, config.Timeout)
		if err != nil {
			allErrors = append(allErrors, err.Error())
			continue
		}
		log.Println("[info] Baseline size random path:", baselineSizeRandomPath, "words:", baselineWordsRandomPath)

		var attempts []*methodwebtest.AttemptInfo
		for _, injectionPath := range allPaths {
			for i := 0; i <= config.Retries; i++ {
				// Check if context has expired
				if ctx.Err() != nil {
					report.Errors = append(report.Errors, "Path traversal engine timeout exceeded")
					break
				}

				attemptInfo := methodwebtest.AttemptInfo{}

				// Path injection location
				requestParams := methodwebtest.RequestParams{}
				requestPath := fmt.Sprintf("%s/%s", parsedTargetPath, strings.Trim(injectionPath, "/"))
				if config.QueryParam != nil {
					requestPath = parsedTargetPath
					requestParams.QueryParams = map[string]string{*config.QueryParam: injectionPath}
				}

				// Send request
				startTime := time.Now()
				request := utils.PerformRequestScan(
					baseURL,
					requestPath,
					methodwebtest.HttpMethodGet,
					requestParams,
					[]*methodwebtest.EventType{methodwebtest.NewEventTypeFromPathEvent(methodwebtest.PathEventTraversal)},
					config.Timeout, false)
				endTime := time.Now()

				// Need to set for crlf module since it doenst have the threshold flag and defines its own analysis of
				// valid findings
				isValid := false
				if config.Threshold != nil {
					isValid = AnalyzeResponse(request, validCodes, config.IgnoreBaseContent, baselineSize, baselineWords, baselineSizeRandomPath, baselineWordsRandomPath, *config.Threshold)
				}

				// Marshal data
				if !config.SuccessfulOnly || isValid {
					attemptInfo.TimeSent = startTime
					attemptInfo.TimeReceived = &endTime
					attemptInfo.Request = &request
					attemptInfo.Finding = &isValid
					attempts = append(attempts, &attemptInfo)
				}

				if config.Sleep > 0 {
					time.Sleep(time.Duration(config.Sleep) * time.Second)
				}

			}
		}
		targetInfo.Attempts = attempts
		targetInfo.RequestCount = len(attempts)
		targetInfo.EndTimestamp = time.Now()
		targets = append(targets, &targetInfo)
	}

	report.Targets = targets
	report.Errors = allErrors
	return &report
}

// AnalyzeResponse checks if the response singifies that file was found based on the response code and the baseline size and word count
func AnalyzeResponse(request methodwebtest.RequestInfo, validCodes map[int]bool, checkBaseContentMatch bool, baselineSize, baselineWords int, baselineSizeRandomPath, baselineWordsRandomPath int, threshold float64) bool {
	if request.StatusCode == nil || !validCodes[*request.StatusCode] || request.ResponseBody == nil {
		return false
	}

	bodySize := len(*request.ResponseBody)
	if bodySize == 0 {
		return false
	}

	wordCount := len(strings.Fields(*request.ResponseBody))
	// If the response is similar to the baseline or the baseline random path, then it is not a valid finding
	// This is to prevent false positives from remote configurations that dont redirect but give blanket responses on all paths
	if checkBaseContentMatch {
		if (areSimilar(bodySize, baselineSize, threshold) && areSimilar(wordCount, baselineWords, threshold)) ||
			(areSimilar(bodySize, baselineSizeRandomPath, threshold) && areSimilar(wordCount, baselineWordsRandomPath, threshold)) {
			return false
		}
	}
	log.Println("[info] Valid finding:", request.BaseUrl, request.Path, "size:", bodySize, "words:", wordCount)
	return true
}

// baseLine gets the baseline size and word count of the target to be used for validation of the response
func baseLine(baseTarget string, path string, followRedirects bool, timeout int) (int, int, error) {
	request := utils.PerformRequestScan(
		baseTarget,
		path,
		methodwebtest.HttpMethodGet,
		methodwebtest.RequestParams{},
		[]*methodwebtest.EventType{methodwebtest.NewEventTypeFromPathEvent(methodwebtest.PathEventTraversal)},
		timeout, followRedirects)

	if request.ResponseBody == nil {
		return 0, 0, errors.New("failed to get baseline body")
	}

	bodySize := len(*request.ResponseBody)
	wordCount := len(strings.Fields(*request.ResponseBody))

	return bodySize, wordCount, nil
}

// parseResponseCodes parses a comma-separated or range-based string of response codes
// (e.g., "200,301,404-410") and returns a map of valid codes.
func parseResponseCodes(responseCodes string) (map[int]bool, error) {
	validCodes := make(map[int]bool)
	for _, part := range strings.Split(responseCodes, ",") {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			start, err1 := strconv.Atoi(rangeParts[0])
			end, err2 := strconv.Atoi(rangeParts[1])
			if err1 != nil || err2 != nil || start > end {
				return nil, errors.New("invalid response code range")
			}
			for i := start; i <= end; i++ {
				validCodes[i] = true
			}
		} else {
			code, err := strconv.Atoi(part)
			if err != nil {
				return nil, errors.New("invalid response code")
			}
			validCodes[code] = true
		}
	}
	return validCodes, nil
}

func gatherPaths(paths []string, pathLists []string) ([]string, error) {
	pathsFromFiles, err := utils.GetEntriesFromFiles(pathLists)
	if err != nil {
		return nil, err
	}
	allPaths := append(paths, pathsFromFiles...)
	return allPaths, nil
}

// areSimilar is a function that checks if the value is similar to the baseline with a given tolerance
// 0 is exact match
// .50 is 50% difference
// 1.00 is 100% difference
// 2.00 is 200% difference
func areSimilar(value, baseline int, tolerance float64) bool {
	difference := math.Abs(float64(value - baseline))
	percent := difference / float64(baseline)
	return percent <= tolerance
}

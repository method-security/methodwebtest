package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils"
)

func RunMultiInjectionsEngine(ctx context.Context, config *methodwebtest.InjectionEngineConfig) *methodwebtest.Report {
	// Initialize report
	report := methodwebtest.Report{}
	report.Config = methodwebtest.NewEngineConfigFromInjectionEngineConfig(config)
	var allErrors []string

	var targets []*methodwebtest.TargetInfo
	for _, target := range config.Targets {
		targetInfo := methodwebtest.TargetInfo{Target: target, StartTimestamp: time.Now()}

		baseURL, parsedPath, err := utils.SplitTarget(target)
		if err != nil {
			allErrors = append(allErrors, err.Error())
			continue
		}

		var attempts []*methodwebtest.AttemptInfo
		for _, path := range config.Paths {
			if config.BaselinePayload != nil {
				baselineAttemptInfo := methodwebtest.AttemptInfo{}

				baseLinePath := parsedPath + path
				baselineRequestParams := methodwebtest.RequestParams{}
				if len(config.BaselinePayload) > 0 && !(len(config.BaselinePayload) == 1 && config.BaselinePayload[""] == "") {
					baseLinePath, baselineRequestParams, err = generateRequestParams(config.BaselinePayload, parsedPath+path, config.InjectionLocation)
					if err != nil {
						allErrors = append(allErrors, err.Error())
						continue
					}
				}

				startTime := time.Now()
				request := utils.PerformRequestScan(baseURL, baseLinePath, config.Method, baselineRequestParams, []*methodwebtest.EventType{config.EventType}, config.Timeout, config.FollowRedirects)
				endTime := time.Now()

				baselineAttemptInfo.TimeSent = startTime
				baselineAttemptInfo.TimeReceived = &endTime
				baselineAttemptInfo.Request = &request
				targetInfo.BaselineAttempt = &baselineAttemptInfo

			}
			for _, payload := range config.InjectedPayloads {
				for i := 0; i <= config.Retries; i++ {
					attemptInfo := methodwebtest.AttemptInfo{}

					injectedPath, requestParams, err := generateRequestParams(payload, parsedPath+path, config.InjectionLocation)
					if err != nil {
						allErrors = append(allErrors, err.Error())
						continue
					}

					startTime := time.Now()
					request := utils.PerformRequestScan(baseURL, injectedPath, config.Method, requestParams, []*methodwebtest.EventType{config.EventType}, config.Timeout, config.FollowRedirects)
					endTime := time.Now()

					attemptInfo.TimeSent = startTime
					attemptInfo.TimeReceived = &endTime
					attemptInfo.Request = &request
					attempts = append(attempts, &attemptInfo)

					if config.Sleep > 0 {
						time.Sleep(time.Duration(config.Sleep) * time.Second)
					}
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

func generateRequestParams(payload map[string]string, path string, location methodwebtest.InjectionLocation) (string, methodwebtest.RequestParams, error) {
	if location == methodwebtest.InjectionLocationHeader {
		return path, methodwebtest.RequestParams{HeaderParams: payload}, nil
	}
	if location == methodwebtest.InjectionLocationPath {
		injectionedPath := path
		for key, value := range payload {
			injectionedPath = strings.ReplaceAll(injectionedPath, fmt.Sprintf("{%s}", key), fmt.Sprintf("{%s}", value))
		}
		return injectionedPath, methodwebtest.RequestParams{}, nil
	}
	if location == methodwebtest.InjectionLocationQuery {
		return path, methodwebtest.RequestParams{QueryParams: payload}, nil
	}
	if location == methodwebtest.InjectionLocationBody {
		jsonBody, err := json.Marshal(payload)
		if err != nil {
			return "", methodwebtest.RequestParams{}, err
		}
		return path, methodwebtest.RequestParams{BodyParams: string(jsonBody)}, nil
	}
	if location == methodwebtest.InjectionLocationForm {
		return path, methodwebtest.RequestParams{FormParams: payload}, nil
	}
	if location == methodwebtest.InjectionLocationMultipart {
		return path, methodwebtest.RequestParams{MultipartParams: payload}, nil
	}

	return "", methodwebtest.RequestParams{}, errors.New("invalid injection location")
}

func GenerateBaselinePayloads(variableData map[string]string) map[string]string {
	payloadMap := map[string]string{}
	for variableName, variableValue := range variableData {
		payloadMap[variableName] = variableValue
	}
	return payloadMap
}
func GenerateInjectionPayloads(payloads []string, variableData map[string]string) []map[string]string {
	generatedPayloads := []map[string]string{}
	for _, payload := range payloads {
		payloadMap := map[string]string{}
		for variableName, variableValue := range variableData {
			payloadMap[variableName] = variableValue + payload
		}
		generatedPayloads = append(generatedPayloads, payloadMap)
	}
	return generatedPayloads
}

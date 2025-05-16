package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"strings"

	new_ "github.com/Method-Security/methodwebtest/generated/go/new_"
	"github.com/Method-Security/methodwebtest/internal/report"
	"github.com/Method-Security/methodwebtest/internal/runner"
	"github.com/Method-Security/methodwebtest/internal/templates"
)

const fuzzMarker = "0x6D6574686F64"

// proxifyRequest is the shape that LoadTargetsWithHttpData("jsonl") expects.
type proxifyRequest struct {
	URL     string `json:"url"`
	Request struct {
		Header   map[string]string `json:"header"`
		Body     string            `json:"body"`
		Raw      string            `json:"raw"`
		Endpoint string            `json:"endpoint"`
	} `json:"request"`
}

// RunScan for scan mode—unchanged.
func RunScan(ctx context.Context, cfg *new_.Config) (*new_.Report, error) {
	var src []fs.FS
	var err error
	if len(cfg.ScanTypes) > 0 {
		src, err = templates.ScanTypeFS(cfg.ScanTypes, cfg.ScanResourceTypes, cfg.ScanModules)
	} else {
		src, err = templates.ScanFS(cfg.ScanResourceTypes, cfg.ScanModules)
	}
	if err != nil {
		return nil, err
	}
	rCfg := runner.Config{
		Targets:        cfg.Targets,
		FS:             src,
		Threads:        cfg.Threads,
		Proxy:          getProxy(cfg),
		RunMode:        cfg.RunMode,
		SuccessfulOnly: cfg.SuccessfulOnly,
	}
	builder := report.NewBuilder()
	if err := builder.PopulateConfig(cfg); err != nil {
		return nil, err
	}
	return runner.Run(ctx, rCfg, builder)
}

// RunDast builds JSONL entries and invokes runner.Run in dast mode.
func RunDast(ctx context.Context, cfg *new_.Config) (*new_.Report, error) {
	srcFS, err := templates.DastFS(cfg.DastVulnTypes)
	if err != nil {
		return nil, err
	}
	jsonl := buildJSONL(cfg)
	rCfg := runner.Config{
		RawRequests:    jsonl,
		FS:             srcFS,
		Threads:        cfg.Threads,
		Proxy:          getProxy(cfg),
		RunMode:        cfg.RunMode,
		SuccessfulOnly: cfg.SuccessfulOnly,
	}
	builder := report.NewBuilder()
	if err := builder.PopulateConfig(cfg); err != nil {
		return nil, err
	}
	return runner.Run(ctx, rCfg, builder)
}

func buildJSONL(cfg *new_.Config) []string {
	var out []string

	for _, method := range cfg.DastMethods {
		for _, tgt := range cfg.Targets {
			// 1) URL + query
			uStr := strings.ReplaceAll(tgt, "%s", fuzzMarker)
			u, err := url.Parse(uStr)
			if err != nil {
				continue
			}
			q := u.Query()
			for _, p := range cfg.DastParams {
				if strings.EqualFold(string(p.Location), "query") && p.Value != nil {
					v := strings.ReplaceAll(*p.Value, "%s", fuzzMarker)
					q.Add(p.Name, v)
				}
			}
			u.RawQuery = q.Encode()

			// 2) headers & cookies
			hmap := map[string]string{}
			for _, p := range cfg.DastParams {
				if p.Value == nil {
					continue
				}
				v := strings.ReplaceAll(*p.Value, "%s", fuzzMarker)
				switch strings.ToLower(string(p.Location)) {
				case "header":
					hmap[p.Name] = v
				case "cookie":
					if prev, ok := hmap["Cookie"]; ok {
						hmap["Cookie"] = prev + "; " + fmt.Sprintf("%s=%s", p.Name, v)
					} else {
						hmap["Cookie"] = fmt.Sprintf("%s=%s", p.Name, v)
					}
				}
			}

			// 3) collect all body params for non-GET/HEAD
			bodyParams := url.Values{}
			if !strings.EqualFold(string(method), "GET") &&
				!strings.EqualFold(string(method), "HEAD") {
				for _, p := range cfg.DastParams {
					if strings.EqualFold(string(p.Location), "body") && p.Value != nil {
						v := strings.ReplaceAll(*p.Value, "%s", fuzzMarker)
						bodyParams.Add(p.Name, v)
					}
				}
			}
			body := bodyParams.Encode()

			// 4) build raw HTTP string
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n",
				method, u.RequestURI()))
			sb.WriteString(fmt.Sprintf("Host: %s\r\n", u.Host))

			if body != "" {
				// include content headers
				sb.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
				sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
			}
			for k, v := range hmap {
				sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
			}
			sb.WriteString("\r\n")
			if body != "" {
				sb.WriteString(body)
			}
			raw := sb.String()

			// 5) marshal into proxifyRequest JSON
			var pr proxifyRequest
			pr.URL = u.String()
			pr.Request.Header = hmap
			pr.Request.Body = body
			pr.Request.Endpoint = u.RequestURI()
			pr.Request.Raw = raw

			j, err := json.Marshal(pr)
			if err != nil {
				continue
			}
			out = append(out, string(j))
		}
	}
	return out
}
func getProxy(cfg *new_.Config) string {
	if cfg.Proxy != nil {
		return *cfg.Proxy
	}
	return ""
}

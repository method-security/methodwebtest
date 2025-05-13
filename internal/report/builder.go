// internal/report/builder.go
//
// Streams nuclei templates and ResultEvents into a Fern-shaped *gen.Report,
// parsing raw request/response dumps for full HTTP detail.
package report

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
	"sync"

	gen "github.com/Method-Security/webscan2/generated/go"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	nout "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// Builder accumulates templates and events into a Fern Report.
type Builder struct {
	mu        sync.Mutex
	report    *gen.Report
	probeIdx  map[string]*gen.Probe      // template-id → Probe
	targetIdx map[string]*gen.TargetInfo // host/baseURL → TargetInfo
}

// NewBuilder returns an empty Builder ready to be populated.
func NewBuilder() *Builder {
	return &Builder{
		report:    &gen.Report{},
		probeIdx:  make(map[string]*gen.Probe),
		targetIdx: make(map[string]*gen.TargetInfo),
	}
}

// PopulateProbes parses every template in the engine and creates one Probe per template.
func (b *Builder) PopulateProbes(eng *nuclei.NucleiEngine) error {
	if err := eng.LoadAllTemplates(); err != nil {
		return err
	}
	for _, tpl := range eng.GetTemplates() {
		id := tpl.ID
		if _, exists := b.probeIdx[id]; exists {
			continue
		}
		// start with empty payload slice so JSON is "[]" not "null"
		pr := &gen.Probe{
			Id:               id,
			Payloads:         []string{},
			ExpectedMatchers: []*gen.ExpectedMatcher{},
		}
		// tpl.RequestsHTTP (each is *requests.HTTPRequest) has Payloads as interface{}
		for _, req := range tpl.RequestsHTTP {
			// Payloads
			for _, raw := range req.Payloads {
				switch vals := raw.(type) {
				case []string:
					pr.Payloads = append(pr.Payloads, vals...)
				case []interface{}:
					for _, iv := range vals {
						if s, ok := iv.(string); ok {
							pr.Payloads = append(pr.Payloads, s)
						}
					}
				}
			}
			// ExpectedMatchers
			for _, ma := range req.Matchers {
				vals := []string{}
				if len(ma.Words) > 0 {
					vals = append(vals, ma.Words...)
				}
				if len(ma.Regex) > 0 {
					vals = append(vals, ma.Regex...)
				}
				pr.ExpectedMatchers = append(pr.ExpectedMatchers, &gen.ExpectedMatcher{
					Type:  ma.Type.String(),
					Value: vals,
				})
			}
		}

		b.probeIdx[id] = pr
		b.report.Probes = append(b.report.Probes, pr)
	}
	return nil
}

// Consume must be called for each ResultEvent emitted by the engine.
func (b *Builder) Consume(ev *nout.ResultEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 1. Probe lookup (fallback to a minimal one if absent)
	pr, exists := b.probeIdx[ev.TemplateID]
	if !exists {
		pr = &gen.Probe{Id: ev.TemplateID}
		b.probeIdx[ev.TemplateID] = pr
		b.report.Probes = append(b.report.Probes, pr)
	}

	// 2. bucket by host/baseURL
	host := hostKey(ev)
	tg, ok := b.targetIdx[host]
	if !ok {
		tg = &gen.TargetInfo{
			Target: host,
		}
		b.targetIdx[host] = tg
		b.report.Targets = append(b.report.Targets, tg)
	}

	// 3. Build AttemptInfo
	at := &gen.AttemptInfo{
		ProbeId:  pr.Id,
		Request:  toRequestInfo(ev),
		TimeSent: ev.Timestamp,
	}

	if hasTag(ev.Info.Tags.ToSlice(), "fingerprint") {
		// Fingerprinting: pull extracted header/body value
		var name string
		if len(ev.ExtractedResults) > 0 {
			name = ev.ExtractedResults[0]
		}
		at.Finding = &gen.FindingInfo{
			Name:    strPtr(name),
			Finding: name != "",
			// informational, so leave severity nil
			Tags: ev.Info.Tags.ToSlice(),
		}
	} else {
		// Default vuln/match logic
		at.Finding = &gen.FindingInfo{
			Name:     strPtr(ev.MatcherName),
			Finding:  ev.MatcherStatus,
			Severity: strPtr(ev.Info.SeverityHolder.Severity.String()),
			Tags:     ev.Info.Tags.ToSlice(),
		}
	}

	tg.Attempts = append(tg.Attempts, at)
	tg.RequestCount++
}

// Final returns the populated Report. Call after all events have been consumed.
func (b *Builder) Final() *gen.Report {
	return b.report
}

/* -------------------------------------------------------------------------- */
/*                               Helpers                                      */
/* -------------------------------------------------------------------------- */

func hostKey(ev *nout.ResultEvent) string {
	if u, err := url.Parse(ev.URL); err == nil && u.Host != "" {
		return u.Host
	}
	return ev.Host
}

// toRequestInfo parses raw request/response dumps into RequestInfo.
func toRequestInfo(ev *nout.ResultEvent) *gen.RequestInfo {
	ri := &gen.RequestInfo{
		PathParams:   map[string]string{},
		QueryParams:  map[string]string{},
		HeaderParams: map[string]string{},
	}

	// 1) BaseUrl
	if parsed, err := url.Parse(ev.URL); err == nil {
		ri.BaseUrl = parsed.Scheme + "://" + parsed.Host
	}

	// 2) Raw request → method, path override, headers, body
	method, path, reqHeaders, reqBody := parseRawRequest(ev.Request)
	if m, err := gen.NewHttpMethodFromString(strings.ToUpper(method)); err == nil {
		ri.Method = m
	}

	// override path + extract queryParams
	if path != "" {
		if u2, err := url.Parse(path); err == nil {
			ri.Path = u2.Path
			for k, vs := range u2.Query() {
				if len(vs) > 0 {
					ri.QueryParams[k] = vs[0]
				}
			}
		} else {
			ri.Path = path
		}
	}

	// headers & body
	ri.HeaderParams = reqHeaders
	if reqBody != "" {
		ri.BodyParams = &reqBody
	}

	// 3) Raw response → status, headers, body
	code, respHeaders, respBody := parseRawResponse(ev.Response)
	if code != 0 {
		ri.StatusCode = &code
	}
	ri.ResponseHeaders = respHeaders
	if respBody != "" {
		ri.ResponseBody = &respBody
		ri.ResponseBodyEncoded = ptrString(base64.StdEncoding.EncodeToString([]byte(respBody)))
	}

	// 4) Errors
	if ev.Error != "" {
		ri.Errors = []string{ev.Error}
	}

	return ri
}

func parseRawRequest(raw string) (method, path string, headers map[string]string, body string) {
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	headers = map[string]string{}
	// first section: request-line + headers
	lines := strings.Split(parts[0], "\r\n")
	if len(lines) > 0 {
		fields := strings.Fields(lines[0])
		if len(fields) >= 2 {
			method, path = fields[0], fields[1]
		}
		for _, h := range lines[1:] {
			if kv := strings.SplitN(h, ":", 2); len(kv) == 2 {
				headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}
	// body after blank line
	if len(parts) == 2 {
		body = parts[1]
	}
	return
}

func parseRawResponse(raw string) (statusCode int, headers map[string]string, body string) {
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	headers = map[string]string{}
	// status-line + headers
	lines := strings.Split(parts[0], "\r\n")
	if len(lines) > 0 {
		if fields := strings.Fields(lines[0]); len(fields) >= 2 {
			if code, err := strconv.Atoi(fields[1]); err == nil {
				statusCode = code
			}
		}
		for _, h := range lines[1:] {
			if kv := strings.SplitN(h, ":", 2); len(kv) == 2 {
				headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}
	// body after blank line
	if len(parts) == 2 {
		body = parts[1]
	}
	return
}

// hasTag returns true if the template info tags include want.
func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func ptrString(s string) *string { return &s }

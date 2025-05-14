package report

import (
	"net/url"
	"strconv"
	"strings"
	"sync"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	nout "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

/* ------------------------------------------------------------------ */
/* Builder                                                            */
/* ------------------------------------------------------------------ */

type Builder struct {
	mu        sync.Mutex
	report    *methodwebtest.Report
	probeIdx  map[string]*methodwebtest.Probe      // template-id → Probe
	targetIdx map[string]*methodwebtest.TargetInfo // host/baseURL → TargetInfo
}

func NewBuilder() *Builder {
	return &Builder{
		report:    &methodwebtest.Report{},
		probeIdx:  make(map[string]*methodwebtest.Probe),
		targetIdx: make(map[string]*methodwebtest.TargetInfo),
	}
}

func (b *Builder) PopulateConfig(cfg *methodwebtest.Config) error {
	b.report.Config = cfg
	return nil
}

/* ---------------- template enumeration ---------------------------- */

func (b *Builder) PopulateProbes(eng *nuclei.NucleiEngine) error {
	if err := eng.LoadAllTemplates(); err != nil {
		return err
	}
	for _, tpl := range eng.GetTemplates() {
		id := tpl.ID
		if _, ok := b.probeIdx[id]; ok {
			continue
		}
		pr := &methodwebtest.Probe{
			Id:               id,
			Payloads:         []string{},
			ExpectedMatchers: []*methodwebtest.ExpectedMatcher{},
		}
		for _, req := range tpl.RequestsHTTP {
			// payloads
			for _, raw := range req.Payloads {
				switch v := raw.(type) {
				case []string:
					pr.Payloads = append(pr.Payloads, v...)
				case []interface{}:
					for _, iv := range v {
						if s, ok := iv.(string); ok {
							pr.Payloads = append(pr.Payloads, s)
						}
					}
				}
			}
			// expected matchers
			for _, ma := range req.Matchers {
				vals := append(ma.Words, ma.Regex...)
				pr.ExpectedMatchers = append(pr.ExpectedMatchers, &methodwebtest.ExpectedMatcher{
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

/* ---------------- event consumption ------------------------------- */

func (b *Builder) Consume(ev *nout.ResultEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	/* probe ----------------------------------------------------------- */
	pr, ok := b.probeIdx[ev.TemplateID]
	if !ok {
		pr = &methodwebtest.Probe{Id: ev.TemplateID}
		b.probeIdx[ev.TemplateID] = pr
		b.report.Probes = append(b.report.Probes, pr)
	}

	/* bucket by host -------------------------------------------------- */
	host := hostKey(ev)
	tg, ok := b.targetIdx[host]
	if !ok {
		tg = &methodwebtest.TargetInfo{Target: host}
		b.targetIdx[host] = tg
		b.report.Targets = append(b.report.Targets, tg)
	}

	/* build AttemptInfo ---------------------------------------------- */
	at := &methodwebtest.AttemptInfo{
		ProbeId:             pr.Id,
		HttpRequestResponse: toReqResp(ev),
	}

	at.Finding = &methodwebtest.FindingInfo{
		Name:     strPtr(ev.MatcherName),
		Finding:  ev.MatcherStatus,
		Severity: strPtr(ev.Info.SeverityHolder.Severity.String()),
		Tags:     ev.Info.Tags.ToSlice(),
	}

	tg.Attempts = append(tg.Attempts, at)
	tg.RequestCount++
}

// Final returns the fully-populated Fern report. Call it after all
// ResultEvents have been consumed.
func (b *Builder) Final() *methodwebtest.Report {
	return b.report
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

func hostKey(ev *nout.ResultEvent) string {
	if u, err := url.Parse(ev.URL); err == nil && u.Host != "" {
		return u.Host
	}
	return ev.Host
}

/* ---------- HttpRequestResponse construction ---------------------- */

func toReqResp(ev *nout.ResultEvent) *methodwebtest.HttpRequestResponse {
	req := &methodwebtest.HttpRequest{
		BaseHeaders: map[string][]string{},
		Timestamp:   ev.Timestamp,
	}
	resp := &methodwebtest.HttpResponse{
		ResponseHeaders: map[string][]string{},
	}

	/* ---------- request part --------------------------------------- */
	method, path, hdr, body := parseRawRequest(ev.Request)

	if m, err := methodwebtest.NewHttpMethodFromString(strings.ToUpper(method)); err == nil {
		req.Method = m
	}
	req.BaseHeaders = singleToMulti(hdr)

	// split BaseUrl / Path / QueryParams
	if p, err := url.Parse(ev.URL); err == nil {
		req.BaseUrl = p.Scheme + "://" + p.Host
	}
	req.Path = path

	params := &methodwebtest.RequestParams{
		Path:  &path,
		Query: map[string]string{},
	}
	if body != "" {
		params.Body = methodwebtest.NewBodyFromText(&methodwebtest.TextBody{Value: body})
	}
	if u2, err := url.Parse(path); err == nil {
		for k, vs := range u2.Query() {
			if len(vs) > 0 {
				params.Query[k] = vs[0]
			}
		}
	}
	req.Parameters = params

	/* ---------- response part -------------------------------------- */
	code, rh, rbody := parseRawResponse(ev.Response)
	if code != 0 {
		resp.StatusCode = &code
	}
	resp.ResponseHeaders = singleToMulti(rh)
	if rbody != "" {
		resp.SizeBytes = ptrInt(len(rbody))
		resp.ResponseBody = methodwebtest.NewBodyFromText(&methodwebtest.TextBody{
			Value: rbody,
		})
	}

	if ev.Error != "" {
		resp.Errors = []string{ev.Error}
	}

	return &methodwebtest.HttpRequestResponse{
		Request:  req,
		Response: resp,
	}
}

/* -------- raw (request|response) parsing -------------------------- */

func parseRawRequest(raw string) (method, path string, headers map[string]string, body string) {
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	headers = map[string]string{}
	lines := strings.Split(parts[0], "\r\n")
	if len(lines) > 0 {
		if f := strings.Fields(lines[0]); len(f) >= 2 {
			method, path = f[0], f[1]
		}
		for _, h := range lines[1:] {
			if kv := strings.SplitN(h, ":", 2); len(kv) == 2 {
				headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}
	if len(parts) == 2 {
		body = parts[1]
	}
	return
}

func parseRawResponse(raw string) (code int, headers map[string]string, body string) {
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	headers = map[string]string{}
	lines := strings.Split(parts[0], "\r\n")
	if len(lines) > 0 {
		if f := strings.Fields(lines[0]); len(f) >= 2 {
			if c, err := strconv.Atoi(f[1]); err == nil {
				code = c
			}
		}
		for _, h := range lines[1:] {
			if kv := strings.SplitN(h, ":", 2); len(kv) == 2 {
				headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}
	if len(parts) == 2 {
		body = parts[1]
	}
	return
}

/* -------- misc ---------------------------------------------------- */

func singleToMulti(m map[string]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range m {
		out[k] = []string{v}
	}
	return out
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
func ptrInt(i int) *int { return &i }

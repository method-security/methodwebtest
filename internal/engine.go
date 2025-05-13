// internal/engine/engine.go
//
// Converts a high-level Config (from CLI / SDK) into a runner.Config,
// selects the right template subset via internal/templates helpers,
// captures stdout from runner.Scan, and returns a *methodwebtest.Report.

package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	"github.com/Method-Security/methodwebtest/internal/runner"
	"github.com/Method-Security/methodwebtest/internal/templates"
)

func RunScan(ctx context.Context, cfg *methodwebtest.Config) (*methodwebtest.Report, error) {
	src, err := templates.ScanFS(cfg.ScanResourceTypes, cfg.ScanModules)
	if err != nil {
		return nil, err
	}
	return execute(ctx, cfg, src, nil, nil)
}

// RunFuzz for “fuzz” commands: build constants, injection key, rewrite URLs
func RunFuzz(ctx context.Context, cfg *methodwebtest.Config) (*methodwebtest.Report, error) {
	// 1) load only the requested fuzz templates
	srcFS, err := templates.FuzzFS(cfg.FuzzVulnTypes)
	if err != nil {
		return nil, err
	}

	// 2) build runtime buckets
	var (
		vars      []string       // for nuclei.WithVars("key=value")
		headers   []string       // for nuclei.WithHeaders("Header:Value")
		extraQ    = url.Values{} // constant query params
		extraP    string         // constant path prefix
		injectKey string         // single injection parameter name
	)

	for _, p := range cfg.FuzzParams {
		if p.Value == nil {
			continue
		}
		switch p.Location {
		case "query":
			if *p.Value == "%s" {
				// this is the one we fuzz
				injectKey = p.Name
				vars = append(vars, fmt.Sprintf("inject_key=%s", p.Name))
			} else {
				extraQ.Set(p.Name, *p.Value)
				vars = append(vars, fmt.Sprintf("%s=%s", p.Name, *p.Value))
			}
		case "header":
			h := fmt.Sprintf("%s:%s", p.Name, *p.Value)
			headers = append(headers, h)
			// also as a variable inside templates
			key := strings.ToLower(strings.ReplaceAll(p.Name, "-", "_"))
			vars = append(vars, fmt.Sprintf("%s=%s", key, *p.Value))
		case "path":
			if *p.Value != "" {
				extraP = path.Join(extraP, *p.Value)
				vars = append(vars, fmt.Sprintf("path_prefix=%s", *p.Value))
			}
		case "body":
			if *p.Value == "%s" {
				injectKey = p.Name
				vars = append(vars, fmt.Sprintf("inject_key=%s", p.Name))
			} else if *p.Value != "" {
				vars = append(vars, fmt.Sprintf("%s=%s", p.Name, *p.Value))
			}
		}
	}

	// 3) rewrite each target so that both constant params AND the injection
	//    key appear in the URL (so nuclei’s fuzz “keys:” will match)
	fixed := make([]string, 0, len(cfg.Targets))
	for _, raw := range cfg.Targets {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		// prepend any constant path segments
		if extraP != "" {
			u.Path = path.Join(extraP, u.Path)
		}
		// merge constant query params
		q := u.Query()
		for k, vs := range extraQ {
			q[k] = vs
		}
		// ensure the injection key is present (even if empty)
		if injectKey != "" {
			if _, exists := q[injectKey]; !exists {
				q.Set(injectKey, "")
			}
		}
		u.RawQuery = q.Encode()
		fixed = append(fixed, u.String())
	}
	cfg.Targets = fixed

	// 4) hand off to the shared execute
	return execute(ctx, cfg, srcFS, vars, headers)
}

/* --------------------------------------------------------------------- */

func execute(parent context.Context, cfg *methodwebtest.Config, srcFS []fs.FS, varList []string, hdrList []string) (*methodwebtest.Report, error) {
	if len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("engine: no targets")
	}

	// optional timeout
	ctx := parent
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parent, time.Duration(cfg.Timeout)*time.Second)
		defer cancel()
	}

	proxy := ""
	if cfg.Proxy != nil {
		proxy = *cfg.Proxy
	}

	rCfg := runner.Config{
		Targets: cfg.Targets,
		Threads: cfg.Threads,
		FS:      srcFS, // <- pass slice directly
		Vars:    varList,
		Headers: hdrList,
		Proxy:   proxy,
		RunMode: cfg.RunMode,
	}

	/* --- capture stdout from runner.Scan -------------------------------- */
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	rep, runErr := runner.Scan(ctx, rCfg)

	w.Close()
	os.Stdout = orig
	if runErr != nil {
		return nil, runErr
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, fmt.Errorf("engine: reading scan output: %w", err)
	}

	return rep, nil
}

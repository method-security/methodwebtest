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

func RunFuzz(ctx context.Context, cfg *methodwebtest.Config) (*methodwebtest.Report, error) {
	src, err := templates.FuzzFS(cfg.FuzzVulnTypes)
	if err != nil {
		return nil, err
	}

	// -------- build runtime buckets ---------------------------------
	varList := []string{}  // "key=value"
	hdrList := []string{}  // "Header:Value"
	extraQ := url.Values{} // constant ?k=v
	extraPath := ""

	for _, p := range cfg.FuzzParams {
		switch {
		case p.Location == "query" && p.Value != nil && *p.Value == "%s":
			// placeholder param
			varList = append(varList, fmt.Sprintf("query_param=%s", p.Name))
		case p.Location == "query":
			extraQ.Set(p.Name, *p.Value)
		case p.Location == "header":
			hdrList = append(hdrList, fmt.Sprintf("%s:%s", p.Name, *p.Value))
		case p.Location == "path":
			extraPath = path.Join(extraPath, *p.Value)
		case p.Location == "body" && p.Value != nil && *p.Value == "%s":
			varList = append(varList, p.Name)
		}
	}

	// -------- rewrite targets once ----------------------------------
	fixed := make([]string, 0, len(cfg.Targets))
	for _, t := range cfg.Targets {
		u, _ := url.Parse(t)
		u.Path = path.Join(extraPath, u.Path)
		q := u.Query()
		for k, v := range extraQ {
			q[k] = v
		}
		u.RawQuery = q.Encode()
		fixed = append(fixed, u.String())
	}

	// -------- hand everything to execute ----------------------------
	cfg.Targets = fixed
	return execute(ctx, cfg, src, varList, hdrList)
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

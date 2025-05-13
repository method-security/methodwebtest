// internal/runner/runner.go
package runner

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	gen "github.com/Method-Security/methodwebtest/generated/go"
	"github.com/Method-Security/methodwebtest/internal/report"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
)

type Config struct {
	Targets []string
	FS      []fs.FS  // one or many sources (usually fs.Sub views)
	Vars    []string // nuclei -WithCustomVariables
	Headers []string // nuclei -WithCustomHeaders ("Key: Value")
	Threads int
	Proxy   string
	RunMode gen.RunMode
}

// Scan runs nuclei and returns a *gen.Report built by report.Builder.
func Scan(ctx context.Context, cfg Config) (*gen.Report, error) {
	if len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("runner: no targets")
	}
	if cfg.Threads <= 0 {
		cfg.Threads = 25
	}

	/* ---- 1. copy selected templates into one temp dir ----------------- */
	tmpDir, err := os.MkdirTemp("", "methodwebtest-tpl-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	for idx, src := range cfg.FS {
		err := fs.WalkDir(src, ".", func(p string, d fs.DirEntry, walkErr error) error {
			// 1) if WalkDir itself had an error, bail out
			if walkErr != nil {
				return walkErr
			}
			// 2) skip directories
			if d.IsDir() {
				return nil
			}
			// 3) only YAML/YML
			ext := filepath.Ext(p)
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}
			// 4) read and write
			data, err := fs.ReadFile(src, p)
			if err != nil {
				return err
			}
			dst := filepath.Join(tmpDir, fmt.Sprintf("%02d-%s", idx, filepath.Base(p)))
			return os.WriteFile(dst, data, 0o600)
		})
		if err != nil {
			return nil, err
		}
	}

	/* ---- 2. nuclei engine options ------------------------------------ */
	opts := []nuclei.NucleiSDKOptions{
		nuclei.WithTemplatesOrWorkflows(
			nuclei.TemplateSources{Templates: []string{tmpDir}},
		),
		nuclei.EnableSelfContainedTemplates(),
		nuclei.DisableUpdateCheck(),
		nuclei.WithConcurrency(nuclei.Concurrency{
			HeadlessHostConcurrency:       cfg.Threads,
			HostConcurrency:               cfg.Threads,
			TemplateConcurrency:           cfg.Threads,
			TemplatePayloadConcurrency:    cfg.Threads,
			HeadlessTemplateConcurrency:   cfg.Threads,
			JavascriptTemplateConcurrency: cfg.Threads,
			ProbeConcurrency:              cfg.Threads,
		}),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{Silent: true}),
		//nuclei.EnableMatcherStatus(),
	}
	if len(cfg.Vars) > 0 {
		opts = append(opts, nuclei.WithVars(cfg.Vars))
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, nuclei.WithHeaders(cfg.Headers))
	}
	if cfg.RunMode == gen.RunModeFuzz {
		opts = append(opts, nuclei.DASTMode())
	}
	if cfg.Proxy != "" {
		opts = append(opts, nuclei.WithProxy([]string{cfg.Proxy}, true))
	}

	/* ---- 3. run nuclei ------------------------------------------------- */
	eng, err := nuclei.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		return nil, err
	}
	defer eng.Close()

	eng.LoadTargets(cfg.Targets, false)

	builder := report.NewBuilder()
	if err := builder.PopulateProbes(eng); err != nil {
		return nil, err
	}

	if err := eng.ExecuteCallbackWithCtx(ctx, builder.Consume); err != nil {
		return nil, err
	}

	return builder.Final(), nil
}

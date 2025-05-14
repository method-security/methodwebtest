// internal/runner/runner.go
package runner

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	"github.com/Method-Security/methodwebtest/internal/report"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
)

type Config struct {
	Targets     []string
	RawRequests []string // JSONL lines when fuzzing
	FS          []fs.FS  // template sources
	Headers     []string // extra headers (optional)
	Threads     int
	Proxy       string
	RunMode     methodwebtest.RunMode
}

func validateConfig(cfg Config) error {
	if cfg.RunMode == methodwebtest.RunModeFuzz {
		if len(cfg.RawRequests) == 0 {
			return fmt.Errorf("runner: no RawRequests provided for fuzz mode")
		}
	} else {
		if len(cfg.Targets) == 0 {
			return fmt.Errorf("runner: no Targets provided for scan mode")
		}
	}
	if cfg.Threads <= 0 {
		cfg.Threads = 25
	}
	return nil
}

func copyTemplatesToTmpDir(cfg Config) (string, error) {
	tmpDir, err := os.MkdirTemp("", "methodwebtest-tpl-*")
	if err != nil {
		return "", err
	}
	for idx, src := range cfg.FS {
		_ = fs.WalkDir(src, ".", func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			ext := filepath.Ext(p)
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}
			data, err := fs.ReadFile(src, p)
			if err != nil {
				return err
			}
			dst := filepath.Join(tmpDir, fmt.Sprintf("%02d-%s", idx, filepath.Base(p)))
			return os.WriteFile(dst, data, 0o600)
		})
	}
	return tmpDir, nil
}

func buildNucleiOptions(cfg Config, tmpDir string) []nuclei.NucleiSDKOptions {
	opts := []nuclei.NucleiSDKOptions{
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{tmpDir}}),
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
		nuclei.EnableMatcherStatus(),
	}

	if cfg.RunMode == methodwebtest.RunModeFuzz {
		opts = append(opts, nuclei.DASTMode())
	}

	// proxy
	if cfg.Proxy != "" {
		opts = append(opts, nuclei.WithProxy([]string{cfg.Proxy}, false))
	}

	return opts
}

func loadTargets(eng *nuclei.NucleiEngine, cfg Config) error {
	if cfg.RunMode == methodwebtest.RunModeFuzz {
		// write JSONL to temp file
		f, err := os.CreateTemp("", "requests-*.jsonl")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		for _, line := range cfg.RawRequests {
			if _, err := f.WriteString(line + "\n"); err != nil {
				return err
			}
		}
		f.Sync()

		// tell Nuclei to parse JSONL
		if err := eng.LoadTargetsWithHttpData(f.Name(), "jsonl"); err != nil {
			return err
		}
	} else {
		// scan mode: by URL
		eng.LoadTargets(cfg.Targets, false)
	}
	return nil
}

func Run(ctx context.Context, cfg Config) (*methodwebtest.Report, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	tmpDir, err := copyTemplatesToTmpDir(cfg)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	opts := buildNucleiOptions(cfg, tmpDir)

	eng, err := nuclei.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		return nil, err
	}
	defer eng.Close()

	if err := loadTargets(eng, cfg); err != nil {
		return nil, err
	}

	builder := report.NewBuilder()
	if err := builder.PopulateProbes(eng); err != nil {
		return nil, err
	}
	if err := eng.ExecuteCallbackWithCtx(ctx, builder.Consume); err != nil {
		return nil, err
	}
	return builder.Final(), nil
}

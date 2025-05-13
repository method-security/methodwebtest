package runner

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Method-Security/methodwebtest/internal/report"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type Config struct {
	Targets []string
	FS      embed.FS
	Threads int
	Proxy   string
}

// Scan runs nuclei against the given targets and prints a Fern-shaped JSON Report.
func Scan(ctx context.Context, cfg Config) error {
	if len(cfg.Targets) == 0 {
		return fmt.Errorf("no targets")
	}
	if cfg.Threads <= 0 {
		cfg.Threads = 25
	}

	/* --- 1. extract embedded templates to a temp dir ------------ */
	tmpDir, err := os.MkdirTemp("", "webscan2-tpl-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	if err := fs.WalkDir(cfg.FS, ".", func(p string, d fs.DirEntry, _ error) error {
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(p)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := cfg.FS.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(tmpDir, filepath.Base(p)), data, 0o600)
	}); err != nil {
		return err
	}

	/* --- 2. output writer (pretty JSON, include req/resp) ------- */
	stdJSON, err := output.NewWriter(
		output.WithJson(true, true), // pretty, dump req/resp
		output.WithTimestamp(true),
	)
	if err != nil {
		return err
	}
	defer stdJSON.Close()

	/* --- 3. engine options -------------------------------------- */
	opts := []nuclei.NucleiSDKOptions{
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{tmpDir}}),
		nuclei.EnableSelfContainedTemplates(),
		nuclei.DisableUpdateCheck(),
		nuclei.WithConcurrency(nuclei.Concurrency{
			HeadlessHostConcurrency:       cfg.Threads,
			HostConcurrency:               cfg.Threads, // ← add this
			TemplateConcurrency:           cfg.Threads,
			TemplatePayloadConcurrency:    cfg.Threads, // optional but safe
			HeadlessTemplateConcurrency:   cfg.Threads,
			JavascriptTemplateConcurrency: cfg.Threads,
			ProbeConcurrency:              cfg.Threads,
		}),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{Silent: true}),
		nuclei.EnableMatcherStatus(),
	}

	if cfg.Proxy != "" {
		opts = append(opts, nuclei.WithProxy([]string{cfg.Proxy}, false))
	}

	/* --- 4. run engine / build report --------------------------- */
	eng, err := nuclei.NewNucleiEngineCtx(ctx, opts...)
	for _, tpl := range eng.GetTemplates() {
		fmt.Fprintln(os.Stderr, "LOADED TEMPLATE:", tpl.ID)
	}
	if err != nil {
		return err
	}
	defer eng.Close()

	eng.LoadTargets(cfg.Targets, false)

	builder := report.NewBuilder()
	if err := builder.PopulateProbes(eng); err != nil {
		return err
	}

	if err := eng.ExecuteCallbackWithCtx(ctx, func(ev *output.ResultEvent) {
		builder.Consume(ev) // populate Fern report
	}); err != nil {
		return err
	}

	final := builder.Final()

	/* --- 5. marshal and print ----------------------------------- */
	raw, err := json.MarshalIndent(final, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(raw))
	return nil
}

package templates

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	new_ "github.com/Method-Security/methodwebtest/generated/go/new_"
)

/* ---------------- public helper API ---------------- */

// ScanFS remains unchanged
func ScanFS(rTypes []new_.ResourceType, modules []string) ([]fs.FS, error) {
	rTypes, err := wantResource(rTypes)
	if err != nil {
		return nil, err
	}
	modSet := normalize(modules)

	var out []fs.FS
	for _, rt := range rTypes {
		base := filepath.Join("pentest", "scan", strings.ToLower(string(rt)))
		if len(modSet) == 0 {
			if sub, err := fs.Sub(All, base); err == nil {
				out = append(out, sub)
			}
			continue
		}
		for m := range modSet {
			p := filepath.Join(base, strings.ToLower(m))
			if sub, err := fs.Sub(All, p); err == nil {
				out = append(out, sub)
			}
		}
	}
	return out, nil
}

// FuzzFS now only recognizes SQLI, XSS, SSTI, COMMAND_INJECTION
func FuzzFS(vTypes []new_.VulnType) ([]fs.FS, error) {
	vTypes, err := wantVuln(vTypes)
	if err != nil {
		return nil, err
	}
	var out []fs.FS
	for _, vt := range vTypes {
		base := filepath.Join("pentest", "fuzz", strings.ToLower(string(vt)))
		sub, err := fs.Sub(All, base)
		if err != nil {
			return nil, fmt.Errorf("no templates under %q: %w", base, err)
		}
		out = append(out, sub)
	}
	return out, nil
}

/* ---------------- tiny helpers ---------------- */

func wantResource(in []new_.ResourceType) ([]new_.ResourceType, error) {
	all := []new_.ResourceType{
		new_.ResourceTypeApi,
		new_.ResourceTypeCms,
		new_.ResourceTypeWebserver,
	}
	if len(in) == 0 {
		return all, nil
	}
	for _, rt := range in {
		switch rt {
		case new_.ResourceTypeApi, new_.ResourceTypeCms, new_.ResourceTypeWebserver:
		default:
			return nil, fmt.Errorf("unknown resource type %q", rt)
		}
	}
	return in, nil
}

func wantVuln(in []new_.VulnType) ([]new_.VulnType, error) {
	// exactly match the enum in your Fern spec
	all := []new_.VulnType{
		new_.VulnTypeSqli,
		new_.VulnTypeXss,
		new_.VulnTypeSsti,
		new_.VulnTypeCommandInjection,
	}
	if len(in) == 0 {
		return all, nil
	}
	// membership set
	valid := map[new_.VulnType]struct{}{
		new_.VulnTypeSqli:             {},
		new_.VulnTypeXss:              {},
		new_.VulnTypeSsti:             {},
		new_.VulnTypeCommandInjection: {},
	}
	for _, vt := range in {
		if _, ok := valid[vt]; !ok {
			return nil, fmt.Errorf("unknown vuln type %q", vt)
		}
	}
	return in, nil
}

func normalize(ms []string) map[string]struct{} {
	if len(ms) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(ms))
	for _, m := range ms {
		if v := strings.ToLower(strings.TrimSpace(m)); v != "" {
			out[v] = struct{}{}
		}
	}
	return out
}

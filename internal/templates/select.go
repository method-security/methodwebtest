package templates

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	new_ "github.com/Method-Security/methodwebtest/generated/go/new_"
)

// All is the pentest templates
//
//go:embed pentest
var All embed.FS

// subFS walks “pentest/<kind>/<subs…>” and returns each matching fs.FS or an error.
func subFS(kind string, subs []string) ([]fs.FS, error) {
	var out []fs.FS
	for _, s := range subs {
		p := filepath.Join("pentest", kind, s)
		sub, err := fs.Sub(All, p)
		if err != nil {
			return nil, fmt.Errorf("no templates under %q: %w", p, err)
		}
		out = append(out, sub)
	}
	return out, nil
}

func ScanFS(rTypes []new_.ResourceType, modules []string) ([]fs.FS, error) {
	// Validate & default
	rTypes, err := wantResource(rTypes)
	if err != nil {
		return nil, err
	}

	// Build the “scan/<resource>/<module>” paths
	var subs []string
	for _, rt := range rTypes {
		rtName := strings.ToLower(string(rt))
		if len(modules) == 0 {
			subs = append(subs, rtName)
		} else {
			for _, m := range modules {
				m = strings.ToLower(strings.TrimSpace(m))
				if m == "" {
					continue
				}
				subs = append(subs, filepath.Join(rtName, m))
			}
		}
	}

	return subFS("scan", subs)
}

func FuzzFS(vTypes []new_.VulnType) ([]fs.FS, error) {
	// Validate & default
	vTypes, err := wantVuln(vTypes)
	if err != nil {
		return nil, err
	}

	// Build the “fuzz/<vuln>” paths
	var subs []string
	for _, vt := range vTypes {
		subs = append(subs, strings.ToLower(string(vt)))
	}

	return subFS("fuzz", subs)
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

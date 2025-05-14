package templates

import "embed"

// All contains every embedded pentest template under internal/templates/pentest.
//
//go:embed pentest
var All embed.FS

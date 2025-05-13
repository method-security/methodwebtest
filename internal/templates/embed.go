// internal/templates/embed.go
package templates

import "embed"

// Embeds the entire pentest directory tree (recursively).
//
//go:embed pentest
var All embed.FS

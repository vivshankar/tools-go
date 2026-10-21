package static

import "embed"

// Files contains the embedded static web assets
//
//go:embed *.html *.css
var Files embed.FS

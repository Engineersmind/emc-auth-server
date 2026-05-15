package migrations

import "embed"

// FS embeds all SQL migration files for goose to consume at runtime.
// This enables the single-binary deployment requirement (NFR-08).
//
//go:embed *.sql
var FS embed.FS

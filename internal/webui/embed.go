// Package webui embeds the zero-dependency 3-panel Hybrid Web Workbench assets.
package webui

import "embed"

// AssetsFS embeds static HTML, CSS, and vanilla JS files for raksa ui.
//
//go:embed assets/*
var AssetsFS embed.FS

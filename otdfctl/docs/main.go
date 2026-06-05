package docs

import "embed"

//go:embed all:man/*
var ManFiles embed.FS

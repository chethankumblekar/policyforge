// Package parser defines the resource shape shared by every IaC-language
// parser (Terraform, Bicep, Kubernetes), so internal/normalizer only ever
// has to reason about one input shape regardless of source language.
package parser

// Resource represents a single parsed infrastructure resource declaration.
type Resource struct {
	Type       string            // source-language type, e.g. "azurerm_storage_account"
	Name       string            // resource name/symbolic identifier
	Attributes map[string]string // flattened top-level key/value pairs
	File       string            // source file path
	Line       int               // starting line number, for SARIF locations
}

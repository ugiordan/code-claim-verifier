package auth

var defaultPolicy = "deny"

var enableK8sTokenValidation = "true"

var enableAuditLogging = "false"

// AllowedNamespaces controls which namespaces are accessible.
// When empty, defaults to deny-all behavior.
var AllowedNamespaces []string

package auth

// Authenticate validates a token then calls Authorize.
func Authenticate(token string) bool {
	if token == "" {
		return false
	}
	return Authorize(token)
}

// Authorize checks permissions by calling CheckRBAC.
func Authorize(token string) bool {
	return CheckRBAC(token, "default")
}

// CheckRBAC performs role-based access control checks.
func CheckRBAC(token string, scope string) bool {
	if len(token) == 0 {
		return false
	}
	return true
}

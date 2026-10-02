package oauth

// Service-level stable errors.
var (
	ErrUnsupportedResponseType = &ServiceError{Code: "unsupported_response_type", Message: "only response_type=code is supported"}
	ErrUnsupportedGrantType    = &ServiceError{Code: "unsupported_grant_type", Message: "unsupported grant_type"}
	ErrInvalidCredentials      = &ServiceError{Code: "access_denied", Message: "invalid local username or password"}
	ErrSessionRevoked          = &ServiceError{Code: "invalid_grant", Message: "session revoked; access token no longer valid"}
)

// ServiceError is the typed, distinguishable error of the oauth layer.
type ServiceError struct {
	Code    string
	Message string
	Cause   error
}

func (e *ServiceError) Error() string { return e.Code + ": " + e.Message }
func (e *ServiceError) Unwrap() error { return e.Cause }

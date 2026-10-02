package authcode

import "errors"

// Distinguishable failure reasons for authorization-code exchange.
var (
	// ErrCodeNotFound means the code was never issued (unknown identifier).
	ErrCodeNotFound = errors.New("authcode: code not found")
	// ErrCodeExpired means the code existed but its short lifetime elapsed.
	ErrCodeExpired = errors.New("authcode: code expired")
	// ErrCodeAlreadyUsed means the one-time code was exchanged before; a
	// repeat presentation must never succeed.
	ErrCodeAlreadyUsed = errors.New("authcode: code already used")
	// ErrPKCEMismatch means the presented code_verifier does not match the
	// code_challenge bound to the code at authorization time.
	ErrPKCEMismatch = errors.New("authcode: PKCE verification failed")
	// ErrParameterMismatch means redirect_uri / client_id differ from the
	// values bound at authorization time.
	ErrParameterMismatch = errors.New("authcode: request parameters do not match the original authorization")
)

// ErrorCode maps an exchange failure to a stable short identifier.
func ErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrCodeNotFound):
		return "invalid_code"
	case errors.Is(err, ErrCodeExpired):
		return "code_expired"
	case errors.Is(err, ErrCodeAlreadyUsed):
		return "code_replayed"
	case errors.Is(err, ErrPKCEMismatch):
		return "pkce_mismatch"
	case errors.Is(err, ErrParameterMismatch):
		return "parameter_mismatch"
	default:
		return "exchange_failed"
	}
}

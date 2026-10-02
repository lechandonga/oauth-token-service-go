package token

import "errors"

// Distinguishable failure reasons for token verification.
var (
	ErrMalformed       = errors.New("token: malformed token")
	ErrSignature       = errors.New("token: invalid signature")
	ErrNoValidKey      = errors.New("token: no signing key accepted the signature within the rotation window")
	ErrTokenExpired    = errors.New("token: token expired")
	ErrNotYetValid     = errors.New("token: token not valid yet")
	ErrIssuerMismatch  = errors.New("token: issuer mismatch")
	ErrAudienceMissing = errors.New("token: required audience missing")
)

// ErrorCode maps a verification failure to a stable short identifier.
func ErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrMalformed):
		return "malformed_token"
	case errors.Is(err, ErrSignature):
		return "invalid_signature"
	case errors.Is(err, ErrNoValidKey):
		return "no_trusted_key"
	case errors.Is(err, ErrTokenExpired):
		return "token_expired"
	case errors.Is(err, ErrNotYetValid):
		return "token_not_yet_valid"
	case errors.Is(err, ErrIssuerMismatch):
		return "issuer_mismatch"
	case errors.Is(err, ErrAudienceMissing):
		return "audience_mismatch"
	default:
		return "verification_failed"
	}
}

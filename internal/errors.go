package internal

import "errors"

// ErrorCode 用稳定的短字符串标识失败原因，便于调用方区分错误，
// 同时避免把底层加解密错误原样透出。
type ErrorCode string

const (
	CodeInvalidRequest     ErrorCode = "invalid_request"        // 请求参数缺失或格式不合法
	CodeUnauthorizedClient ErrorCode = "unauthorized_client"    // 客户端标识或密钥不被允许
	CodeInvalidRedirect    ErrorCode = "invalid_redirect_uri"   // 回调地址未注册或不匹配
	CodeInvalidGrant       ErrorCode = "invalid_grant"          // 授权码/刷新令牌不存在、已用、已撤销
	CodeCodeExpired        ErrorCode = "code_expired"           // 授权码已过期
	CodePKCEMismatch       ErrorCode = "pkce_verifier_mismatch" // code_verifier 与 code_challenge 不匹配
	CodeParamsTampered     ErrorCode = "params_tampered"        // 重定向/客户端等参数与签发时不一致
	CodeReuseDetected      ErrorCode = "refresh_reuse_detected" // 刷新令牌被重复使用，整条链已撤销
	CodeTokenExpired       ErrorCode = "token_expired"
	CodeTokenRevoked       ErrorCode = "token_revoked"
	CodeTokenIssuer        ErrorCode = "invalid_issuer"
	CodeTokenAudience      ErrorCode = "invalid_audience"
	CodeBadSignature       ErrorCode = "bad_signature"
	CodeMalformedToken     ErrorCode = "malformed_token"
	CodeKeyUnavailable     ErrorCode = "key_unavailable"
)

// Error 是服务内统一错误类型。Cause 仅用于服务端日志，不会返回给调用方。
type Error struct {
	Code  ErrorCode
	Desc  string
	Cause error
}

func (e *Error) Error() string {
	if e.Desc != "" {
		return string(e.Code) + ": " + e.Desc
	}
	return string(e.Code)
}

func (e *Error) Unwrap() error { return e.Cause }

// NewE 构造一个带原因码错误。
func NewE(code ErrorCode, desc string) *Error {
	return &Error{Code: code, Desc: desc}
}

// WrapE 附带上底层原因（仅记录日志，不透传文本）。
func WrapE(code ErrorCode, desc string, cause error) *Error {
	return &Error{Code: code, Desc: desc, Cause: cause}
}

// CodeOf 提取错误对应的原因码；未知错误归为 invalid_request。
func CodeOf(err error) ErrorCode {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeInvalidRequest
}

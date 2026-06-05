package auth

import "errors"

var (
	ErrAccessTokenExpired         = errors.New("access token expired")
	ErrAccessTokenNotFound        = errors.New("no access token found")
	ErrClientCredentialsNotFound  = errors.New("client credentials not found")
	ErrInvalidAuthType            = errors.New("invalid auth type")
	ErrUnauthenticated            = errors.New("not logged in")
	ErrParsingAccessToken         = errors.New("failed to parse access token")
	ErrProfileCredentialsNotFound = errors.New("profile missing credentials")
	ErrNoRefreshToken             = errors.New("no refresh token available")
	ErrRefreshFailed              = errors.New("token refresh failed")
)

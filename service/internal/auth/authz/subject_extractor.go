package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	platformauthz "github.com/opentdf/platform/service/pkg/authz"
	"github.com/opentdf/platform/service/pkg/util"
)

const (
	SubjectRolePrefix   = "role:"
	SubjectClientPrefix = "client:"
)

var (
	ErrClientIDClaimNotConfigured = errors.New("no client ID claim configured")
	ErrClientIDClaimNotFound      = errors.New("client ID claim not found")
	ErrClientIDClaimNotString     = errors.New("client ID claim is not a string")
	ErrTokenRequired              = errors.New("token is required")
)

type SubjectExtractor struct {
	UserNameClaim string
	ClientIDClaim string
	RoleProvider  platformauthz.RoleProvider
	Logger        *logger.Logger
}

func (e SubjectExtractor) BuildSubjectFromToken(ctx context.Context, token jwt.Token, req platformauthz.RoleRequest, usePrefix bool) ([]string, []string, error) {
	subjects := []string{}

	if e.Logger != nil {
		e.Logger.Debug("building subject from token")
	}

	claims, err := e.ClaimsForRequest(ctx, token, req)
	if err != nil {
		return nil, nil, err
	}
	roles := normalizeRoles(claims.Groups, usePrefix)

	if clientID := claims.ClientID; clientID != "" {
		subjects = append(subjects, subjectWithPrefix(clientID, SubjectClientPrefix, usePrefix))
	}
	subjects = append(subjects, roles...)
	if claims.Subject != "" {
		subjects = append(subjects, claims.Subject)
	}

	return subjects, append([]string(nil), roles...), nil
}

func (e SubjectExtractor) ContextWithClaims(ctx context.Context, token jwt.Token, req platformauthz.RoleRequest) (context.Context, error) {
	claims, err := e.ClaimsForRequest(ctx, token, req)
	if err != nil {
		return ctx, err
	}
	return platformauthz.ContextWithClaims(ctx, claims), nil
}

func (e SubjectExtractor) ClaimsForRequest(ctx context.Context, token jwt.Token, req platformauthz.RoleRequest) (platformauthz.RequestClaims, error) {
	if claims, ok := platformauthz.ClaimsFromContext(ctx); ok {
		if claims.Subject != "" || len(claims.Groups) > 0 {
			return claims, nil
		}
	}
	if token == nil {
		return platformauthz.RequestClaims{}, ErrTokenRequired
	}

	var roles []string
	if e.RoleProvider != nil {
		var err error
		roles, err = e.RoleProvider.Roles(ctx, token, req)
		if err != nil {
			return platformauthz.RequestClaims{}, err
		}
	}
	claims, _ := platformauthz.ClaimsFromContext(ctx)
	claims.Subject = e.usernameFromToken(token)
	claims.Groups = roles
	if claims.ClientID == "" {
		clientID, err := e.ClientIDFromToken(ctx, token)
		if err == nil {
			claims.ClientID = clientID
		}
	}
	return claims, nil
}

func (e SubjectExtractor) ClientIDFromToken(ctx context.Context, token jwt.Token) (string, error) {
	if e.ClientIDClaim == "" {
		return "", ErrClientIDClaimNotConfigured
	}
	if token == nil {
		return "", ErrTokenRequired
	}
	claims, err := token.AsMap(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to parse token as a map and find claim at [%s]: %w", e.ClientIDClaim, err)
	}
	found := util.Dotnotation(claims, e.ClientIDClaim)
	if found == nil {
		return "", fmt.Errorf("%w at [%s]", ErrClientIDClaimNotFound, e.ClientIDClaim)
	}
	clientID, ok := found.(string)
	if !ok {
		return "", fmt.Errorf("%w at [%s]", ErrClientIDClaimNotString, e.ClientIDClaim)
	}
	return clientID, nil
}

func normalizeRoles(roles []string, usePrefix bool) []string {
	normalized := make([]string, 0, len(roles))

	for _, role := range roles {
		if role == "" {
			continue
		}
		normalized = append(normalized, subjectWithPrefix(role, SubjectRolePrefix, usePrefix))
	}
	return normalized
}

func subjectWithPrefix(subject, prefix string, usePrefix bool) string {
	if !usePrefix || strings.HasPrefix(subject, prefix) {
		return subject
	}
	return prefix + subject
}

func (e SubjectExtractor) usernameFromToken(token jwt.Token) string {
	if token == nil || e.UserNameClaim == "" {
		return ""
	}

	claim, found := token.Get(e.UserNameClaim)
	if !found {
		return ""
	}

	username, ok := claim.(string)
	if !ok {
		if e.Logger != nil {
			e.Logger.Warn(
				"username claim not of type string",
				slog.String("claim", e.UserNameClaim),
				slog.Any("claims", claim),
			)
		}
		return ""
	}
	if username == "" {
		return ""
	}
	if strings.HasPrefix(username, SubjectRolePrefix) {
		if e.Logger != nil {
			e.Logger.Warn(
				"ignoring username subject with reserved role prefix",
				slog.String("claim", e.UserNameClaim),
				slog.String("prefix", SubjectRolePrefix),
			)
		}
		return ""
	}
	if strings.HasPrefix(username, SubjectClientPrefix) {
		if e.Logger != nil {
			e.Logger.Warn(
				"ignoring username subject with reserved client prefix",
				slog.String("claim", e.UserNameClaim),
				slog.String("prefix", SubjectClientPrefix),
			)
		}
		return ""
	}

	return username
}

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
	ErrSubjectExtractorLogger     = errors.New("subject extractor logger is required")
	ErrSubjectExtractorRoles      = errors.New("subject extractor role provider is required")
)

type SubjectExtractor struct {
	userNameClaim string
	clientIDClaim string
	roleProvider  platformauthz.RoleProvider
	logger        *logger.Logger
}

// NewSubjectExtractor constructs a subject extractor with required dependencies.
func NewSubjectExtractor(userNameClaim, clientIDClaim string, roleProvider platformauthz.RoleProvider, log *logger.Logger) (SubjectExtractor, error) {
	if log == nil {
		return SubjectExtractor{}, ErrSubjectExtractorLogger
	}
	if roleProvider == nil {
		return SubjectExtractor{}, ErrSubjectExtractorRoles
	}

	return SubjectExtractor{
		userNameClaim: userNameClaim,
		clientIDClaim: clientIDClaim,
		roleProvider:  roleProvider,
		logger:        log,
	}, nil
}

// BuildV1SubjectsFromToken preserves legacy subjects: claims.Groups plus
// claims.Subject as-is, including empty values. It does not emit an independent
// client ID subject or filter reserved role:/client: username prefixes.
func (e SubjectExtractor) BuildV1SubjectsFromToken(ctx context.Context, token jwt.Token, req platformauthz.RoleRequest) ([]string, []string, error) {
	subjects := []string{}

	e.logger.Debug("building v1 subjects from token")

	claims, err := e.ClaimsForRequest(ctx, token, req)
	if err != nil {
		return nil, nil, err
	}

	subjects = append(subjects, claims.Groups...)
	subjects = append(subjects, claims.Subject)

	return subjects, append([]string(nil), claims.Groups...), nil
}

// BuildV2SubjectsFromToken emits typed subjects: client IDs and roles use
// reserved prefixes, empty roles are filtered, and usernames with role:/client:
// prefixes are skipped to avoid collisions.
func (e SubjectExtractor) BuildV2SubjectsFromToken(ctx context.Context, token jwt.Token, req platformauthz.RoleRequest) ([]string, []string, error) {
	subjects := []string{}

	e.logger.Debug("building v2 subjects from token")

	claims, err := e.ClaimsForRequest(ctx, token, req)
	if err != nil {
		return nil, nil, err
	}
	roles := normalizeV2Roles(claims.Groups)

	if claims.ClientID != "" {
		subjects = append(subjects, subjectWithPrefix(claims.ClientID, SubjectClientPrefix))
	}

	subjects = append(subjects, roles...)
	if claims.Subject != "" {
		if e.usernameHasReservedPrefix(claims.Subject) {
			return subjects, append([]string(nil), roles...), nil
		}
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
	var err error
	roles, err = e.roleProvider.Roles(ctx, token, req)
	if err != nil {
		return platformauthz.RequestClaims{}, err
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
	if e.clientIDClaim == "" {
		return "", ErrClientIDClaimNotConfigured
	}
	if token == nil {
		return "", ErrTokenRequired
	}
	claims, err := token.AsMap(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to parse token as a map and find claim at [%s]: %w", e.clientIDClaim, err)
	}
	found := util.Dotnotation(claims, e.clientIDClaim)
	if found == nil {
		return "", fmt.Errorf("%w at [%s]", ErrClientIDClaimNotFound, e.clientIDClaim)
	}
	clientID, ok := found.(string)
	if !ok {
		return "", fmt.Errorf("%w at [%s]", ErrClientIDClaimNotString, e.clientIDClaim)
	}
	return clientID, nil
}

func normalizeV2Roles(roles []string) []string {
	normalized := make([]string, 0, len(roles))

	for _, role := range roles {
		if role == "" {
			continue
		}
		normalized = append(normalized, subjectWithPrefix(role, SubjectRolePrefix))
	}
	return normalized
}

func subjectWithPrefix(subject, prefix string) string {
	if strings.HasPrefix(subject, prefix) {
		return subject
	}
	return prefix + subject
}

func (e SubjectExtractor) usernameFromToken(token jwt.Token) string {
	if token == nil || e.userNameClaim == "" {
		return ""
	}

	claim, found := token.Get(e.userNameClaim)
	if !found {
		return ""
	}

	username, ok := claim.(string)
	if !ok {
		e.logger.Warn(
			"username claim not of type string",
			slog.String("claim", e.userNameClaim),
			slog.Any("claims", claim),
		)
		return ""
	}

	return username
}

func (e SubjectExtractor) usernameHasReservedPrefix(username string) bool {
	if strings.HasPrefix(username, SubjectRolePrefix) {
		e.logger.Warn(
			"ignoring username subject with reserved role prefix",
			slog.String("claim", e.userNameClaim),
			slog.String("prefix", SubjectRolePrefix),
		)
		return true
	}
	if strings.HasPrefix(username, SubjectClientPrefix) {
		e.logger.Warn(
			"ignoring username subject with reserved client prefix",
			slog.String("claim", e.userNameClaim),
			slog.String("prefix", SubjectClientPrefix),
		)
		return true
	}

	return false
}

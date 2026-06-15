package authz

import (
	"context"
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

type SubjectExtractor struct {
	UserNameClaim string
	ClientIDClaim string
	RoleProvider  platformauthz.RoleProvider
	UsePrefix     bool
	Logger        *logger.Logger
}

func (e SubjectExtractor) BuildSubjectFromToken(ctx context.Context, token jwt.Token, req platformauthz.RoleRequest) ([]string, []string, error) {
	subjects := []string{}

	if e.Logger != nil {
		e.Logger.Debug("building subject from token")
	}

	var roles []string
	if e.RoleProvider != nil {
		var err error
		roles, err = e.RoleProvider.Roles(ctx, token, req)
		if err != nil {
			return nil, nil, err
		}
	}
	roles = e.normalizeRoles(roles)

	if clientID := e.clientIDFromToken(ctx, token); clientID != "" {
		subjects = append(subjects, e.subjectWithPrefix(clientID, SubjectClientPrefix))
	}
	subjects = append(subjects, roles...)
	if username := e.usernameFromToken(token); username != "" {
		subjects = append(subjects, username)
	}

	return subjects, append([]string(nil), roles...), nil
}

func (e SubjectExtractor) normalizeRoles(roles []string) []string {
	if !e.UsePrefix {
		return roles
	}
	prefixed := make([]string, 0, len(roles))
	for _, role := range roles {
		if role == "" {
			continue
		}
		prefixed = append(prefixed, e.subjectWithPrefix(role, SubjectRolePrefix))
	}
	return prefixed
}

func (e SubjectExtractor) subjectWithPrefix(subject, prefix string) string {
	if !e.UsePrefix || strings.HasPrefix(subject, prefix) {
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

	return username
}

func (e SubjectExtractor) clientIDFromToken(ctx context.Context, token jwt.Token) string {
	if token == nil || e.ClientIDClaim == "" {
		return ""
	}
	claims, err := token.AsMap(ctx)
	if err != nil {
		return ""
	}
	found := util.Dotnotation(claims, e.ClientIDClaim)
	clientID, ok := found.(string)
	if !ok || clientID == "" {
		return ""
	}
	return clientID
}

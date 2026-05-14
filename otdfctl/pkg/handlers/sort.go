package handlers

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
)

type SortOption struct {
	Field     string
	Direction policy.SortDirection
}

const (
	sortDirectionAsc  = "asc"
	sortDirectionDesc = "desc"
	sortSeparator     = ":"
)

var (
	ErrInvalidSortFormat    = errors.New("sort must use field:direction; field or direction may be omitted")
	ErrInvalidSortDirection = errors.New("invalid sort direction")
	ErrInvalidSortField     = errors.New("invalid sort field")
)

func ParseSortOption(value string) (SortOption, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return SortOption{}, nil
	}

	fieldPart, directionPart, ok := strings.Cut(value, sortSeparator)
	if !ok || strings.Contains(directionPart, sortSeparator) {
		return SortOption{}, ErrInvalidSortFormat
	}

	field := strings.ToLower(strings.TrimSpace(fieldPart))
	directionValue := strings.ToLower(strings.TrimSpace(directionPart))
	if field == "" && directionValue == "" {
		return SortOption{}, ErrInvalidSortFormat
	}

	direction, err := parseSortDirection(directionValue)
	if err != nil {
		return SortOption{}, err
	}

	return SortOption{
		Field:     field,
		Direction: direction,
	}, nil
}

func parseSortDirection(value string) (policy.SortDirection, error) {
	switch value {
	case "":
		return policy.SortDirection_SORT_DIRECTION_UNSPECIFIED, nil
	case sortDirectionAsc:
		return policy.SortDirection_SORT_DIRECTION_ASC, nil
	case sortDirectionDesc:
		return policy.SortDirection_SORT_DIRECTION_DESC, nil
	default:
		return policy.SortDirection_SORT_DIRECTION_UNSPECIFIED, errors.Join(
			ErrInvalidSortDirection,
			fmt.Errorf("%q must be asc or desc", value),
		)
	}
}

func (s SortOption) IsZero() bool {
	return s.Field == "" && s.Direction == policy.SortDirection_SORT_DIRECTION_UNSPECIFIED
}

func sortField[T any](resource string, option SortOption, allowed map[string]T) (T, error) {
	var zero T
	if option.Field == "" {
		return zero, nil
	}

	field, ok := allowed[option.Field]
	if !ok {
		return zero, invalidSortFieldError(resource, option.Field, allowed)
	}

	return field, nil
}

func invalidSortFieldError[T any](resource, field string, allowed map[string]T) error {
	fields := make([]string, 0, len(allowed))
	for f := range allowed {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	return errors.Join(
		ErrInvalidSortField,
		fmt.Errorf("%q is not a valid sort field for %s; valid fields: %s", field, resource, strings.Join(fields, ", ")),
	)
}

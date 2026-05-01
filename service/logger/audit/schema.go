package audit

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

var (
	errReservedAuditPath  = errors.New("reserved audit path")
	errUnknownAuditPath   = errors.New("unknown audit path")
	errAuditContainerPath = errors.New("audit path resolves to a container")

	auditClaimDestinationSchema = mustBuildAuditPathSchema(reflect.TypeOf(EventObject{}))
)

type auditFieldOptions struct {
	name       string
	reserved   bool
	extensible bool
}

type auditPathSchema struct {
	children   map[string]*auditPathSchema
	reserved   bool
	extensible bool
}

func mustBuildAuditPathSchema(rootType reflect.Type) *auditPathSchema {
	root, err := buildAuditPathSchema(rootType)
	if err != nil {
		panic(err)
	}
	return root
}

func buildAuditPathSchema(rootType reflect.Type) (*auditPathSchema, error) {
	rootType = indirectType(rootType)
	if rootType.Kind() != reflect.Struct {
		return nil, fmt.Errorf("audit schema root must be a struct, got %s", rootType.Kind())
	}

	root := &auditPathSchema{
		children: make(map[string]*auditPathSchema),
	}
	if err := addAuditSchemaFields(root, rootType); err != nil {
		return nil, err
	}
	return root, nil
}

func addAuditSchemaFields(parent *auditPathSchema, structType reflect.Type) error {
	for i := range structType.NumField() {
		field := structType.Field(i)
		if !field.IsExported() {
			continue
		}

		opts, ok := parseAuditFieldOptions(field)
		if !ok {
			continue
		}
		if _, exists := parent.children[opts.name]; exists {
			return fmt.Errorf("duplicate audit schema path %q on %s", opts.name, structType)
		}

		child := &auditPathSchema{
			children:   make(map[string]*auditPathSchema),
			reserved:   opts.reserved,
			extensible: opts.extensible,
		}
		parent.children[opts.name] = child

		fieldType := indirectType(field.Type)
		if fieldType.Kind() == reflect.Struct {
			if err := addAuditSchemaFields(child, fieldType); err != nil {
				return err
			}
		}
		if len(child.children) == 0 {
			child.children = nil
		}
	}

	return nil
}

func parseAuditFieldOptions(field reflect.StructField) (auditFieldOptions, bool) {
	tag := field.Tag.Get("audit")
	if tag == "-" {
		return auditFieldOptions{}, false
	}

	name, reserved, extensible := parseAuditTag(tag)
	if name == "" {
		name = parseJSONFieldName(field)
	}
	if name == "" {
		return auditFieldOptions{}, false
	}

	return auditFieldOptions{
		name:       name,
		reserved:   reserved,
		extensible: extensible,
	}, true
}

func parseAuditTag(tag string) (string, bool, bool) {
	if tag == "" {
		return "", false, false
	}

	parts := strings.Split(tag, ",")
	name := parts[0]
	var (
		reserved   bool
		extensible bool
	)
	for _, option := range parts[1:] {
		switch option {
		case "reserved":
			reserved = true
		case "extensible":
			extensible = true
		}
	}
	return name, reserved, extensible
}

func parseJSONFieldName(field reflect.StructField) string {
	tag := field.Tag.Get("json")
	if tag == "-" {
		return ""
	}
	if tag == "" {
		return field.Name
	}

	name, _, _ := strings.Cut(tag, ",")
	if name == "" {
		return field.Name
	}
	return name
}

func indirectType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func validateClaimDestinationPath(path string) error {
	if path == "" {
		return fmt.Errorf("%w: empty path", errUnknownAuditPath)
	}

	segments := strings.Split(path, ".")
	current := auditClaimDestinationSchema
	for idx, segment := range segments {
		if segment == "" {
			return fmt.Errorf("%w: %s", errUnknownAuditPath, path)
		}

		child, ok := current.children[segment]
		if !ok {
			if current.extensible {
				return nil
			}
			return fmt.Errorf("%w: %s", errUnknownAuditPath, path)
		}

		isLast := idx == len(segments)-1
		if isLast {
			switch {
			case child.reserved:
				return fmt.Errorf("%w: %s", errReservedAuditPath, path)
			case child.extensible || len(child.children) > 0:
				return fmt.Errorf("%w: %s", errAuditContainerPath, path)
			default:
				return nil
			}
		}

		current = child
	}

	return nil
}

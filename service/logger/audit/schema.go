package audit

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

var (
	// ErrReservedAuditPath indicates a claim destination targets a protected audit field.
	ErrReservedAuditPath = errors.New("reserved audit path")
	// ErrUnknownAuditPath indicates a claim destination traverses an unknown closed-schema path.
	ErrUnknownAuditPath = errors.New("unknown audit path")
	// ErrAuditContainerPath indicates a claim destination resolves to a container instead of a writable leaf.
	ErrAuditContainerPath = errors.New("audit path resolves to a container")

	auditClaimDestinationSchema = mustBuildAuditPathSchema(reflect.TypeOf(EventObject{}))
)

type auditFieldOptions struct {
	name       string
	reserved   bool
	extensible bool
}

type auditPathSchema struct {
	children   map[string]*auditPathSchema
	isLeaf     bool
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
		children:   make(map[string]*auditPathSchema),
		extensible: true,
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
			isLeaf:     isWritableAuditLeaf(indirectType(field.Type)),
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

	reserved, extensible := parseAuditTag(tag)
	name := parseJSONFieldName(field)
	if name == "" {
		return auditFieldOptions{}, false
	}

	return auditFieldOptions{
		name:       name,
		reserved:   reserved,
		extensible: extensible,
	}, true
}

func parseAuditTag(tag string) (bool, bool) {
	switch tag {
	case "":
		return false, false
	case "reserved":
		return true, false
	case "extensible":
		return false, true
	default:
		return false, false
	}
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

func isWritableAuditLeaf(t reflect.Type) bool {
	kind := indirectType(t).Kind()
	return kind != reflect.Struct && kind != reflect.Map
}

func validateClaimDestinationPath(path string) error {
	if path == "" {
		return fmt.Errorf("%w: empty path", ErrUnknownAuditPath)
	}

	segments := strings.Split(path, ".")
	current := auditClaimDestinationSchema
	for idx, segment := range segments {
		if segment == "" {
			return fmt.Errorf("%w: %s", ErrUnknownAuditPath, path)
		}

		child, ok := current.children[segment]
		if !ok {
			if current.extensible {
				return nil
			}
			return fmt.Errorf("%w: %s", ErrUnknownAuditPath, path)
		}

		isLast := idx == len(segments)-1
		if isLast {
			switch {
			case child.reserved:
				return fmt.Errorf("%w: %s", ErrReservedAuditPath, path)
			case child.extensible || !child.isLeaf:
				return fmt.Errorf("%w: %s", ErrAuditContainerPath, path)
			default:
				return nil
			}
		}

		current = child
	}

	return nil
}

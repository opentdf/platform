// Package celeval is an EXPERIMENTAL, spike-only reference implementation for DSPX-3673. It lowers
// the policy Subject Condition Set model (SubjectSet -> ConditionGroup -> Condition) to a single
// CEL (https://cel.dev) expression and evaluates it against a flattened entity.
//
// It exists to benchmark CEL against the hand-written operator switch in
// subject_mapping_builtin.go (EvaluateCondition / EvaluateConditionGroup / EvaluateSubjectSet) and
// is the reference for the migration sketch in
// service/policy/adr/0005-dspx-3673-cel-condition-evaluation-spike.md.
//
// It is NOT wired into any request path. Do not use in production without the review the ADR calls
// for.
//
// Lowering matches the native semantics exactly:
//   - SubjectSet: condition groups AND-ed (empty -> true).
//   - ConditionGroup AND: conditions AND-ed (empty -> true). OR: conditions OR-ed (empty -> false).
//   - Condition: the legacy SubjectMappingOperatorEnum (IN / NOT_IN / IN_CONTAINS), or, when that is
//     unspecified, the decomposed comparison + quantifier + case_insensitive axes from issue #3335.
//
// Selector values are bound per request as one list(string) variable per distinct selector;
// condition target values are baked into the compiled program as CEL list literals, so a stored
// condition compiles once and only the entity varies per evaluation.
package celeval

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/policy"
)

// Program is a compiled SubjectSet ready to evaluate against flattened entities.
type Program struct {
	prog cel.Program
	src  string
	vars []varBinding
}

type varBinding struct {
	name     string
	selector string
}

// selectorAlloc assigns a stable CEL variable name to each distinct selector in first-appearance
// order (v0, v1, ...). CEL identifiers cannot contain the dots/brackets selectors use.
type selectorAlloc struct {
	byName []varBinding
	bySel  map[string]string
}

func newSelectorAlloc() *selectorAlloc {
	return &selectorAlloc{bySel: map[string]string{}}
}

func (s *selectorAlloc) varFor(selector string) string {
	if name, ok := s.bySel[selector]; ok {
		return name
	}
	name := fmt.Sprintf("v%d", len(s.byName))
	s.bySel[selector] = name
	s.byName = append(s.byName, varBinding{name: name, selector: selector})
	return name
}

// Source returns the lowered CEL expression (useful for debugging and the ADR).
func (p *Program) Source() string { return p.src }

// CompileSubjectSet lowers ss to CEL and compiles it.
func CompileSubjectSet(ss *policy.SubjectSet) (*Program, error) {
	alloc := newSelectorAlloc()
	src, err := subjectSetToCEL(ss, alloc)
	if err != nil {
		return nil, err
	}

	opts := make([]cel.EnvOption, 0, len(alloc.byName)+1)
	opts = append(opts, ext.Strings())
	for _, vb := range alloc.byName {
		opts = append(opts, cel.Variable(vb.name, cel.ListType(cel.StringType)))
	}
	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("cel env: %w", err)
	}
	ast, iss := env.Compile(src)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("cel compile %q: %w", src, iss.Err())
	}
	prog, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("cel program: %w", err)
	}
	return &Program{prog: prog, src: src, vars: alloc.byName}, nil
}

// Eval binds the entity's selector values and evaluates the compiled program. The activation build
// mirrors what the native EvaluateCondition does per condition: pull values at the selector and
// stringify them.
func (p *Program) Eval(flat flattening.Flattened) (bool, error) {
	act := make(map[string]any, len(p.vars))
	for _, vb := range p.vars {
		raw := flattening.GetFromFlattened(flat, vb.selector)
		vals := make([]string, len(raw))
		for i, v := range raw {
			vals[i] = fmt.Sprintf("%v", v)
		}
		act[vb.name] = vals
	}
	out, _, err := p.prog.Eval(act)
	if err != nil {
		return false, fmt.Errorf("cel eval: %w", err)
	}
	result, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("cel expression did not return bool: %T", out.Value())
	}
	return result, nil
}

func subjectSetToCEL(ss *policy.SubjectSet, alloc *selectorAlloc) (string, error) {
	groups := ss.GetConditionGroups()
	if len(groups) == 0 {
		return "true", nil
	}
	parts := make([]string, 0, len(groups))
	for _, g := range groups {
		part, err := conditionGroupToCEL(g, alloc)
		if err != nil {
			return "", err
		}
		parts = append(parts, part)
	}
	return joinBool(parts, "&&", "true"), nil
}

func conditionGroupToCEL(cg *policy.ConditionGroup, alloc *selectorAlloc) (string, error) {
	var op, empty string
	switch cg.GetBooleanOperator() {
	case policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND:
		op, empty = "&&", "true"
	case policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR:
		op, empty = "||", "false"
	case policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_UNSPECIFIED:
		return "", errors.New("unspecified condition group boolean operator")
	default:
		return "", errors.New("unsupported condition group boolean operator: " + cg.GetBooleanOperator().String())
	}

	conditions := cg.GetConditions()
	parts := make([]string, 0, len(conditions))
	for _, c := range conditions {
		part, err := conditionToCEL(c, alloc)
		if err != nil {
			return "", err
		}
		parts = append(parts, part)
	}
	return joinBool(parts, op, empty), nil
}

func conditionToCEL(c *policy.Condition, alloc *selectorAlloc) (string, error) {
	valuesVar := alloc.varFor(c.GetSubjectExternalSelectorValue())
	targets := celListLiteral(c.GetSubjectExternalValues())

	// Legacy operator takes precedence when set; otherwise use the decomposed axes (#3335).
	//nolint:staticcheck // intentionally reads the deprecated legacy operator to match the native evaluator
	if op := c.GetOperator(); op != policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED {
		//nolint:exhaustive // UNSPECIFIED is excluded by the guard above
		switch op {
		case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN:
			return existsAny(targets, valuesVar, eqPred(false)), nil
		case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN:
			return "!" + existsAny(targets, valuesVar, eqPred(false)), nil
		case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS:
			return existsAny(targets, valuesVar, containsPred(false)), nil
		default:
			return "", errors.New("unsupported subject mapping operator: " + op.String())
		}
	}

	return decomposedToCEL(c, targets, valuesVar)
}

func decomposedToCEL(c *policy.Condition, targets, valuesVar string) (string, error) {
	ci := c.GetCaseInsensitive().GetValue()

	var pred string
	switch c.GetComparison() {
	case policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_EQUALS:
		pred = eqPred(ci)
	case policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_CONTAINS:
		pred = containsPred(ci)
	case policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_STARTS_WITH:
		pred = strFnPred("startsWith", ci)
	case policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_ENDS_WITH:
		pred = strFnPred("endsWith", ci)
	case policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_UNSPECIFIED:
		return "", errors.New("unspecified condition comparison operator")
	default:
		return "", errors.New("unsupported condition comparison operator: " + c.GetComparison().String())
	}

	switch c.GetQuantifier() {
	case policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_ANY:
		return existsAny(targets, valuesVar, pred), nil
	case policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_ALL:
		return fmt.Sprintf("%s.all(t, %s.exists(v, %s))", targets, valuesVar, pred), nil
	case policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_NONE:
		return "!" + existsAny(targets, valuesVar, pred), nil
	case policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_UNSPECIFIED:
		return "", errors.New("unspecified condition quantifier")
	default:
		return "", errors.New("unsupported condition quantifier: " + c.GetQuantifier().String())
	}
}

// existsAny renders ANY-quantified matching: some target matches some entity value under pred.
func existsAny(targets, valuesVar, pred string) string {
	return fmt.Sprintf("%s.exists(t, %s.exists(v, %s))", targets, valuesVar, pred)
}

// eqPred compares entity value v to target t for equality, optionally case-insensitively.
func eqPred(caseInsensitive bool) string {
	if caseInsensitive {
		return "v.lowerAscii() == t.lowerAscii()"
	}
	return "v == t"
}

func containsPred(caseInsensitive bool) string {
	return strFnPred("contains", caseInsensitive)
}

// strFnPred renders a CEL string-method predicate, e.g. v.contains(t), optionally lowercasing both
// sides for case-insensitive matching.
func strFnPred(fn string, caseInsensitive bool) string {
	if caseInsensitive {
		return fmt.Sprintf("v.lowerAscii().%s(t.lowerAscii())", fn)
	}
	return fmt.Sprintf("v.%s(t)", fn)
}

func joinBool(parts []string, op, empty string) string {
	if len(parts) == 0 {
		return empty
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " "+op+" ") + ")"
}

func celListLiteral(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = strconv.Quote(v)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

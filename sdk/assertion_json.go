package sdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// This file implements the parsing rules of the ZTDF assertions
// specification, Section 3, which Go's encoding/json cannot enforce: it keeps
// the last of duplicate members, matches member names case-insensitively, and
// silently turns lone surrogate escapes and invalid UTF-8 into U+FFFD. The
// scanner below therefore reads the raw bytes before any struct decoding:
//
//   - duplicate member names anywhere, compared after decoding escapes, are
//     duplicate-member;
//   - at every level of the manifest the SDK models (see levelSpecs), a case
//     variant of a modelled member name, or two members whose names are case
//     variants of each other, are ambiguous-member;
//   - invalid UTF-8 anywhere is invalid-json, since RFC 8259 Section 8.1
//     requires UTF-8;
//   - inside an assertion object, lone surrogates, noncharacters and numbers
//     outside the IEEE 754 double range are invalid-json too.
//
// Apart from UTF-8, which encoding/json does not check, it accepts exactly
// the JSON grammar of RFC 8259 and the same nesting limit as encoding/json.

// maxJSONDepth matches encoding/json's nesting limit.
const maxJSONDepth = 10000

// bindingMember is the assertion member that carries the binding, the only
// member left out of the assertion hash.
const bindingMember = "binding"

// firstUnescapedByte is the lowest byte allowed unescaped in a JSON string.
const firstUnescapedByte = 0x20

// nameSetMapThreshold is the member count above which duplicate detection
// switches from a linear scan to a map.
const nameSetMapThreshold = 16

type jsonKind uint8

const (
	jsonInvalid jsonKind = iota
	jsonObject
	jsonArray
	jsonString
	jsonNumber
	jsonTrue
	jsonFalse
	jsonNull
)

// jsonLevel says which modelled member names, if any, apply to an object.
type jsonLevel uint8

const (
	levelOther jsonLevel = iota
	levelManifest
	levelPayload
	levelEncryptionInformation
	levelKeyAccessList // the array value of encryptionInformation.keyAccess
	levelKeyAccess
	levelPolicyBinding
	levelMethod
	levelIntegrityInformation
	levelRootSignature
	levelSegmentList // the array value of integrityInformation.segments
	levelSegment
	levelAssertionList // the array value of the manifest's assertions
	levelAssertion
	levelStatement
	levelBinding
	levelCount
)

// levelSpec describes one level of the manifest for spec Section 3.2.
type levelSpec struct {
	// path names the level: the member names from the manifest root joined
	// by dots, with [] for each element of an array, and empty for the root.
	path string
	// names are the member names the SDK models at this level. An object at
	// this level may not hold a case variant of one of them (R1), nor two
	// members whose names are case variants of each other (R2).
	names []string
	// exceptions are case variants that R1 tolerates at this level.
	exceptions []string
	// children gives the level of the value of a modelled member.
	children map[string]jsonLevel
	// elements is, for an array level, the level of each element.
	elements jsonLevel
}

// levelSpecs is the table of modelled member names in spec Section 3.2. The
// checks apply only to objects at these levels: not inside statement.value,
// not inside members the table does not list, and not to JSON carried in
// string values.
//
//nolint:goconst // the same member names recur at different levels by design
var levelSpecs = [levelCount]levelSpec{
	levelManifest: {
		path:  "", // the manifest root
		names: []string{"assertions", "encryptionInformation", "payload", "schemaVersion", "tdf_spec_version"},
		children: map[string]jsonLevel{
			"assertions":            levelAssertionList,
			"encryptionInformation": levelEncryptionInformation,
			"payload":               levelPayload,
		},
	},
	levelPayload: {
		path:  "payload",
		names: []string{"type", "url", "protocol", "mimeType", "isEncrypted", "tdf_spec_version"},
	},
	levelEncryptionInformation: {
		path:  "encryptionInformation",
		names: []string{"type", "policy", "keyAccess", "method", "integrityInformation"},
		children: map[string]jsonLevel{
			"keyAccess":            levelKeyAccessList,
			"method":               levelMethod,
			"integrityInformation": levelIntegrityInformation,
		},
	},
	levelKeyAccessList: {elements: levelKeyAccess},
	levelKeyAccess: {
		path: "encryptionInformation.keyAccess[]",
		names: []string{
			"type", "url", "protocol", "wrappedKey", "policyBinding", "encryptedMetadata",
			"kid", "sid", "schemaVersion", "ephemeralPublicKey",
		},
		children: map[string]jsonLevel{"policyBinding": levelPolicyBinding},
	},
	levelPolicyBinding: {
		path:  "encryptionInformation.keyAccess[].policyBinding",
		names: []string{"alg", "hash"},
	},
	levelMethod: {
		path:  "encryptionInformation.method",
		names: []string{"algorithm", "iv", "isStreamable"},
		// java-sdk up to v0.7.5 wrote IsStreamable; readers give it no meaning.
		exceptions: []string{"IsStreamable"},
	},
	levelIntegrityInformation: {
		path:  "encryptionInformation.integrityInformation",
		names: []string{"rootSignature", "segmentHashAlg", "segmentSizeDefault", "encryptedSegmentSizeDefault", "segments"},
		children: map[string]jsonLevel{
			"rootSignature": levelRootSignature,
			"segments":      levelSegmentList,
		},
	},
	levelRootSignature: {
		path:  "encryptionInformation.integrityInformation.rootSignature",
		names: []string{"alg", "sig"},
	},
	levelSegmentList: {elements: levelSegment},
	levelSegment: {
		path:  "encryptionInformation.integrityInformation.segments[]",
		names: []string{"hash", "segmentSize", "encryptedSegmentSize"},
	},
	levelAssertionList: {elements: levelAssertion},
	levelAssertion: {
		path:  "assertions[]",
		names: []string{"id", "type", "scope", "appliesToState", "statement", bindingMember},
		children: map[string]jsonLevel{
			"statement":   levelStatement,
			bindingMember: levelBinding,
		},
	},
	levelStatement: {
		path:  "assertions[].statement",
		names: []string{"format", "schema", "value"},
	},
	levelBinding: {
		path:  "assertions[].binding",
		names: []string{"method", "signature", "bdo"},
	},
}

// modelledByFold indexes each level's modelled names by their folded form.
var modelledByFold = func() [levelCount]map[string]string {
	var index [levelCount]map[string]string
	for level, spec := range levelSpecs {
		if len(spec.names) == 0 {
			continue
		}
		index[level] = make(map[string]string, len(spec.names))
		for _, name := range spec.names {
			index[level][foldName(name)] = name
		}
	}
	return index
}()

// foldName maps ASCII A to Z to a to z, U+017F (long s) to s, and U+212A
// (Kelvin sign) to k, leaving every other code point unchanged. Two names
// are case variants when they differ but fold to the same string, which for
// an ASCII name is exactly how encoding/json matches struct fields
// (strings.EqualFold).
func foldName(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r == '\u017F':
			return 's'
		case r == '\u212A':
			return 'k'
		default:
			return r
		}
	}, name)
}

// jsonNode is a parsed JSON value. Every value keeps its byte span in the
// source. With a capture depth of n, an object or array keeps its members or
// elements when n >= 1 and a string keeps its decoded text when n >= 1; the
// values inside are parsed with n-1.
type jsonNode struct {
	kind  jsonKind
	start int
	end   int
	// str is the decoded text of a captured string.
	str string
	// strProblem names the I-JSON violation in a string, or is empty.
	strProblem string
	members    []jsonMember
	elems      []jsonNode
}

type jsonMember struct {
	name string
	// start is the offset of the opening quote of the member name, so
	// source[start:value.end] is the member exactly as received.
	start int
	value jsonNode
}

// member returns the value of the member named exactly name. Callers only
// use it on parsed objects, which hold no duplicate names.
func (n jsonNode) member(name string) (jsonNode, bool) {
	for _, m := range n.members {
		if m.name == name {
			return m.value, true
		}
	}
	return jsonNode{}, false
}

// jsonSyntaxError reports input that is not JSON at all.
type jsonSyntaxError struct {
	offset int
	msg    string
}

func (e *jsonSyntaxError) Error() string {
	return fmt.Sprintf("invalid JSON at offset %d: %s", e.offset, e.msg)
}

// assertionTrack records what the scanner learned about one assertion
// object's exact "id" member, so a parse failure can name the assertion.
type assertionTrack struct {
	idCount int
	id      string
	idValid bool
}

// jsonFinding is a Section 3 violation in otherwise well-formed JSON.
type jsonFinding struct {
	reason    AssertionFailureReason
	detail    string
	assertion *assertionTrack
}

// Findings are reported in the order Section 8 lists the checks: duplicates
// first, then case variants, then I-JSON violations. Within a kind, the first
// one in document order wins.
const (
	findingDuplicate = iota
	findingAmbiguous
	findingIJSON
	findingKinds
)

type strictJSONParser struct {
	data     []byte
	pos      int
	depth    int
	findings [findingKinds]*jsonFinding
	current  *assertionTrack
}

// parseStrictJSON parses data, applying the Section 3 rules for an object at
// level root, and captures values up to capture levels deep.
//
// It returns a *jsonSyntaxError for input that is not JSON, and an
// ErrAssertionFailure for a Section 3 violation. When both occur, the
// violation is reported, since it was found first.
func parseStrictJSON(data []byte, root jsonLevel, capture int) (jsonNode, error) {
	p := &strictJSONParser{data: data}
	node, err := p.parseValue(root, false, capture)
	if err == nil {
		p.skipWhitespace()
		if p.pos != len(p.data) {
			err = p.syntaxError("unexpected data after the top-level value")
		}
	}
	for _, f := range p.findings {
		if f != nil {
			return node, f.err()
		}
	}
	return node, err
}

func (f *jsonFinding) err() error {
	id := ""
	if f.assertion != nil && f.assertion.idCount == 1 && f.assertion.idValid {
		id = f.assertion.id
	}
	return assertionFailure(id, f.reason, f.detail)
}

// section3Error turns a scanner error into the typed failure that Section 9
// assigns to it: input that is not JSON is invalid-json.
func section3Error(id string, err error) error {
	var se *jsonSyntaxError
	if errors.As(err, &se) {
		return assertionFailure(id, AssertionReasonInvalidJSON, se.Error())
	}
	return err
}

// parseManifestSection3 applies spec Section 3 to a whole manifest.
func parseManifestSection3(manifest []byte) error {
	_, err := parseStrictJSON(manifest, levelManifest, 0)
	return section3Error("", err)
}

// checkManifestSection3 is parseManifestSection3 for readers. A manifest that
// is not JSON at all is left to the existing decoder, so its error does not
// change. If the decoder would accept what this scanner calls malformed, the
// manifest is rejected anyway rather than read without the Section 3 checks.
func checkManifestSection3(manifest []byte) error {
	_, err := parseStrictJSON(manifest, levelManifest, 0)
	var se *jsonSyntaxError
	if errors.As(err, &se) && !json.Valid(manifest) {
		return nil
	}
	return section3Error("", err)
}

func (p *strictJSONParser) note(kind int, reason AssertionFailureReason, detail string) {
	if p.findings[kind] == nil {
		p.findings[kind] = &jsonFinding{reason: reason, detail: detail, assertion: p.current}
	}
}

func (p *strictJSONParser) syntaxError(msg string) error {
	return &jsonSyntaxError{offset: p.pos, msg: msg}
}

func (p *strictJSONParser) skipWhitespace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *strictJSONParser) parseValue(level jsonLevel, iJSON bool, capture int) (jsonNode, error) {
	p.skipWhitespace()
	if p.pos >= len(p.data) {
		return jsonNode{}, p.syntaxError("unexpected end of input")
	}
	start := p.pos
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.parseObject(level, iJSON, capture)
	case c == '[':
		return p.parseArray(level, iJSON, capture)
	case c == '"':
		s, problem, err := p.parseString(capture > 0)
		if err != nil {
			return jsonNode{}, err
		}
		if iJSON && problem != "" {
			p.note(findingIJSON, AssertionReasonInvalidJSON, "string contains "+problem)
		}
		return jsonNode{kind: jsonString, start: start, end: p.pos, str: s, strProblem: problem}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		if err := p.parseNumber(iJSON); err != nil {
			return jsonNode{}, err
		}
		return jsonNode{kind: jsonNumber, start: start, end: p.pos}, nil
	case c == 't':
		return p.parseLiteral("true", jsonTrue)
	case c == 'f':
		return p.parseLiteral("false", jsonFalse)
	case c == 'n':
		return p.parseLiteral("null", jsonNull)
	default:
		return jsonNode{}, p.syntaxError(fmt.Sprintf("unexpected character %q", c))
	}
}

func (p *strictJSONParser) parseLiteral(lit string, kind jsonKind) (jsonNode, error) {
	start := p.pos
	if !bytes.HasPrefix(p.data[p.pos:], []byte(lit)) {
		return jsonNode{}, p.syntaxError("invalid literal")
	}
	p.pos += len(lit)
	return jsonNode{kind: kind, start: start, end: p.pos}, nil
}

func (p *strictJSONParser) enter() error {
	p.depth++
	if p.depth > maxJSONDepth {
		return p.syntaxError("exceeded maximum nesting depth")
	}
	return nil
}

// childLevel returns the level of the value of member name in an object at
// level. It applies only if that value is an object, or, for an array level,
// an array of objects. Only the exact name leads to a child level; a case
// variant is rejected instead.
func childLevel(level jsonLevel, name string) jsonLevel {
	if child, ok := levelSpecs[level].children[name]; ok {
		return child
	}
	return levelOther
}

// caseVariantOf returns the modelled member name at level of which name is a
// case variant (rule R1), unless the level tolerates that variant.
func caseVariantOf(level jsonLevel, name string) (string, bool) {
	modelled, ok := modelledByFold[level][foldName(name)]
	if !ok || modelled == name || slices.Contains(levelSpecs[level].exceptions, name) {
		return "", false
	}
	return modelled, true
}

// caseVariantSet detects two members of one object whose names are case
// variants of each other (rule R2).
type caseVariantSet map[string]string

func (s caseVariantSet) add(name string) (string, bool) {
	folded := foldName(name)
	if prev, ok := s[folded]; ok {
		return prev, prev != name
	}
	s[folded] = name
	return "", false
}

// nameSet detects repeated member names in one object.
type nameSet struct {
	small []string
	big   map[string]struct{}
}

func (s *nameSet) add(name string) bool {
	if s.big != nil {
		if _, dup := s.big[name]; dup {
			return true
		}
		s.big[name] = struct{}{}
		return false
	}
	for _, n := range s.small {
		if n == name {
			return true
		}
	}
	s.small = append(s.small, name)
	if len(s.small) > nameSetMapThreshold {
		s.big = make(map[string]struct{}, len(s.small)*2) //nolint:mnd // headroom for growth
		for _, n := range s.small {
			s.big[n] = struct{}{}
		}
		s.small = nil
	}
	return false
}

func (p *strictJSONParser) parseObject(level jsonLevel, iJSON bool, capture int) (jsonNode, error) {
	node := jsonNode{kind: jsonObject, start: p.pos}
	p.pos++ // '{'
	if err := p.enter(); err != nil {
		return jsonNode{}, err
	}
	defer func() { p.depth-- }()

	var track *assertionTrack
	if level == levelAssertion {
		track = &assertionTrack{}
		saved := p.current
		p.current = track
		defer func() { p.current = saved }()
		iJSON = true
	}

	var names nameSet
	var variants caseVariantSet
	if modelledByFold[level] != nil {
		variants = caseVariantSet{}
	}
	p.skipWhitespace()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		node.end = p.pos
		return node, nil
	}
	for {
		p.skipWhitespace()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return jsonNode{}, p.syntaxError("expected a member name")
		}
		nameStart := p.pos
		name, problem, err := p.parseString(true)
		if err != nil {
			return jsonNode{}, err
		}
		if iJSON && problem != "" {
			p.note(findingIJSON, AssertionReasonInvalidJSON, "member name contains "+problem)
		}
		if names.add(name) {
			p.note(findingDuplicate, AssertionReasonDuplicateMember, fmt.Sprintf("duplicate member %q", name))
		}
		if variants != nil {
			if modelled, ok := caseVariantOf(level, name); ok {
				p.note(findingAmbiguous, AssertionReasonAmbiguousMember,
					fmt.Sprintf("member %q is a case variant of %q", name, modelled))
			}
			if prev, ok := variants.add(name); ok {
				p.note(findingAmbiguous, AssertionReasonAmbiguousMember,
					fmt.Sprintf("members %q and %q are case variants of each other", prev, name))
			}
		}

		p.skipWhitespace()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return jsonNode{}, p.syntaxError("expected ':' after a member name")
		}
		p.pos++

		childCapture := max(capture-1, 0)
		if track != nil && name == "id" {
			// The id names the assertion in errors, so decode it even when
			// nothing else is captured.
			childCapture = max(childCapture, 1)
		}
		value, err := p.parseValue(childLevel(level, name), iJSON, childCapture)
		if err != nil {
			return jsonNode{}, err
		}
		if track != nil && name == "id" {
			track.idCount++
			track.id = value.str
			track.idValid = value.kind == jsonString && value.str != "" && value.strProblem == ""
		}
		if capture > 0 {
			node.members = append(node.members, jsonMember{name: name, start: nameStart, value: value})
		}

		p.skipWhitespace()
		if p.pos >= len(p.data) {
			return jsonNode{}, p.syntaxError("unterminated object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			node.end = p.pos
			return node, nil
		default:
			return jsonNode{}, p.syntaxError("expected ',' or '}' in an object")
		}
	}
}

func (p *strictJSONParser) parseArray(level jsonLevel, iJSON bool, capture int) (jsonNode, error) {
	node := jsonNode{kind: jsonArray, start: p.pos}
	p.pos++ // '['
	if err := p.enter(); err != nil {
		return jsonNode{}, err
	}
	defer func() { p.depth-- }()

	elemLevel := levelSpecs[level].elements
	p.skipWhitespace()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		node.end = p.pos
		return node, nil
	}
	for {
		value, err := p.parseValue(elemLevel, iJSON, max(capture-1, 0))
		if err != nil {
			return jsonNode{}, err
		}
		if capture > 0 {
			node.elems = append(node.elems, value)
		}
		p.skipWhitespace()
		if p.pos >= len(p.data) {
			return jsonNode{}, p.syntaxError("unterminated array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			node.end = p.pos
			return node, nil
		default:
			return jsonNode{}, p.syntaxError("expected ',' or ']' in an array")
		}
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (p *strictJSONParser) skipDigits() int {
	n := 0
	for p.pos < len(p.data) && isDigit(p.data[p.pos]) {
		p.pos++
		n++
	}
	return n
}

// parseNumber scans an RFC 8259 number. Inside an assertion, a number that
// overflows a double becomes Infinity, which RFC 8785 cannot canonicalize, so
// it is an I-JSON violation. Underflow to zero is not.
func (p *strictJSONParser) parseNumber(iJSON bool) error {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	switch {
	case p.pos < len(p.data) && p.data[p.pos] == '0':
		p.pos++
	case p.skipDigits() == 0:
		return p.syntaxError("invalid number")
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if p.skipDigits() == 0 {
			return p.syntaxError("invalid number: no digits after the decimal point")
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if p.skipDigits() == 0 {
			return p.syntaxError("invalid number: no digits in the exponent")
		}
	}
	if iJSON {
		f, _ := strconv.ParseFloat(string(p.data[start:p.pos]), 64)
		if math.IsInf(f, 0) {
			p.note(findingIJSON, AssertionReasonInvalidJSON, "number is outside the IEEE 754 double range")
		}
	}
	return nil
}

// isNoncharacter reports whether r is a Unicode noncharacter: U+FDD0 to
// U+FDEF, or the last two code points of any plane.
func isNoncharacter(r rune) bool {
	return (r >= 0xFDD0 && r <= 0xFDEF) || (r&0xFFFE == 0xFFFE && r <= utf8.MaxRune)
}

func hexValue(c byte) (rune, bool) {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0'), true
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10, true //nolint:mnd // hex digit value
	case c >= 'A' && c <= 'F':
		return rune(c-'A') + 10, true //nolint:mnd // hex digit value
	default:
		return 0, false
	}
}

// hex4 reads the four hex digits of a \u escape at offset at.
func (p *strictJSONParser) hex4(at int) (rune, bool) {
	const digits = 4
	if at+digits > len(p.data) {
		return 0, false
	}
	var r rune
	for i := range digits {
		v, ok := hexValue(p.data[at+i])
		if !ok {
			return 0, false
		}
		r = r<<4 | v //nolint:mnd // one hex digit is four bits
	}
	return r, true
}

// parseString scans a string starting at its opening quote. It returns the
// decoded text if decode is set, and the first I-JSON violation found, if
// any. Like encoding/json, it decodes a lone surrogate or an invalid UTF-8
// byte as U+FFFD, so decoded names compare the way Go's decoder sees them.
func (p *strictJSONParser) parseString(decode bool) (string, string, error) {
	p.pos++ // opening quote
	var b []byte
	problem := ""
	flag := func(what string) {
		if problem == "" {
			problem = what
		}
	}
	for {
		if p.pos >= len(p.data) {
			return "", "", p.syntaxError("unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return string(b), problem, nil
		case c == '\\':
			r, err := p.parseEscape(flag)
			if err != nil {
				return "", "", err
			}
			if decode {
				b = utf8.AppendRune(b, r)
			}
		case c < firstUnescapedByte:
			return "", "", p.syntaxError("control character in a string")
		case c < utf8.RuneSelf:
			if decode {
				b = append(b, c)
			}
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size == 1 {
				flag("invalid UTF-8")
				p.note(findingIJSON, AssertionReasonInvalidJSON, "invalid UTF-8")
			} else if isNoncharacter(r) {
				flag("a noncharacter")
			}
			if decode {
				b = utf8.AppendRune(b, r)
			}
			p.pos += size
		}
	}
}

// parseEscape decodes the escape sequence at p.pos, which holds a backslash.
func (p *strictJSONParser) parseEscape(flag func(string)) (rune, error) {
	const (
		prefixLen  = 2 // the backslash and the escape letter
		hexLen     = 4
		uEscapeLen = prefixLen + hexLen
		lowStart   = 0xDC00
		lowEnd     = 0xDFFF
	)
	if p.pos+1 >= len(p.data) {
		return 0, p.syntaxError("unterminated escape")
	}
	e := p.data[p.pos+1]
	p.pos += prefixLen
	switch e {
	case '"', '\\', '/':
		return rune(e), nil
	case 'b':
		return '\b', nil
	case 'f':
		return '\f', nil
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case 'u':
	default:
		return 0, p.syntaxError(fmt.Sprintf("invalid escape %q", e))
	}
	r, ok := p.hex4(p.pos)
	if !ok {
		return 0, p.syntaxError("invalid \\u escape")
	}
	p.pos += hexLen
	if !utf16.IsSurrogate(r) {
		if isNoncharacter(r) {
			flag("a noncharacter")
		}
		return r, nil
	}
	if r < lowStart && p.pos+uEscapeLen <= len(p.data) && p.data[p.pos] == '\\' && p.data[p.pos+1] == 'u' {
		if low, isHex := p.hex4(p.pos + prefixLen); isHex && low >= lowStart && low <= lowEnd {
			p.pos += uEscapeLen
			combined := utf16.DecodeRune(r, low)
			if isNoncharacter(combined) {
				flag("a noncharacter")
			}
			return combined, nil
		}
	}
	flag("a lone surrogate")
	return utf8.RuneError, nil
}

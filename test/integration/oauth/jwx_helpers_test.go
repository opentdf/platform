package oauth_test

// jwtField returns the named claim as stored by jwx, and whether it is present.
func jwtField(g interface{ Get(string, any) error }, name string) (any, bool) {
	var v any
	if err := g.Get(name, &v); err != nil {
		return nil, false
	}
	return v, true
}

package attributes

import (
	"fmt"
	"regexp"
)

// Reference to a specific attribute and value
type AttributeInstance struct {
	Authority, Name, Value string
}

var attrRE = regexp.MustCompile(`(?P<a>https?://(?:[a-z0-9](?:[a-z0-9-]{0,61})(?:[a-z0-9])?\.)*(?:[a-z0-9](?:[a-z0-9-]{0,61})(?:[a-z0-9])))/attr/(?P<n>[A-Za-z0-9](?:[A-Za-z0-9-]+[A-Za-z0-9])?)/value/(?P<v>[A-Za-z0-9.-]+)`)

func AttributeInstanceFromURL(s string) (*AttributeInstance, error) {
	m := attrRE.FindStringSubmatch(s)
	if len(m) == 0 {
		return nil, InvalidAttributeError(s)
	}
	return &AttributeInstance{m[1], m[2], m[3]}, nil
}

func (a *AttributeInstance) String() string {
	return fmt.Sprintf("%s/attr/%s/value/%s", a.Authority, a.Name, a.Value)
}

type InvalidAttributeError string

func (e InvalidAttributeError) Error() string {
	return fmt.Sprintf("invalid url [%s]", string(e))
}

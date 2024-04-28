package main

import (
	"fmt"
	"github.com/arkavo-org/opentdf-platform/examples/cmd"
	"github.com/go-ldap/ldap/v3"
	"log"
)

func main() {
	cmd.Execute()
	//ExampleConn_Search()
	//ExampleConn_Bind()
}

func ExampleConn_Bind() {
	l, err := ldap.DialURL("ldap://localhost:389")
	if err != nil {
		log.Fatal(err)
	}
	defer func(l *ldap.Conn) {
		err := l.Close()
		if err != nil {

		}
	}(l)

	err = l.Bind("cn=admin", "admin")
	if err != nil {
		log.Fatal(err)
	}
}

// This example demonstrates how to use the search interface
func ExampleConn_Search() {
	l, err := ldap.DialURL("ldap://localhost:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	searchRequest := ldap.NewSearchRequest(
		"dc=example,dc=com", // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=organizationalPerson))", // The filter to apply
		[]string{"dn", "cn"},                    // A list attributes to retrieve
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	for _, entry := range sr.Entries {
		fmt.Printf("%s: %v\n", entry.DN, entry.GetAttributeValue("cn"))
	}
}

package main

import (
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
)

type b string

type entity struct {
	userId string
}

var Revocation b

var allowlistEnv = os.Getenv("EO_ALLOW_LIST")
var blockListEnv = os.Getenv("EO_ALLOW_LIST")

func Update(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Entity := r.Header.Get("entity")
		mockEntity := entity{userId: "mockId"}
		if !match(mockEntity) {
			w.WriteHeader(http.StatusForbidden)
			_, err := fmt.Fprint(w, "Access denied")
			if err != nil {
				panic(err)
			}
		}

		next(w, r)
	}
}

func Upsert(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Entity := r.Header.Get("entity")
		mockEntity := entity{userId: "mockId"}
		if !match(mockEntity) {
			w.WriteHeader(http.StatusForbidden)
			_, err := fmt.Fprint(w, "Access denied")
			if err != nil {
				panic(err)
			}
		}

		next(w, r)
	}
}

func match(entity entity) bool {
	allows := strings.Split(allowlistEnv, ",")
	blocks := strings.Split(blockListEnv, ",")

	if slices.Contains(blocks, entity.userId) {
		return false
	}

	if slices.Contains(allows, "*") {
		return true
	}

	return slices.Contains(allows, entity.userId)
}

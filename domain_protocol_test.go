package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveDomainURLFallsBackToHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	want := server.URL + "/library"
	got, err := resolveDomainURL(strings.TrimPrefix(want, "http://"))
	if err != nil || got != want {
		t.Fatalf("got %q, %v; want %q", got, err, want)
	}
}

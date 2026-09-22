package main

import (
	"strings"
	"testing"
	"time"
)

// TestNormalizeEndpoint pins the -url normalisation rules. The case that
// motivated them is "origin only": a run against http://localhost:8080 used to
// 404 five times in a row and abort under the Appendix B streak rule, which
// looks in the report exactly like a service that fell over.
func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		want     string
		wantNote bool // a note is printed to stderr for the operator
	}{
		{
			name:     "origin without path",
			in:       "http://localhost:8080",
			want:     "http://localhost:8080/process",
			wantNote: true,
		},
		{
			name:     "origin with trailing slash",
			in:       "http://localhost:8080/",
			want:     "http://localhost:8080/process",
			wantNote: true,
		},
		{
			name: "already the endpoint",
			in:   "http://localhost:8080/process",
			want: "http://localhost:8080/process",
		},
		{
			name:     "endpoint with trailing slash",
			in:       "http://localhost:8080/process/",
			want:     "http://localhost:8080/process",
			wantNote: true,
		},
		{
			name:     "some other path is left alone",
			in:       "https://staging.example.com/api/v1/mask",
			want:     "https://staging.example.com/api/v1/mask",
			wantNote: true,
		},
		{
			name:     "query string survives the appended path",
			in:       "http://localhost:8080?debug=1",
			want:     "http://localhost:8080/process?debug=1",
			wantNote: true,
		},
		{
			name: "https origin with explicit port",
			in:   "https://127.0.0.1:9443/process",
			want: "https://127.0.0.1:9443/process",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, note, err := normalizeEndpoint(tc.in)
			if err != nil {
				t.Fatalf("normalizeEndpoint(%q): unexpected error %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("normalizeEndpoint(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if (note != "") != tc.wantNote {
				t.Errorf("normalizeEndpoint(%q) note = %q, wantNote %v", tc.in, note, tc.wantNote)
			}
		})
	}
}

// TestNormalizeEndpointRejects covers the inputs we refuse rather than guess
// at. Normalisation may add a missing path; it may never invent a host.
func TestNormalizeEndpointRejects(t *testing.T) {
	for _, in := range []string{
		"http://",
		"http:///process",
		"http://foo\x7f/process",
	} {
		if got, _, err := normalizeEndpoint(in); err == nil {
			t.Errorf("normalizeEndpoint(%q) = %q, want an error", in, got)
		}
	}
}

// TestValidateNormalizesURL checks that the normalisation is actually wired
// into option validation, not just available as a helper.
func TestValidateNormalizesURL(t *testing.T) {
	o := options{
		url:         "http://localhost:8080",
		rps:         10,
		duration:    time.Second,
		concurrency: 1,
		timeout:     time.Second,
	}
	if err := o.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if o.url != "http://localhost:8080/process" {
		t.Errorf("validate left url = %q", o.url)
	}
	if !strings.Contains(o.urlNote, "/process") {
		t.Errorf("validate left urlNote = %q, want a note naming the endpoint", o.urlNote)
	}
}

// TestValidateRejectsRelativeURL keeps the pre-existing absolute-URL rule in
// force: normalisation must not have turned a scheme-less argument into
// something the HTTP client would silently accept.
func TestValidateRejectsRelativeURL(t *testing.T) {
	o := options{
		url:         "localhost:8080",
		rps:         10,
		duration:    time.Second,
		concurrency: 1,
		timeout:     time.Second,
	}
	if err := o.validate(); err == nil {
		t.Fatal("validate accepted a URL with no scheme")
	}
}

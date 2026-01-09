package auth

import (
	"testing"
	"reflect"
	"errors"
	"net/http"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		header http.Header
		want string
		err error
	}{
		"valid": {header: http.Header{"Authorization": []string{"ApiKey valid"}}, want: "valid", err: nil},
		"no-apikey": {header: http.Header{"Authorization": []string{"AuthKey invalid"}}, err: errors.New("malformed authorization header"), want: ""},
		"empty-apikey": {header: http.Header{"Authorization": []string{"ApiKey "}}, err: nil, want: ""},
		"empty-header": {header: http.Header{}, err: ErrNoAuthHeaderIncluded, want: ""},
		"no-authheader": {header: http.Header{"ApiKey": []string{"ApiKey"}}, err: ErrNoAuthHeaderIncluded, want: ""},
		"invalid-authheader": {header: http.Header{"Authorization": []string{"AuthKey"}}, err: errors.New("malformed authorization header"), want: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.header)
			if !reflect.DeepEqual(tc.err, err){
				t.Fatalf("Reported error: %v\nExpected error: %v\nInput header: %v", err, tc.err, tc.header)
			}
			if !reflect.DeepEqual(tc.want, got) {
				t.Fatalf("Expected value: %v, returned value: %v, input header: %v", tc.want, got, tc.header)
			}
		})
	}
}

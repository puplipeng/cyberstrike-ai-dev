package database

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSQLNullStringRepairsInvalidUTF8(t *testing.T) {
	value := sqlNullString(string([]byte{0xcb, 0xf9, 'o', 'k'}))
	if !value.Valid || !utf8.ValidString(value.String) || !strings.Contains(value.String, "ok") {
		t.Fatalf("invalid UTF-8 was not repaired: %#v", value)
	}
}

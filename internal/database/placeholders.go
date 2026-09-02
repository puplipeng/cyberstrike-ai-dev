package database

import (
	"strconv"
	"strings"
)

// postgresPlaceholders builds a bound IN list; start is the one-based index.
func postgresPlaceholders(start, count int) string {
	params := make([]string, count)
	for i := range params {
		params[i] = "$" + strconv.Itoa(start+i)
	}
	return strings.Join(params, ",")
}

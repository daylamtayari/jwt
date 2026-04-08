package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Exits the program fatally and prints the given error
func fatal(err error) {
	fmt.Fprintf(os.Stderr, "%s\n", err.Error())
	os.Exit(1)
}

// Marshals to JSON and prints the provided value
func printJSON(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("%s\n", string(data))
}

// Returns true if a value was passed throught stdin
func hasStdin() bool {
	siStat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (siStat.Mode()&os.ModeCharDevice == 0)
}

// Reads the value in from stdin
func readStdin() string {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal(err)
	}
	return strings.TrimSpace(string(data))
}

// Must decodes the signature string or fatally exits
func mustDecodeSig(sig string) []byte {
	data, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		fatal(err)
	}
	return data
}

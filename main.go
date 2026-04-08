package main

import (
	"errors"
	"fmt"
	"os"
	"time"
)

var (
	ErrExpired    = errors.New("JWT is expired")
	ErrInvalidExp = errors.New("invalid exp claim")
	ErrNoKey      = errors.New("no key provided")
)

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		// No arguments and token passed from stdin
		if hasStdin() {
			jwt := mustParse(readStdin())
			printJSON(jwt)
		} else {
			printUsage()
		}
		return
	}

	cmd := args[0]
	switch cmd {
	case "decode":
		jwt := mustParse(getToken(args[1:]))
		printJSON(jwt)
	case "data", "payload":
		jwt := mustParse(getToken(args[1:]))
		printJSON(jwt.Payload)
	case "header", "headers":
		jwt := mustParse(getToken(args[1:]))
		printJSON(jwt.Header)
	case "sig":
		jwt := mustParse(getToken(args[1:]))
		os.Stdout.Write(mustDecodeSig(jwt.Signature))
	case "valid":
		key, remaining := parseKeyFlag(args[1:])
		jwt := mustParse(getToken(remaining))

		// Check expiry
		if exp, exists := jwt.Payload["exp"]; exists {
			expVal, ok := exp.(float64)
			if !ok {
				fatal(ErrInvalidExp)
			}
			if time.Now().Unix() > int64(expVal) {
				fatal(ErrExpired)
			}
		}

		// Verify signature only if it was provided
		if key != "" {
			if err := Verify(jwt, key); err != nil {
				fatal(err)
			}
		}

		os.Stdout.Write([]byte("true"))
	case "verify":
		key, remaining := parseKeyFlag(args[1:])
		if key == "" {
			fatal(ErrNoKey)
		}
		jwt := mustParse(getToken(remaining))
		if err := Verify(jwt, key); err != nil {
			fatal(err)
		}
		os.Stdout.Write([]byte("true"))
	case "help", "--help", "-h":
		printUsage()
	default:
		jwt := mustParse(args[0])
		printJSON(jwt)
	}
}

// Prints usage instructions
func printUsage() {
	fmt.Printf("%s\n", `Usage:

	`)
}

// Retrieves token from arguments and if not present, from stdin
func getToken(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	if hasStdin() {
		return readStdin()
	}

	// If no token is specified via arguments or stdin, output help
	printUsage()
	os.Exit(0)
	return ""
}

// Parses arguments for a key flag and its value
// Returns the key flag value and the remaining args
// NOTE: If no key is present, an empty string is
// returned for the key
func parseKeyFlag(args []string) (string, []string) {
	var key string
	var remaining []string
	for i := 0; i < len(args); i++ {
		if args[i] == "-k" || args[i] == "--key" {
			if i+1 >= len(args) {
				fatal(ErrNoKey)
			}
			key = args[i+1]
			i++
		} else {
			remaining = append(remaining, args[i])
		}
	}
	return key, remaining
}

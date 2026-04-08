package main

import (
	"fmt"
	"os"
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
	case "header":
		jwt := mustParse(getToken(args[1:]))
		printJSON(jwt.Header)
	case "sig":
		jwt := mustParse(getToken(args[1:]))
		os.Stdout.Write(mustDecodeSig(jwt.Signature))
	case "help":
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
	return readStdin()
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidJWT = errors.New("invalid JWT")
)

// Represents a JWT and its part and their respective claims
type JWT struct {
	Header       map[string]any
	Payload      map[string]any
	Signature    string
	signingInput string
}

// Parses a JWT returning a JWT type and an error that is nil if successful
func Parse(token string) (JWT, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return JWT{}, ErrInvalidJWT
	}
	header, err := decodeComponent(parts[0])
	if err != nil {
		return JWT{}, fmt.Errorf("%w: %w", ErrInvalidJWT, err)
	}
	payload, err := decodeComponent(parts[1])
	if err != nil {
		return JWT{}, fmt.Errorf("%w: %w", ErrInvalidJWT, err)
	}

	return JWT{
		Header:       header,
		Payload:      payload,
		Signature:    parts[2],
		signingInput: parts[0] + "." + parts[1],
	}, nil
}

// Decodes a JWT component and returns its claims and an error that is nil if successful
func decodeComponent(seg string) (map[string]any, error) {
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, err
	}

	return claims, nil
}

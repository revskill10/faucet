// Package identity verifies the signed identity a request carries for a
// PostgreSQL service (model.IdentityConfig) and turns it into the settings the
// request's transaction applies.
package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/faucetdb/faucet/internal/model"
)

// ErrInvalid is returned for any token that does not verify. Its message never
// includes the token or the reason in detail, so it is safe to return to clients.
var ErrInvalid = errors.New("invalid identity token")

// Claims are a verified token's claims, as decoded JSON.
type Claims map[string]any

// Verify checks a compact JWS (EdDSA) against the configuration: its signature
// by one of the public keys, its audience, and its validity period.
func Verify(cfg *model.IdentityConfig, token string, now time.Time) (Claims, error) {
	if cfg == nil || len(cfg.PublicKeys) == 0 {
		return nil, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalid
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := decodeJSON(parts[0], &header); err != nil || header.Alg != "EdDSA" {
		return nil, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalid
	}
	signed := []byte(parts[0] + "." + parts[1])
	verified := false
	for _, k := range cfg.PublicKeys {
		key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(k))
		if err != nil || len(key) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(key), signed, signature) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, ErrInvalid
	}
	var claims Claims
	if err := decodeJSON(parts[1], &claims); err != nil {
		return nil, ErrInvalid
	}
	leeway := time.Duration(cfg.LeewaySeconds) * time.Second
	if cfg.LeewaySeconds == 0 {
		leeway = 30 * time.Second
	}
	exp, ok := claims["exp"].(float64)
	if !ok || now.After(time.Unix(int64(exp), 0).Add(leeway)) {
		return nil, ErrInvalid
	}
	if nbf, ok := claims["nbf"].(float64); ok && now.Add(leeway).Before(time.Unix(int64(nbf), 0)) {
		return nil, ErrInvalid
	}
	if cfg.Audience != "" && !hasAudience(claims["aud"], cfg.Audience) {
		return nil, ErrInvalid
	}
	return claims, nil
}

func hasAudience(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func decodeJSON(segment string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// Setting is one transaction-local setting a request applies.
type Setting struct{ Name, Value string }

// Settings are what a verified identity sets: every claim as JSON in
// "request.claims", and each mapped claim under its setting name (strings as
// they are, anything else as JSON). Missing claims are set to "".
func Settings(cfg *model.IdentityConfig, claims Claims) ([]Setting, error) {
	all, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("encode claims: %w", err)
	}
	out := []Setting{{Name: "request.claims", Value: string(all)}}
	mapped := make([]string, 0, len(cfg.Settings))
	for claim := range cfg.Settings {
		mapped = append(mapped, claim)
	}
	sort.Strings(mapped)
	for _, claim := range mapped {
		name := cfg.Settings[claim]
		value := ""
		switch v := claims[claim].(type) {
		case nil:
		case string:
			value = v
		default:
			b, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("encode claim %q: %w", claim, err)
			}
			value = string(b)
		}
		out = append(out, Setting{Name: name, Value: value})
	}
	return out, nil
}

// HeaderName is the header a service's token is read from.
func HeaderName(cfg *model.IdentityConfig) string {
	if cfg.Header != "" {
		return cfg.Header
	}
	return model.IdentityHeader
}

// Validate checks an identity configuration before it is stored.
func Validate(cfg *model.IdentityConfig, driver string) error {
	if cfg == nil {
		return nil
	}
	if driver != "postgres" {
		return errors.New("identity is supported for PostgreSQL services only")
	}
	if len(cfg.PublicKeys) == 0 {
		return errors.New("identity needs at least one public key")
	}
	for _, k := range cfg.PublicKeys {
		key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(k))
		if err != nil || len(key) != ed25519.PublicKeySize {
			return errors.New("identity public keys must be raw Ed25519 keys, base64url without padding")
		}
	}
	for claim, name := range cfg.Settings {
		// PostgreSQL custom settings need a prefix: "app.user_id"
		if claim == "" || !settingName.MatchString(name) || name == "request.claims" {
			return fmt.Errorf("identity setting %q for claim %q must look like prefix.name and not be request.claims", name, claim)
		}
	}
	if cfg.LeewaySeconds < 0 || cfg.LeewaySeconds > 300 {
		return errors.New("identity leeway_seconds must be 0 to 300")
	}
	if cfg.SchemaClaim != "" && !claimName.MatchString(cfg.SchemaClaim) {
		return errors.New("identity schema_claim must be a simple claim name")
	}
	return nil
}

var claimName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
var versionName = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)

// SchemaVersion is the schema a request's tables are read and written in, as
// its token chooses (cfg.SchemaClaim): "" for the service's schema base, or
// base itself, or one of its versions "<base>_<version>". Anything else is
// refused.
func SchemaVersion(cfg *model.IdentityConfig, claims Claims, base string) (string, error) {
	if cfg == nil || cfg.SchemaClaim == "" {
		return "", nil
	}
	raw, present := claims[cfg.SchemaClaim]
	if !present || raw == nil {
		return "", nil
	}
	schema, ok := raw.(string)
	if !ok {
		return "", errors.New("schema claim must be a string")
	}
	if schema == "" || schema == base {
		return "", nil
	}
	if !strings.HasPrefix(schema, base+"_") || !versionName.MatchString(strings.TrimPrefix(schema, base+"_")) || len(schema) > 63 {
		return "", fmt.Errorf("schema %q is not a version of %q", schema, base)
	}
	return schema, nil
}

var settingName = regexp.MustCompile(`^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$`)

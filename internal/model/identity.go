package model

// IdentityConfig lets a PostgreSQL service carry the identity of the person
// behind each request into the database, so that row-level security policies
// (and any SQL that reads the settings) apply per person.
//
// A request presents a signed token (compact JWS, EdDSA) in Header alongside its
// API key. Faucet verifies it against PublicKeys and Audience, then runs every
// statement of the request in one transaction that first sets the token's
// claims as transaction-local settings: all of them as JSON in
// "request.claims", and each claim named in Settings under its setting name.
// With Role set, the transaction also switches to that role (SET LOCAL ROLE),
// so policies apply even though Faucet connects as the tables' owner.
type IdentityConfig struct {
	// Header carrying the token. Defaults to X-Faucet-Identity.
	Header string `json:"header,omitempty"`
	// PublicKeys are the Ed25519 public keys (raw 32 bytes, base64url) that may
	// sign tokens. Several allow key rotation.
	PublicKeys []string `json:"public_keys"`
	// Audience, when set, must appear in the token's "aud" claim.
	Audience string `json:"audience,omitempty"`
	// Required refuses API-key requests that carry no token.
	Required bool `json:"required,omitempty"`
	// Role is switched to for the request's transaction (SET LOCAL ROLE).
	Role string `json:"role,omitempty"`
	// Settings maps a claim name to the setting it is exposed as, e.g.
	// {"sub": "app.user_id"}. Non-string claims are set as JSON.
	Settings map[string]string `json:"settings,omitempty"`
	// LeewaySeconds tolerates clock skew when checking exp and nbf. Defaults to 30.
	LeewaySeconds int `json:"leeway_seconds,omitempty"`
	// SchemaClaim names the claim choosing the schema version a request's
	// table reads and writes use: the service's schema, or one of its versions
	// "<schema>_<version>" (such as the versioned schemas of pgroll, serving
	// old and new clients during a migration). Procedures, keys and schema
	// changes stay on the service's schema. Unset or absent: the service's schema.
	SchemaClaim string `json:"schema_claim,omitempty"`
}

// IdentityHeader is the header a token is read from when none is configured.
const IdentityHeader = "X-Faucet-Identity"

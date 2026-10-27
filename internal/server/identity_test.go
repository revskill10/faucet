package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/faucetdb/faucet/internal/connector"
	"github.com/faucetdb/faucet/internal/connector/postgres"
	"github.com/faucetdb/faucet/internal/model"
)

// Per-request identity against a real PostgreSQL (model.IdentityConfig). Set
// FAUCET_TEST_POSTGRES_DSN to a superuser connection to run these tests; each
// test uses a schema of its own and drops it afterwards.

type identityEnv struct {
	*testEnv
	key    ed25519.PrivateKey
	apiKey string
	schema string
	dsn    string
}

func newIdentityEnv(t *testing.T, required bool) *identityEnv {
	t.Helper()
	dsn := os.Getenv("FAUCET_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set FAUCET_TEST_POSTGRES_DSN to run per-request identity tests against PostgreSQL")
	}
	schema := fmt.Sprintf("identity_%d", time.Now().UnixNano())
	admin, err := sqlx.Connect("pgx", dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`)
		admin.Close()
	})
	// A table under row-level security: each person sees and writes their own notes
	statements := []string{
		`DO $$ BEGIN CREATE ROLE faucet_identity_member NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$`,
		`CREATE SCHEMA ` + schema,
		`CREATE TABLE ` + schema + `.notes (id serial PRIMARY KEY, owner text NOT NULL, body text NOT NULL)`,
		`INSERT INTO ` + schema + `.notes (owner, body) VALUES ('alice', 'a1'), ('alice', 'a2'), ('bob', 'b1')`,
		`ALTER TABLE ` + schema + `.notes ENABLE ROW LEVEL SECURITY`,
		`CREATE POLICY own ON ` + schema + `.notes USING (owner = current_setting('app.user_id', true)) WITH CHECK (owner = current_setting('app.user_id', true))`,
		`CREATE FUNCTION ` + schema + `.whoami() RETURNS TABLE(user_id text, claims text) LANGUAGE sql AS ` +
			`'SELECT coalesce(current_setting(''app.user_id'', true), ''''), coalesce(current_setting(''request.claims'', true), '''')'`,
		`GRANT USAGE ON SCHEMA ` + schema + ` TO faucet_identity_member`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ` + schema + `.notes TO faucet_identity_member`,
		`GRANT USAGE ON SEQUENCE ` + schema + `.notes_id_seq TO faucet_identity_member`,
		`GRANT EXECUTE ON FUNCTION ` + schema + `.whoami() TO faucet_identity_member`,
	}
	for _, s := range statements {
		if _, err := admin.Exec(s); err != nil {
			t.Fatalf("prepare schema: %v\n%s", err, s)
		}
	}

	env := newTestEnv(t)
	env.seedAdmin(t)
	env.registry.RegisterDriver("postgres", func() connector.Connector { return postgres.New() })
	// One connection: a setting or role left behind by one request would show in the next
	if err := env.registry.Connect("notes", connector.ConnectionConfig{Driver: "postgres", DSN: dsn, SchemaName: schema, MaxOpenConns: 1, MaxIdleConns: 1}); err != nil {
		t.Fatalf("connect service: %v", err)
	}
	t.Cleanup(func() { env.registry.Disconnect("notes") })

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	svc := &model.ServiceConfig{Name: "notes", Driver: "postgres", DSN: dsn, Schema: schema, IsActive: true, Pool: model.DefaultPoolConfig(),
		Identity: &model.IdentityConfig{PublicKeys: []string{base64.RawURLEncoding.EncodeToString(pub)}, Audience: "platform", Required: required,
			Role: "faucet_identity_member", Settings: map[string]string{"sub": "app.user_id"}, SchemaClaim: "schema"}}
	if err := env.store.CreateService(context.Background(), svc); err != nil {
		t.Fatalf("CreateService: %v", err)
	}
	_, key := env.createRoleWithKey(t, "member", true, []model.RoleAccess{accessRule("notes", "*", model.VerbAll)})
	return &identityEnv{testEnv: env, key: priv, apiKey: key, schema: schema, dsn: dsn}
}

func signIdentity(key ed25519.PrivateKey, claims map[string]any) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	signed := enc(map[string]any{"alg": "EdDSA"}) + "." + enc(claims)
	return signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(signed)))
}

func (e *identityEnv) as(user string) string {
	return signIdentity(e.key, map[string]any{"sub": user, "aud": "platform", "exp": time.Now().Add(time.Minute).Unix()})
}

func (e *identityEnv) call(t *testing.T, method, path, signed string, body any) (int, map[string]any) {
	t.Helper()
	headers := map[string]string{"X-API-Key": e.apiKey}
	if signed != "" {
		headers[model.IdentityHeader] = signed
	}
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = strings.NewReader(string(b))
	}
	rr := e.do(t, method, "/api/v1/notes"+path, reader, headers)
	out := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func column(resp map[string]any, name string) string {
	rows, _ := resp["resource"].([]any)
	out := []string{}
	for _, r := range rows {
		out = append(out, fmt.Sprint(r.(map[string]any)[name]))
	}
	return strings.Join(out, ",")
}

func TestIdentity_EachPersonSeesOnlyTheirRows(t *testing.T) {
	e := newIdentityEnv(t, true)
	for i := 0; i < 5; i++ { // alternating on one pooled connection: nothing carries over
		if code, resp := e.call(t, "GET", "/_table/notes?order=id", e.as("alice"), nil); code != http.StatusOK || column(resp, "owner") != "alice,alice" {
			t.Fatalf("alice: %d %v", code, resp)
		}
		if code, resp := e.call(t, "GET", "/_table/notes", e.as("bob"), nil); code != http.StatusOK || column(resp, "owner") != "bob" {
			t.Fatalf("bob: %d %v", code, resp)
		}
	}
	// Procedures see the identity too
	code, resp := e.call(t, "POST", "/_proc/whoami", e.as("alice"), map[string]any{})
	if code != http.StatusOK || !strings.Contains(fmt.Sprint(resp), "user_id:alice") {
		t.Fatalf("whoami as alice: %d %v", code, resp)
	}
}

func TestIdentity_RefusesMissingForgedExpiredAndForeignIdentities(t *testing.T) {
	e := newIdentityEnv(t, true)
	_, forger, _ := ed25519.GenerateKey(rand.Reader)
	cases := map[string]string{
		"missing":        "",
		"forged":         signIdentity(forger, map[string]any{"sub": "alice", "aud": "platform", "exp": time.Now().Add(time.Minute).Unix()}),
		"expired":        signIdentity(e.key, map[string]any{"sub": "alice", "aud": "platform", "exp": time.Now().Add(-time.Hour).Unix()}),
		"other audience": signIdentity(e.key, map[string]any{"sub": "alice", "aud": "elsewhere", "exp": time.Now().Add(time.Minute).Unix()}),
	}
	for name, signed := range cases {
		if code, _ := e.call(t, "GET", "/_table/notes", signed, nil); code != http.StatusUnauthorized {
			t.Errorf("%s identity: status %d, want 401", name, code)
		}
	}
}

func TestIdentity_OptionalIdentityLeavesOtherRequestsAsTheyWere(t *testing.T) {
	e := newIdentityEnv(t, false)
	// Without an identity the request runs as before (the connection's own role, which owns the table)
	if code, resp := e.call(t, "GET", "/_table/notes", "", nil); code != http.StatusOK || len(resp["resource"].([]any)) != 3 {
		t.Fatalf("without identity: %d %v", code, resp)
	}
	// ...and an earlier request's identity is not left on the pooled connection
	e.call(t, "GET", "/_table/notes", e.as("alice"), nil)
	code, resp := e.call(t, "POST", "/_proc/whoami", "", map[string]any{})
	if code != http.StatusOK || strings.Contains(fmt.Sprint(resp), "alice") {
		t.Fatalf("identity left on the connection: %d %v", code, resp)
	}
}

func TestIdentity_WritesFollowThePolicyAndFailuresKeepNothing(t *testing.T) {
	e := newIdentityEnv(t, true)
	alice := e.as("alice")
	if code, resp := e.call(t, "POST", "/_table/notes", alice, map[string]any{"resource": []any{map[string]any{"owner": "alice", "body": "a3"}}}); code != http.StatusCreated {
		t.Fatalf("own insert: %d %v", code, resp)
	}
	// Writing someone else's row is refused by the policy, and nothing of the request is kept
	if code, _ := e.call(t, "POST", "/_table/notes?rollback=true", alice, map[string]any{"resource": []any{
		map[string]any{"owner": "alice", "body": "a4"}, map[string]any{"owner": "bob", "body": "stolen"}}}); code < 400 {
		t.Fatalf("insert for bob: status %d, want a refusal", code)
	}
	// A "continue" batch keeps the records the policy allows, even after one fails
	code, resp := e.call(t, "POST", "/_table/notes?continue=true", alice, map[string]any{"resource": []any{
		map[string]any{"owner": "alice", "body": "a5"}, map[string]any{"owner": "bob", "body": "stolen"}, map[string]any{"owner": "alice", "body": "a6"}}})
	if meta, _ := resp["meta"].(map[string]any); code != http.StatusOK || meta["succeeded"] != float64(2) || meta["failed"] != float64(1) {
		t.Fatalf("continue batch: %d %v", code, resp)
	}
	if _, resp := e.call(t, "GET", "/_table/notes?order=id", alice, nil); column(resp, "body") != "a1,a2,a3,a5,a6" {
		t.Fatalf("alice's notes: %v", resp)
	}
	if _, resp := e.call(t, "GET", "/_table/notes", e.as("bob"), nil); column(resp, "owner") != "bob" {
		t.Fatalf("bob's notes: %v", resp)
	}
}

// The admin API refuses identity settings it cannot honour: on a service that is
// not PostgreSQL, or with keys or setting names PostgreSQL would not accept.
func TestIdentity_AdminAPIValidatesTheConfiguration(t *testing.T) {
	env := newRBACEnv(t)
	adminToken := env.adminToken(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	good := map[string]any{"public_keys": []string{base64.RawURLEncoding.EncodeToString(pub)}, "settings": map[string]string{"sub": "app.user_id"}}
	for name, identity := range map[string]any{
		"not postgres": good,
		"bad key":      map[string]any{"public_keys": []string{"short"}},
	} {
		rr := env.doAuth(t, "PUT", "/api/v1/system/service/mydb", jsonBody(t, map[string]any{"identity": identity}), adminToken)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "Invalid identity") {
			t.Errorf("%s: %d %s", name, rr.Code, rr.Body.String())
		}
	}
	// A refused change leaves the service as it was
	if svc, _ := env.store.GetServiceByName(context.Background(), "mydb"); svc.Identity != nil {
		t.Fatalf("identity stored despite the refusal: %+v", svc.Identity)
	}
}

// A version of the service's schema (as pgroll serves one during a migration: views over the tables, here renaming
// body to text) is chosen per request by the identity's schema claim; row-level security still applies through the
// views, procedures stay on the service's schema, and only existing versions of that schema are accepted.
func TestIdentity_SchemaClaimChoosesAVersionOfTheSchema(t *testing.T) {
	e := newIdentityEnv(t, true)
	admin, err := sqlx.Connect("pgx", e.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	v2 := e.schema + "_v2"
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA IF EXISTS ` + v2 + ` CASCADE`) })
	for _, s := range []string{
		`CREATE SCHEMA ` + v2,
		`CREATE VIEW ` + v2 + `.notes WITH (security_invoker = true) AS SELECT id, owner, body AS text FROM ` + e.schema + `.notes`,
		`GRANT USAGE ON SCHEMA ` + v2 + ` TO faucet_identity_member`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ` + v2 + `.notes TO faucet_identity_member`,
	} {
		if _, err := admin.Exec(s); err != nil {
			t.Fatalf("prepare version: %v\n%s", err, s)
		}
	}
	as := func(user, schema string) string {
		return signIdentity(e.key, map[string]any{"sub": user, "aud": "platform", "exp": time.Now().Add(time.Minute).Unix(), "schema": schema})
	}
	// The version's columns, and only alice's rows
	if code, resp := e.call(t, "GET", "/_table/notes?order=id", as("alice", v2), nil); code != http.StatusOK || column(resp, "text") != "a1,a2" {
		t.Fatalf("alice on v2: %d %v", code, resp)
	}
	// Written through the version, read back through the service's schema
	if code, resp := e.call(t, "POST", "/_table/notes", as("alice", v2), map[string]any{"resource": []any{map[string]any{"owner": "alice", "text": "a3"}}}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("insert on v2: %d %v", code, resp)
	}
	if code, resp := e.call(t, "GET", "/_table/notes?order=id", as("alice", e.schema), nil); code != http.StatusOK || column(resp, "body") != "a1,a2,a3" {
		t.Fatalf("alice on the schema: %d %v", code, resp)
	}
	// Procedures stay on the service's schema
	if code, resp := e.call(t, "POST", "/_proc/whoami", as("alice", v2), map[string]any{}); code != http.StatusOK || !strings.Contains(fmt.Sprint(resp), "user_id:alice") {
		t.Fatalf("whoami on v2: %d %v", code, resp)
	}
	// A version that does not exist, or another schema altogether, is refused
	if code, _ := e.call(t, "GET", "/_table/notes", as("alice", e.schema+"_v9"), nil); code != http.StatusConflict {
		t.Fatalf("missing version: %d", code)
	}
	if code, _ := e.call(t, "GET", "/_table/notes", as("alice", "pg_catalog"), nil); code != http.StatusUnauthorized {
		t.Fatalf("foreign schema: %d", code)
	}
}

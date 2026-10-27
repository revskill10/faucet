package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/faucetdb/faucet/internal/model"
)

func sign(t *testing.T, key ed25519.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signed := enc(header) + "." + enc(claims)
	return signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(signed)))
}

func keys(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, base64.RawURLEncoding.EncodeToString(pub)
}

func TestVerify(t *testing.T) {
	priv, pub := keys(t)
	other, _ := keys(t)
	now := time.Unix(1_800_000_000, 0)
	cfg := &model.IdentityConfig{PublicKeys: []string{pub}, Audience: "platform"}
	header := map[string]any{"alg": "EdDSA", "typ": "hbctx"}
	good := map[string]any{"sub": "user-1", "aud": "platform", "exp": float64(now.Unix() + 300)}

	claims, err := Verify(cfg, sign(t, priv, header, good), now)
	if err != nil || claims["sub"] != "user-1" {
		t.Fatalf("valid token: claims %v, err %v", claims, err)
	}
	// Several keys: any one of them may sign (rotation)
	_, spare := keys(t)
	if _, err := Verify(&model.IdentityConfig{PublicKeys: []string{spare, pub}, Audience: "platform"}, sign(t, priv, header, good), now); err != nil {
		t.Fatalf("second key: %v", err)
	}

	cases := map[string]string{
		"another key":    sign(t, other, header, good),
		"wrong audience": sign(t, priv, header, map[string]any{"sub": "u", "aud": "other", "exp": float64(now.Unix() + 300)}),
		"expired":        sign(t, priv, header, map[string]any{"sub": "u", "aud": "platform", "exp": float64(now.Unix() - 31)}),
		"no expiry":      sign(t, priv, header, map[string]any{"sub": "u", "aud": "platform"}),
		"not yet valid":  sign(t, priv, header, map[string]any{"sub": "u", "aud": "platform", "exp": float64(now.Unix() + 300), "nbf": float64(now.Unix() + 60)}),
		"other alg":      sign(t, priv, map[string]any{"alg": "none"}, good),
		"not a token":    "abc",
	}
	for name, token := range cases {
		if _, err := Verify(cfg, token, now); err != ErrInvalid {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	// Within the leeway, an expired token still passes
	if _, err := Verify(cfg, sign(t, priv, header, map[string]any{"aud": "platform", "exp": float64(now.Unix() - 10)}), now); err != nil {
		t.Errorf("within leeway: %v", err)
	}
	// An audience list is accepted when it contains the audience
	if _, err := Verify(cfg, sign(t, priv, header, map[string]any{"aud": []string{"x", "platform"}, "exp": float64(now.Unix() + 60)}), now); err != nil {
		t.Errorf("audience list: %v", err)
	}
	// No keys configured: nothing verifies
	if _, err := Verify(&model.IdentityConfig{}, sign(t, priv, header, good), now); err != ErrInvalid {
		t.Errorf("no keys: %v", err)
	}
}

func TestSettings(t *testing.T) {
	cfg := &model.IdentityConfig{Settings: map[string]string{"sub": "app.user_id", "companies": "app.companies", "missing": "app.missing"}}
	got, err := Settings(cfg, Claims{"sub": "user-1", "companies": []any{"acme"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []Setting{{"request.claims", `{"companies":["acme"],"sub":"user-1"}`}, {"app.companies", `["acme"]`}, {"app.missing", ""}, {"app.user_id", "user-1"}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("setting %d: got %v, want %v", i, got[i], want[i])
		}
	}
}

func TestValidate(t *testing.T) {
	_, pub := keys(t)
	ok := &model.IdentityConfig{PublicKeys: []string{pub}, Settings: map[string]string{"sub": "app.user_id"}}
	if err := Validate(ok, "postgres"); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if err := Validate(nil, "mysql"); err != nil {
		t.Fatalf("none: %v", err)
	}
	bad := map[string]*model.IdentityConfig{
		"not postgres":     ok,
		"no keys":          {},
		"bad key":          {PublicKeys: []string{"short"}},
		"setting no dot":   {PublicKeys: []string{pub}, Settings: map[string]string{"sub": "user_id"}},
		"reserved setting": {PublicKeys: []string{pub}, Settings: map[string]string{"sub": "request.claims"}},
		"leeway":           {PublicKeys: []string{pub}, LeewaySeconds: 3600},
	}
	for name, cfg := range bad {
		driver := "postgres"
		if name == "not postgres" {
			driver = "mysql"
		}
		if err := Validate(cfg, driver); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

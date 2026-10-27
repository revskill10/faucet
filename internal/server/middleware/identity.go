package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/faucetdb/faucet/internal/config"
	"github.com/faucetdb/faucet/internal/connector"
	"github.com/faucetdb/faucet/internal/identity"
)

// RequestIdentity returns an HTTP middleware that carries a request's signed
// identity into a PostgreSQL service configured for it (model.IdentityConfig).
// It must be mounted inside the "/{serviceName}" route group, after
// Authenticate and RequireAccess.
//
// With a valid token, every statement of the request runs in one transaction
// that first sets the token's claims (transaction-local) and switches to the
// configured role. The transaction commits only when the request succeeds
// (status below 400); the response is held until then, so a client never sees
// success for work that was not kept. Services without an identity
// configuration, and requests to them without a token (unless it is required),
// pass through unchanged.
func RequestIdentity(store *config.Store, registry *connector.Registry) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serviceName := chi.URLParam(r, "serviceName")
			svc, err := store.GetServiceByName(r.Context(), serviceName)
			if errors.Is(err, config.ErrNotFound) || (err == nil && svc.Identity == nil) {
				next.ServeHTTP(w, r)
				return
			}
			if err != nil {
				writeAuthError(w, http.StatusInternalServerError, "Authorization check failed", nil)
				return
			}
			cfg := svc.Identity
			token := strings.TrimSpace(r.Header.Get(identity.HeaderName(cfg)))
			principal := GetPrincipal(r.Context())
			if token == "" {
				if cfg.Required && (principal == nil || !principal.IsAdmin) {
					writeAuthError(w, http.StatusUnauthorized, "Identity required: provide "+identity.HeaderName(cfg), nil)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			if svc.Driver != "postgres" {
				writeAuthError(w, http.StatusBadRequest, "Per-request identity is supported for PostgreSQL services only", nil)
				return
			}
			claims, err := identity.Verify(cfg, token, time.Now())
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "Invalid identity", nil)
				return
			}
			settings, err := identity.Settings(cfg, claims)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "Invalid identity", nil)
				return
			}
			base := svc.Schema
			if base == "" {
				base = "public"
			}
			schema, err := identity.SchemaVersion(cfg, claims, base)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "Invalid identity", nil)
				return
			}
			conn, err := registry.Get(serviceName)
			if err != nil {
				// The handler reports why the service is unavailable
				next.ServeHTTP(w, r)
				return
			}
			tx, err := conn.BeginTx(r.Context(), nil)
			if err != nil {
				writeAuthError(w, http.StatusServiceUnavailable, "Failed to begin transaction", nil)
				return
			}
			defer func() { _ = tx.Rollback() }()
			for _, s := range settings {
				if _, err := tx.ExecContext(r.Context(), "SELECT set_config($1, $2, true)", s.Name, s.Value); err != nil {
					writeAuthError(w, http.StatusBadRequest, fmt.Sprintf("Identity setting %q could not be applied", s.Name), nil)
					return
				}
			}
			if cfg.Role != "" {
				if _, err := tx.ExecContext(r.Context(), "SET LOCAL ROLE "+conn.QuoteIdentifier(cfg.Role)); err != nil {
					writeAuthError(w, http.StatusInternalServerError, "Identity role could not be applied", nil)
					return
				}
			}

			ctx := connector.WithRequestTx(r.Context(), tx)
			if schema != "" {
				var exists bool
				if err := tx.GetContext(r.Context(), &exists, "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)", schema); err != nil || !exists {
					writeAuthError(w, http.StatusConflict, "Schema version not available: "+schema, nil)
					return
				}
				ctx = connector.WithSchema(ctx, schema)
			}

			held := &heldResponse{header: http.Header{}, status: http.StatusOK}
			next.ServeHTTP(held, r.WithContext(ctx))
			if held.status < 400 {
				if err := tx.Commit(); err != nil {
					writeAuthError(w, http.StatusConflict, "The request's changes could not be committed", nil)
					return
				}
			}
			held.writeTo(w)
		})
	}
}

// heldResponse keeps a handler's response until the request's transaction ends.
type heldResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
	wrote  bool
}

func (h *heldResponse) Header() http.Header { return h.header }

func (h *heldResponse) WriteHeader(status int) {
	if !h.wrote {
		h.status, h.wrote = status, true
	}
}

func (h *heldResponse) Write(b []byte) (int, error) {
	h.wrote = true
	return h.body.Write(b)
}

func (h *heldResponse) writeTo(w http.ResponseWriter) {
	for k, v := range h.header {
		w.Header()[k] = v
	}
	w.WriteHeader(h.status)
	_, _ = w.Write(h.body.Bytes())
}

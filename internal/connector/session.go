package connector

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// A request can carry its own transaction (a PostgreSQL service with a per-request
// identity, see model.IdentityConfig): every statement of the request then runs
// in it, after the identity's settings. Handlers and connectors ask for their
// executor through Executor, and open nested units of work with BeginScope.

type requestTxKey struct{}
type requestSchemaKey struct{}

// WithSchema has the request's table reads and writes use another schema of
// the service (a version of its schema, see model.IdentityConfig.SchemaClaim).
func WithSchema(ctx context.Context, schema string) context.Context {
	return context.WithValue(ctx, requestSchemaKey{}, schema)
}

// RequestSchema is the schema chosen for the request's tables, or "".
func RequestSchema(ctx context.Context) string {
	s, _ := ctx.Value(requestSchemaKey{}).(string)
	return s
}

// requestTx is the request's transaction and the savepoints opened in it.
type requestTx struct {
	tx         *sqlx.Tx
	savepoints int
}

// WithRequestTx attaches the request's transaction to its context.
func WithRequestTx(ctx context.Context, tx *sqlx.Tx) context.Context {
	return context.WithValue(ctx, requestTxKey{}, &requestTx{tx: tx})
}

// RequestTx is the request's transaction, or nil when it has none.
func RequestTx(ctx context.Context) *sqlx.Tx {
	if rt, ok := ctx.Value(requestTxKey{}).(*requestTx); ok {
		return rt.tx
	}
	return nil
}

// Executor runs the request's statements: its transaction when it has one,
// otherwise the connection pool.
func Executor(ctx context.Context, db *sqlx.DB) QueryExecutor {
	if tx := RequestTx(ctx); tx != nil {
		return tx
	}
	return db
}

// Scope is a unit of work that commits or rolls back as a whole: a transaction
// of its own, or a savepoint inside the request's transaction.
type Scope struct {
	Exec     QueryExecutor
	commit   func() error
	rollback func() error
	done     bool
}

// BeginScope opens a unit of work on the connector.
func BeginScope(ctx context.Context, conn Connector) (*Scope, error) {
	if rt, ok := ctx.Value(requestTxKey{}).(*requestTx); ok {
		rt.savepoints++
		name := fmt.Sprintf("faucet_scope_%d", rt.savepoints)
		if _, err := rt.tx.ExecContext(ctx, "SAVEPOINT "+name); err != nil {
			return nil, err
		}
		return &Scope{
			Exec:     rt.tx,
			commit:   func() error { _, err := rt.tx.ExecContext(ctx, "RELEASE SAVEPOINT "+name); return err },
			rollback: func() error { _, err := rt.tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT "+name); return err },
		}, nil
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &Scope{Exec: tx, commit: tx.Commit, rollback: tx.Rollback}, nil
}

// Commit ends the unit of work, keeping what it did.
func (s *Scope) Commit() error {
	if s.done {
		return nil
	}
	s.done = true
	return s.commit()
}

// Rollback ends the unit of work, undoing what it did; after Commit it does nothing.
func (s *Scope) Rollback() error {
	if s.done {
		return nil
	}
	s.done = true
	return s.rollback()
}

// Isolate runs one independent statement group (a record of a "continue" batch).
// Inside the request's transaction it gets a savepoint, so its failure does not
// abort the transaction for the records after it; otherwise it runs on exec.
func Isolate(ctx context.Context, conn Connector, exec QueryExecutor, fn func(QueryExecutor) error) error {
	if RequestTx(ctx) == nil {
		return fn(exec)
	}
	scope, err := BeginScope(ctx, conn)
	if err != nil {
		return err
	}
	if err := fn(scope.Exec); err != nil {
		_ = scope.Rollback()
		return err
	}
	return scope.Commit()
}

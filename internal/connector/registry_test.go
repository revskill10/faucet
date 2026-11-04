package connector

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/faucetdb/faucet/internal/model"
)

// mockConnector implements Connector for testing without a real database.
type mockConnector struct {
	connected    bool
	disconnected bool
	cfg          ConnectionConfig
}

func (m *mockConnector) Connect(cfg ConnectionConfig) error {
	if cfg.DSN == "fail" {
		return fmt.Errorf("mock connect failure")
	}
	m.connected = true
	m.cfg = cfg
	return nil
}
func (m *mockConnector) Disconnect() error {
	m.disconnected = true
	m.connected = false
	return nil
}
func (m *mockConnector) Ping(_ context.Context) error { return nil }
func (m *mockConnector) DB() *sqlx.DB                 { return nil }
func (m *mockConnector) BeginTx(_ context.Context, _ *sql.TxOptions) (*sqlx.Tx, error) {
	return nil, fmt.Errorf("mock: transactions not supported")
}
func (m *mockConnector) IntrospectSchema(_ context.Context) (*model.Schema, error) {
	return nil, nil
}
func (m *mockConnector) IntrospectTable(_ context.Context, _ string) (*model.TableSchema, error) {
	return nil, nil
}
func (m *mockConnector) GetTableNames(_ context.Context) ([]string, error) { return nil, nil }
func (m *mockConnector) GetStoredProcedures(_ context.Context) ([]model.StoredProcedure, error) {
	return nil, nil
}
func (m *mockConnector) BuildSelect(_ context.Context, _ SelectRequest) (string, []interface{}, error) {
	return "", nil, nil
}
func (m *mockConnector) BuildInsert(_ context.Context, _ InsertRequest) (string, []interface{}, error) {
	return "", nil, nil
}
func (m *mockConnector) BuildUpdate(_ context.Context, _ UpdateRequest) (string, []interface{}, error) {
	return "", nil, nil
}
func (m *mockConnector) BuildDelete(_ context.Context, _ DeleteRequest) (string, []interface{}, error) {
	return "", nil, nil
}
func (m *mockConnector) BuildCount(_ context.Context, _ CountRequest) (string, []interface{}, error) {
	return "", nil, nil
}
func (m *mockConnector) CreateTable(_ context.Context, _ model.TableSchema) error { return nil }
func (m *mockConnector) AlterTable(_ context.Context, _ string, _ []SchemaChange) error {
	return nil
}
func (m *mockConnector) DropTable(_ context.Context, _ string) error { return nil }
func (m *mockConnector) CallProcedure(_ context.Context, _ string, _ map[string]interface{}) ([]map[string]interface{}, error) {
	return nil, nil
}
func (m *mockConnector) DriverName() string                 { return "mock" }
func (m *mockConnector) QuoteIdentifier(name string) string { return `"` + name + `"` }
func (m *mockConnector) SupportsReturning() bool            { return false }
func (m *mockConnector) SupportsUpsert() bool               { return false }
func (m *mockConnector) ParameterPlaceholder(_ int) string  { return "?" }

// ---------------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------------

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry() returned nil")
	}
	if len(r.ListServices()) != 0 {
		t.Error("new registry should have no services")
	}
}

func TestRegisterDriver(t *testing.T) {
	r := NewRegistry()
	r.RegisterDriver("mock", func() Connector { return &mockConnector{} })

	if _, ok := r.factories["mock"]; !ok {
		t.Error("expected mock driver to be registered")
	}
}

func TestConnectAndGet(t *testing.T) {
	r := NewRegistry()
	r.RegisterDriver("mock", func() Connector { return &mockConnector{} })

	err := r.Connect("test-svc", ConnectionConfig{Driver: "mock", DSN: "test-dsn"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	conn, err := r.Get("test-svc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}

	mc := conn.(*mockConnector)
	if !mc.connected {
		t.Error("connector should be connected")
	}
	if mc.cfg.DSN != "test-dsn" {
		t.Errorf("expected DSN test-dsn, got %s", mc.cfg.DSN)
	}
}

func TestConnectUnsupportedDriver(t *testing.T) {
	r := NewRegistry()

	err := r.Connect("test-svc", ConnectionConfig{Driver: "unknown"})
	if err == nil {
		t.Fatal("expected error for unsupported driver")
	}
}

func TestConnectFailure(t *testing.T) {
	r := NewRegistry()
	r.RegisterDriver("mock", func() Connector { return &mockConnector{} })

	err := r.Connect("test-svc", ConnectionConfig{Driver: "mock", DSN: "fail"})
	if err == nil {
		t.Fatal("expected error for connection failure")
	}
}

// retireNow makes replaced connectors close immediately for the test.
func retireNow(t *testing.T) {
	t.Helper()
	orig := retireDelay
	retireDelay = 0
	t.Cleanup(func() { retireDelay = orig })
}

func TestConnectReplacesExisting(t *testing.T) {
	retireNow(t)
	r := NewRegistry()
	var first *mockConnector
	r.RegisterDriver("mock", func() Connector {
		mc := &mockConnector{}
		if first == nil {
			first = mc
		}
		return mc
	})

	r.Connect("svc", ConnectionConfig{Driver: "mock", DSN: "dsn1"})
	r.Connect("svc", ConnectionConfig{Driver: "mock", DSN: "dsn2"})

	if !first.disconnected {
		t.Error("first connector should have been disconnected on replacement")
	}

	conn, _ := r.Get("svc")
	mc := conn.(*mockConnector)
	if mc.cfg.DSN != "dsn2" {
		t.Errorf("expected DSN dsn2 after replacement, got %s", mc.cfg.DSN)
	}
}

func TestGetNotFound(t *testing.T) {
	r := NewRegistry()

	_, err := r.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent service")
	}
}

func TestDisconnect(t *testing.T) {
	r := NewRegistry()
	r.RegisterDriver("mock", func() Connector { return &mockConnector{} })

	r.Connect("svc", ConnectionConfig{Driver: "mock", DSN: "dsn"})
	err := r.Disconnect("svc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = r.Get("svc")
	if err == nil {
		t.Error("expected error after disconnect")
	}
}

func TestDisconnectNotFound(t *testing.T) {
	r := NewRegistry()

	err := r.Disconnect("nonexistent")
	if err == nil {
		t.Fatal("expected error for disconnecting nonexistent service")
	}
}

func TestCloseAll(t *testing.T) {
	r := NewRegistry()
	r.RegisterDriver("mock", func() Connector { return &mockConnector{} })

	r.Connect("svc1", ConnectionConfig{Driver: "mock", DSN: "dsn1"})
	r.Connect("svc2", ConnectionConfig{Driver: "mock", DSN: "dsn2"})

	r.CloseAll()

	if len(r.ListServices()) != 0 {
		t.Error("expected no services after CloseAll")
	}
}

func TestListServices(t *testing.T) {
	r := NewRegistry()
	r.RegisterDriver("mock", func() Connector { return &mockConnector{} })

	r.Connect("alpha", ConnectionConfig{Driver: "mock", DSN: "dsn"})
	r.Connect("beta", ConnectionConfig{Driver: "mock", DSN: "dsn"})

	services := r.ListServices()
	sort.Strings(services)

	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}
	if services[0] != "alpha" || services[1] != "beta" {
		t.Errorf("expected [alpha beta], got %v", services)
	}
}

func TestConnectFailureDropsExistingConnection(t *testing.T) {
	retireNow(t)
	r := NewRegistry()
	var first *mockConnector
	r.RegisterDriver("mock", func() Connector {
		mc := &mockConnector{}
		if first == nil {
			first = mc
		}
		return mc
	})

	if err := r.Connect("svc", ConnectionConfig{Driver: "mock", DSN: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Connect("svc", ConnectionConfig{Driver: "mock", DSN: "fail"}); err == nil {
		t.Fatal("expected connect failure")
	}

	if !first.disconnected {
		t.Error("old connector should be closed when reconnecting fails")
	}
	_, err := r.Get("svc")
	if !errors.Is(err, ErrServiceNotConnected) {
		t.Errorf("Get error = %v, want ErrServiceNotConnected", err)
	}
	st := r.State("svc")
	if st.Connected || st.Paused || st.Error == "" {
		t.Errorf("State = %+v, want failed with an error", st)
	}
	if _, ok := r.Failures()["svc"]; !ok {
		t.Error("Failures() should list svc")
	}

	// A later successful connect clears the failure.
	if err := r.Connect("svc", ConnectionConfig{Driver: "mock", DSN: "ok"}); err != nil {
		t.Fatal(err)
	}
	if st := r.State("svc"); !st.Connected || st.Error != "" {
		t.Errorf("State after reconnect = %+v", st)
	}
}

func TestPauseAndGetErrors(t *testing.T) {
	r := NewRegistry()
	mc := &mockConnector{}
	r.RegisterDriver("mock", func() Connector { return mc })
	if err := r.Connect("svc", ConnectionConfig{Driver: "mock", DSN: "ok"}); err != nil {
		t.Fatal(err)
	}

	r.Pause("svc")
	if !mc.disconnected {
		t.Error("Pause should close the connection")
	}
	if _, err := r.Get("svc"); !errors.Is(err, ErrServicePaused) {
		t.Errorf("Get error = %v, want ErrServicePaused", err)
	}
	if st := r.State("svc"); !st.Paused || st.Connected {
		t.Errorf("State = %+v, want paused", st)
	}

	// Deleting the service forgets it entirely.
	_ = r.Disconnect("svc")
	if _, err := r.Get("svc"); !errors.Is(err, ErrServiceNotFound) {
		t.Errorf("Get error after Disconnect = %v, want ErrServiceNotFound", err)
	}
}

// blockingConnector blocks in Connect until release is closed.
type blockingConnector struct {
	mockConnector
	release chan struct{}
}

func (b *blockingConnector) Connect(cfg ConnectionConfig) error {
	<-b.release
	return b.mockConnector.Connect(cfg)
}

func TestSlowConnectDoesNotUndoPauseOrDelete(t *testing.T) {
	for _, tc := range []struct {
		name    string
		act     func(r *Registry)
		wantErr error
	}{
		{"pause", func(r *Registry) { r.Pause("svc") }, ErrServicePaused},
		{"delete", func(r *Registry) { _ = r.Disconnect("svc") }, ErrServiceNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry()
			bc := &blockingConnector{release: make(chan struct{})}
			r.RegisterDriver("slow", func() Connector { return bc })

			done := make(chan error, 1)
			go func() { done <- r.Connect("svc", ConnectionConfig{Driver: "slow", DSN: "ok"}) }()
			// Wait until Connect has registered its generation.
			for {
				r.mu.RLock()
				g := r.gen["svc"]
				r.mu.RUnlock()
				if g > 0 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			tc.act(r)
			close(bc.release)
			<-done

			if _, err := r.Get("svc"); !errors.Is(err, tc.wantErr) {
				t.Errorf("Get error = %v, want %v", err, tc.wantErr)
			}
			if !bc.disconnected {
				t.Error("superseded connection should be closed")
			}
			if len(r.Failures()) != 0 {
				t.Errorf("Failures() = %v, want none", r.Failures())
			}
		})
	}
}

func TestCloseAllClosesRetiringConnections(t *testing.T) {
	r := NewRegistry()
	var conns []*mockConnector
	r.RegisterDriver("mock", func() Connector {
		mc := &mockConnector{}
		conns = append(conns, mc)
		return mc
	})
	_ = r.Connect("svc", ConnectionConfig{Driver: "mock", DSN: "1"})
	_ = r.Connect("svc", ConnectionConfig{Driver: "mock", DSN: "2"})
	if conns[0].disconnected {
		t.Fatal("replaced connection should stay open during the retire delay")
	}
	r.CloseAll()
	if !conns[0].disconnected || !conns[1].disconnected {
		t.Error("CloseAll should close active and retiring connections")
	}
}

// flakyConnector refuses its first failures connects (a database still starting), then connects.
type flakyConnector struct {
	mockConnector
	attempts *atomic.Int64
	failures int
}

func (f *flakyConnector) Connect(cfg ConnectionConfig) error {
	n := f.attempts.Add(1)
	if n <= int64(f.failures) {
		return fmt.Errorf("connection refused (attempt %d)", n)
	}
	return f.mockConnector.Connect(cfg)
}

// fastRetries makes ConnectRetrying try again within milliseconds for the test.
func fastRetries(t *testing.T) {
	t.Helper()
	first, max := reconnectFirst, reconnectMax
	reconnectFirst, reconnectMax = 5*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { reconnectFirst, reconnectMax = first, max })
}

// eventually waits up to a second for check to hold.
func eventually(t *testing.T, what string, check func() bool) {
	t.Helper()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if check() {
			return
		}
	}
	t.Fatalf("not within a second: %s", what)
}

// A database woken together with Faucet refuses connections while it starts: the service connects once it accepts them,
// with no edit (it stayed unconnected until one before, answering 503 to every request).
func TestConnectRetryingConnectsOnceTheDatabaseAccepts(t *testing.T) {
	fastRetries(t)
	var attempts atomic.Int64
	r := NewRegistry()
	r.RegisterDriver("mock", func() Connector { return &flakyConnector{attempts: &attempts, failures: 3} })

	if err := r.ConnectRetrying("svc", ConnectionConfig{Driver: "mock", DSN: "ok"}); err == nil {
		t.Fatal("the first attempt should fail: the database is still starting")
	}
	if _, err := r.Get("svc"); !errors.Is(err, ErrServiceNotConnected) {
		t.Fatalf("until it connects the service is not connected, got %v", err)
	}
	eventually(t, "the service connected", func() bool { _, err := r.Get("svc"); return err == nil })
	if attempts.Load() != 4 {
		t.Fatalf("connected on the fourth attempt, got %d attempts", attempts.Load())
	}
	// Connected: no further attempts
	time.Sleep(50 * time.Millisecond)
	if attempts.Load() != 4 {
		t.Fatalf("retries continued after connecting: %d attempts", attempts.Load())
	}
}

// Another change supersedes the retries: an operator's pause made while they run is never undone by them.
func TestConnectRetryingStopsWhenSuperseded(t *testing.T) {
	fastRetries(t)
	var attempts atomic.Int64
	r := NewRegistry()
	r.RegisterDriver("mock", func() Connector { return &flakyConnector{attempts: &attempts, failures: 1_000_000} })

	_ = r.ConnectRetrying("svc", ConnectionConfig{Driver: "mock", DSN: "ok"})
	eventually(t, "a retry ran", func() bool { return attempts.Load() >= 2 })
	r.Pause("svc")
	seen := attempts.Load()
	time.Sleep(60 * time.Millisecond)
	if attempts.Load() > seen+1 { // one retry may have been under way when the pause landed
		t.Fatalf("retries continued after a pause: %d attempts, %d when paused", attempts.Load(), seen)
	}
	if !r.State("svc").Paused {
		t.Fatal("the pause was undone by a retry")
	}
}

// After CloseAll (Faucet stopping) nothing reconnects.
func TestConnectRetryingStopsWhenClosed(t *testing.T) {
	fastRetries(t)
	var attempts atomic.Int64
	r := NewRegistry()
	r.RegisterDriver("mock", func() Connector { return &flakyConnector{attempts: &attempts, failures: 1_000_000} })

	_ = r.ConnectRetrying("svc", ConnectionConfig{Driver: "mock", DSN: "ok"})
	eventually(t, "a retry ran", func() bool { return attempts.Load() >= 2 })
	r.CloseAll()
	seen := attempts.Load()
	time.Sleep(60 * time.Millisecond)
	if attempts.Load() > seen+1 {
		t.Fatalf("retries continued after CloseAll: %d attempts, %d when closed", attempts.Load(), seen)
	}
}

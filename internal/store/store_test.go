package store

import (
	"testing"

	"github.com/srmta/srmta/internal/config"
)

func TestNewDatabase_Postgres(t *testing.T) {
	cfg := config.DatabaseConfig{
		Driver: "postgres",
		Host:   "localhost",
		Port:   5432,
		User:   "srmta",
		DBName: "srmta",
	}

	db, err := NewDatabase(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer db.Close()

	if db.Driver() != "postgres" {
		t.Errorf("expected driver=postgres, got %s", db.Driver())
	}
}

func TestNewDatabase_PostgresDefault(t *testing.T) {
	// Empty driver should default to postgres
	cfg := config.DatabaseConfig{
		Driver: "",
		Host:   "localhost",
		Port:   5432,
		User:   "srmta",
		DBName: "srmta",
	}

	db, err := NewDatabase(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer db.Close()

	if db.Driver() != "postgres" {
		t.Errorf("expected driver=postgres, got %s", db.Driver())
	}
}

func TestNewDatabase_MySQL(t *testing.T) {
	cfg := config.DatabaseConfig{
		Driver: "mysql",
		Host:   "localhost",
		Port:   3306,
		User:   "srmta",
		DBName: "srmta",
	}

	db, err := NewDatabase(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer db.Close()

	if db.Driver() != "mysql" {
		t.Errorf("expected driver=mysql, got %s", db.Driver())
	}
}

func TestNewDatabase_UnsupportedDriver(t *testing.T) {
	cfg := config.DatabaseConfig{
		Driver: "sqlite",
	}

	_, err := NewDatabase(cfg)
	if err == nil {
		t.Fatal("expected error for unsupported driver")
	}
}

func TestPostgresDSN(t *testing.T) {
	cfg := config.DatabaseConfig{
		Driver:   "postgres",
		Host:     "db.example.com",
		Port:     5432,
		User:     "admin",
		Password: "secret",
		DBName:   "maildb",
		SSLMode:  "require",
	}

	dsn := cfg.DSN()
	expected := "host=db.example.com port=5432 user=admin password=secret dbname=maildb sslmode=require"
	if dsn != expected {
		t.Errorf("PostgreSQL DSN mismatch:\n  got:  %s\n  want: %s", dsn, expected)
	}
}

func TestMySQLDSN(t *testing.T) {
	cfg := config.DatabaseConfig{
		Driver:   "mysql",
		Host:     "db.example.com",
		Port:     3306,
		User:     "admin",
		Password: "secret",
		DBName:   "maildb",
		Charset:  "utf8mb4",
	}

	dsn := cfg.DSN()
	if dsn == "" {
		t.Fatal("MySQL DSN should not be empty")
	}
	// Should contain TCP connection format
	if !containsStr(dsn, "tcp(db.example.com:3306)") {
		t.Errorf("MySQL DSN should contain tcp connection: %s", dsn)
	}
	if !containsStr(dsn, "charset=utf8mb4") {
		t.Errorf("MySQL DSN should contain charset: %s", dsn)
	}
	if !containsStr(dsn, "parseTime=True") {
		t.Errorf("MySQL DSN should contain parseTime: %s", dsn)
	}
}

func TestMySQLDSN_DefaultCharset(t *testing.T) {
	cfg := config.DatabaseConfig{
		Driver: "mysql",
		Host:   "localhost",
		Port:   3306,
		User:   "root",
		DBName: "test",
	}

	dsn := cfg.DSN()
	if !containsStr(dsn, "charset=utf8mb4") {
		t.Errorf("MySQL DSN should default to utf8mb4 charset: %s", dsn)
	}
}

func TestMySQLDSN_WithTLS(t *testing.T) {
	cfg := config.DatabaseConfig{
		Driver:   "mysql",
		Host:     "db.example.com",
		Port:     3306,
		User:     "admin",
		Password: "secret",
		DBName:   "maildb",
		SSLMode:  "true",
	}

	dsn := cfg.DSN()
	if !containsStr(dsn, "tls=true") {
		t.Errorf("MySQL DSN should contain TLS param: %s", dsn)
	}
}

func TestPostgresDSN_DefaultSSLMode(t *testing.T) {
	cfg := config.DatabaseConfig{
		Driver: "postgres",
		Host:   "localhost",
		Port:   5432,
		User:   "srmta",
		DBName: "srmta",
		// SSLMode is empty
	}

	dsn := cfg.DSN()
	if !containsStr(dsn, "sslmode=prefer") {
		t.Errorf("PostgreSQL DSN should default to sslmode=prefer: %s", dsn)
	}
}

func TestDatabaseInterface_PostgresStore(t *testing.T) {
	var db Database
	store, _ := NewPostgresStore(config.DatabaseConfig{})
	db = store // Verify PostgresStore implements Database
	_ = db
}

func TestDatabaseInterface_MySQLStore(t *testing.T) {
	var db Database
	store, _ := NewMySQLStore(config.DatabaseConfig{})
	db = store // Verify MySQLStore implements Database
	_ = db
}

func TestRecordEvent_DoesNotPanic(t *testing.T) {
	pg, _ := NewPostgresStore(config.DatabaseConfig{})
	defer pg.Close()

	event := &DeliveryEvent{
		MessageID: "test-123",
		Sender:    "sender@example.com",
		Recipient: "rcpt@example.com",
		Status:    "delivered",
	}

	// Should not panic
	pg.RecordEvent(event)
}

func TestRecordEvent_MySQL_DoesNotPanic(t *testing.T) {
	my, _ := NewMySQLStore(config.DatabaseConfig{})
	defer my.Close()

	event := &DeliveryEvent{
		MessageID: "test-456",
		Sender:    "sender@example.com",
		Recipient: "rcpt@example.com",
		Status:    "delivered",
	}

	// Should not panic
	my.RecordEvent(event)
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

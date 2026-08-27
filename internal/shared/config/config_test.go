package config

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/jackc/pgx/v5"
)

func TestPgxPoolConfigRejectsRDSIAMWithoutTLS(t *testing.T) {
	// sslmode=disable is the silent-downgrade case: the token would go over the
	// wire in clear and the server would reject it with an opaque auth error.
	_, err := PgxPoolConfig("postgres://u@h:5432/d?sslmode=disable", AuthRDSIAM)
	if err == nil || !strings.Contains(err.Error(), "requires TLS") {
		t.Fatalf("want a TLS refusal, got %v", err)
	}
}

func TestPgxPoolConfigRejectsUnknownAuthMode(t *testing.T) {
	if _, err := PgxPoolConfig("postgres://u@h:5432/d", "iam"); err == nil {
		t.Fatal("an unknown DB_AUTH must not fall through to password auth")
	}
}

func TestPgxPoolConfigAcceptsRDSIAMWithTLS(t *testing.T) {
	cfg, err := PgxPoolConfig("postgres://u@h:5432/d?sslmode=require", AuthRDSIAM)
	if err != nil {
		t.Fatalf("PgxPoolConfig: %v", err)
	}
	if cfg.BeforeConnect == nil {
		t.Fatal("rds-iam must install a BeforeConnect hook")
	}
}

func TestRDSIAMBeforeConnectMintsPerConnection(t *testing.T) {
	loads, signs := 0, 0
	hook := rdsIAMBeforeConnect(
		func(context.Context, string, string, string, aws.CredentialsProvider) (string, error) {
			signs++
			return "token", nil
		},
		func(context.Context) (aws.Config, error) { loads++; return aws.Config{Region: "ap-northeast-1"}, nil },
	)
	for i := 0; i < 3; i++ {
		cc := &pgx.ConnConfig{}
		cc.Host, cc.Port, cc.User = "h", 5432, "dns-delegate"
		if err := hook(context.Background(), cc); err != nil {
			t.Fatalf("hook: %v", err)
		}
		if cc.Password != "token" {
			t.Fatalf("password not replaced: %q", cc.Password)
		}
	}
	if loads != 1 {
		t.Fatalf("aws config must load once, loaded %d", loads)
	}
	if signs != 3 {
		t.Fatalf("a token must be minted per connection, minted %d", signs)
	}
}

func TestRDSIAMBeforeConnectSurfacesLoadFailure(t *testing.T) {
	want := errors.New("no credentials")
	hook := rdsIAMBeforeConnect(
		func(context.Context, string, string, string, aws.CredentialsProvider) (string, error) {
			t.Fatal("must not sign when the config failed to load")
			return "", nil
		},
		func(context.Context) (aws.Config, error) { return aws.Config{}, want },
	)
	cc := &pgx.ConnConfig{}
	if err := hook(context.Background(), cc); !errors.Is(err, want) {
		t.Fatalf("want the load error, got %v", err)
	}
}

package bridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luminariadev/raksa/internal/schema"
)

func TestSIEMClientHealthAndIngest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		if r.URL.Path == "/api/v1/ingest" {
			if got := r.Header.Get("Authorization"); got != "Bearer tok-123" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var rep schema.SuiteReport
			if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"ingested":1,"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := NewClient("ftp://bad.example", "", time.Second); err == nil {
		t.Fatal("expected unsupported scheme error")
	}

	client, err := NewClient(srv.URL, "tok-123", 2*time.Second)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	res, err := client.IngestReport(context.Background(), schema.SuiteReport{SchemaVersion: "1.0", Tool: "raksa"})
	if err != nil || res["status"] != "ok" {
		t.Fatalf("IngestReport: res=%v err=%v", res, err)
	}
}

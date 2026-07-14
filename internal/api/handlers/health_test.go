package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestHealthHandler(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := HealthHandler(c)
	if err != nil {
		t.Fatalf("HealthHandler returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if contentType := rec.Header().Get(echo.HeaderContentType); !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("expected content type to start with %q, got %q", "application/json", contentType)
	}

	expected := `{"status":"ok","service":"emc-auth-server"}`
	if got := strings.TrimSpace(rec.Body.String()); got != expected {
		t.Fatalf("unexpected body:\nexpected: %s\ngot: %s", expected, got)
	}
}

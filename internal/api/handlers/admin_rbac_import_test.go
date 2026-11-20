package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func bindRBAC(t *testing.T, body string) error {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	c := e.NewContext(req, httptest.NewRecorder())
	_, err := bindRBACImportDocument(c)
	return err
}

func TestBindRBACImportDocument_AcceptsDocumentWithTrailingWhitespace(t *testing.T) {
	if err := bindRBAC(t, `{"permissions":[{"name":"a:b"}]}`+"\n  \n"); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestBindRBACImportDocument_RejectsTrailingData(t *testing.T) {
	for name, body := range map[string]string{
		"stray bracket":   `{"permissions":[]}]`,
		"second document": `{"permissions":[]}{"roles":[]}`,
		"trailing text":   `{"permissions":[]} junk`,
	} {
		t.Run(name, func(t *testing.T) {
			err := bindRBAC(t, body)
			if err == nil || errors.Is(err, errRBACBodyTooLarge) {
				t.Fatalf("err = %v, want a trailing-data error", err)
			}
		})
	}
}

func TestBindRBACImportDocument_RejectsUnknownField(t *testing.T) {
	if err := bindRBAC(t, `{"permissionz":[]}`); err == nil {
		t.Fatal("a typo'd key must fail the upload")
	}
}

// A valid document followed by padding up to the limit and then more content
// used to be accepted: LimitReader turned the cut-off into EOF.
func TestBindRBACImportDocument_OversizedBodyIsRejectedNotTruncated(t *testing.T) {
	pad := strings.Repeat(" ", maxRBACImportBodyBytes)
	err := bindRBAC(t, `{"permissions":[]}`+pad+`{"roles":[]}`)
	if !errors.Is(err, errRBACBodyTooLarge) {
		t.Fatalf("err = %v, want errRBACBodyTooLarge", err)
	}
}

func TestBindRBACImportDocument_BodyExactlyAtLimitIsAccepted(t *testing.T) {
	doc := `{"permissions":[]}`
	body := doc + strings.Repeat(" ", maxRBACImportBodyBytes-len(doc))
	if err := bindRBAC(t, body); err != nil {
		t.Fatalf("err = %v", err)
	}
}

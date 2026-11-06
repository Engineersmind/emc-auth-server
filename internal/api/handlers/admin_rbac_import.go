package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/audit"
)

// maxRBACImportBodyBytes bounds an RBAC import upload before it is parsed, for
// the reason maxImportBodyBytes does for users: the row cap in the service is no
// protection against a body that is decoded before the service sees a row.
// 2MiB holds maxRBACImportRows of realistic names and descriptions.
const maxRBACImportBodyBytes = 2 << 20

// errRBACBodyTooLarge is returned when an upload exceeds maxRBACImportBodyBytes.
var errRBACBodyTooLarge = errors.New("import file is larger than 2 MiB")

// bindRBACImportDocument reads and decodes a bounded RBAC import payload.
//
// The body is read up to the limit plus one byte, and anything longer is
// rejected outright. io.LimitReader alone would turn the cut-off into a clean
// EOF, so a valid document followed by padding and a second document would be
// accepted with the rest silently dropped.
//
// Unknown fields are refused so that a typo'd key ("permissionz") fails the
// upload instead of importing a file with its permissions dropped. Trailing data
// is refused by requiring end of input after the document: Decoder.More only
// reports whether an array or object has another element, so it does not see a
// stray "]" or a second document after a top-level value.
func bindRBACImportDocument(c echo.Context) (admin.RBACImportDocument, error) {
	var doc admin.RBACImportDocument
	body, err := io.ReadAll(io.LimitReader(c.Request().Body, maxRBACImportBodyBytes+1))
	if err != nil {
		return doc, err
	}
	if len(body) > maxRBACImportBodyBytes {
		return doc, errRBACBodyTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return doc, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return doc, errors.New("unexpected data after the JSON document")
	}
	return doc, nil
}

// ValidateRBACImport handles
// POST /api/v1/tenants/:tid/applications/:appID/rbac/import/validate.
//
// @Summary      Validate an application RBAC import (dry run)
// @Description  Checks a document of permissions and roles against the application's current state and writes nothing. Returns a per-row report: what would be created, updated or skipped, and every rejected row with its reason. Roles reference permissions by name. Requires permissions:write and roles:write for the application, because the report discloses which names already exist.
// @Tags         admin-rbac
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        tid   path      string                   true  "Tenant ID"
// @Param        appID path      string                   true  "Application ID"
// @Param        body  body      admin.RBACImportDocument true  "Permissions and roles"
// @Success      200   {object}  admin.RBACImportResult
// @Failure      400   {object}  map[string]string
// @Failure      413   {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/applications/{appID}/rbac/import/validate [post]
func (h *AdminHandler) ValidateRBACImport(c echo.Context) error {
	tenantID, appScope, claims, ok := h.importScope(c)
	if !ok {
		return nil
	}
	if appScope == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "application id is required"})
	}
	doc, err := bindRBACImportDocument(c)
	if err != nil {
		if errors.Is(err, errRBACBodyTooLarge) {
			return c.JSON(http.StatusRequestEntityTooLarge, APIError{Error: "import_too_large", Message: err.Error()})
		}
		return c.JSON(http.StatusBadRequest, APIError{Error: "import_invalid", Message: "That import file couldn't be read: " + err.Error()})
	}

	res, err := h.svc.ValidateRBACImport(c.Request().Context(), tenantID, *appScope, doc)
	if err != nil {
		if errors.Is(err, admin.ErrRBACImportTooLarge) {
			return c.JSON(http.StatusRequestEntityTooLarge, APIError{Error: "import_too_large", Message: err.Error()})
		}
		h.logger.Error().Err(err).Msg("admin: rbac import validation failed")
		return fail(c, http.StatusInternalServerError, "import_failed")
	}

	h.auditAdminTenantMeta(c, claims, &tenantID, audit.ActionAdminRBACImportValidated, "application", "", appScope,
		map[string]any{"rejected": res.Rejected, "mode": res.Mode,
			"permissions_to_create": res.PermissionsCreated, "roles_to_create": res.RolesCreated, "roles_to_update": res.RolesUpdated})
	return c.JSON(http.StatusOK, res)
}

// CommitRBACImport handles
// POST /api/v1/tenants/:tid/applications/:appID/rbac/import.
//
// All-or-nothing: one transaction, one rate-limit hit, one audit event. If any
// row is rejected nothing is written and the response is 422 with the same
// per-row report the validate endpoint returns. Safe to re-run: existing names
// are matched and skipped.
//
// @Summary      Import an application's permissions and roles
// @Description  Creates permissions and roles and maps them, in one transaction: it fully succeeds or writes nothing. Roles reference permissions by name. mode "merge" (default) adds the listed permissions to each role and keeps existing ones; "replace" makes the list complete. Re-running is a no-op for anything already present. Requires permissions:write and roles:write for the application.
// @Tags         admin-rbac
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        tid   path      string                   true  "Tenant ID"
// @Param        appID path      string                   true  "Application ID"
// @Param        body  body      admin.RBACImportDocument true  "Permissions and roles"
// @Success      200   {object}  admin.RBACImportResult
// @Failure      400   {object}  map[string]string
// @Failure      409   {object}  map[string]string  "A name was created concurrently; nothing was written, retry"
// @Failure      413   {object}  map[string]string
// @Failure      422   {object}  admin.RBACImportResult  "Rows rejected; nothing was written"
// @Router       /api/v1/tenants/{tid}/applications/{appID}/rbac/import [post]
func (h *AdminHandler) CommitRBACImport(c echo.Context) error {
	tenantID, appScope, claims, ok := h.importScope(c)
	if !ok {
		return nil
	}
	if appScope == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "application id is required"})
	}
	doc, err := bindRBACImportDocument(c)
	if err != nil {
		if errors.Is(err, errRBACBodyTooLarge) {
			return c.JSON(http.StatusRequestEntityTooLarge, APIError{Error: "import_too_large", Message: err.Error()})
		}
		return c.JSON(http.StatusBadRequest, APIError{Error: "import_invalid", Message: "That import file couldn't be read: " + err.Error()})
	}

	res, err := h.svc.CommitRBACImport(c.Request().Context(), tenantID, *appScope, doc)
	if err != nil {
		switch {
		case errors.Is(err, admin.ErrRBACImportTooLarge):
			return c.JSON(http.StatusRequestEntityTooLarge, APIError{Error: "import_too_large", Message: err.Error()})
		case errors.Is(err, admin.ErrRBACImportRejected):
			return c.JSON(http.StatusUnprocessableEntity, res)
		case errors.Is(err, admin.ErrAlreadyExists):
			return c.JSON(http.StatusConflict, APIError{Error: "import_conflict",
				Message: "A permission or role with one of these names was created while the import ran. Nothing was written; run it again."})
		}
		h.logger.Error().Err(err).Msg("admin: rbac import failed")
		return fail(c, http.StatusInternalServerError, "import_failed")
	}

	h.auditAdminTenantMeta(c, claims, &tenantID, audit.ActionAdminRBACImported, "application", "", appScope,
		map[string]any{"mode": res.Mode,
			"permissions_created": res.PermissionsCreated, "roles_created": res.RolesCreated,
			"roles_updated": res.RolesUpdated, "skipped": res.PermissionsSkipped + res.RolesSkipped})
	return c.JSON(http.StatusOK, res)
}

// ExportRBAC handles
// GET /api/v1/tenants/:tid/applications/:appID/rbac/export.
//
// Returns the application's permissions and roles in the shape the import takes,
// so the file can be restored or copied to another application. JSON (default)
// is lossless; format=csv gives the permission matrix for a spreadsheet. System
// roles are omitted because the importer refuses to change them.
//
// The export is complete, not truncated. An application with more rows than one
// import accepts therefore yields a file that must be split before it can be
// imported; the response says so in X-RBAC-Export-Exceeds-Import-Limit.
//
// @Summary      Export an application's permissions and roles
// @Description  Returns permissions and roles in the import document shape. format=json (default) or format=csv. The export is complete: if it has more rows than one import accepts (2000 permissions + roles), the response carries X-RBAC-Export-Exceeds-Import-Limit and the file must be split before it is imported. Requires permissions:read and roles:read for the application.
// @Tags         admin-rbac
// @Produce      json
// @Produce      text/csv
// @Security     BearerAuth
// @Param        tid    path   string true  "Tenant ID"
// @Param        appID  path   string true  "Application ID"
// @Param        format query  string false "json (default) or csv"
// @Success      200    {object}  admin.RBACImportDocument
// @Failure      422    {object}  map[string]string  "CSV cannot represent a role name; use JSON"
// @Router       /api/v1/tenants/{tid}/applications/{appID}/rbac/export [get]
func (h *AdminHandler) ExportRBAC(c echo.Context) error {
	tenantID, appScope, claims, ok := h.importScope(c)
	if !ok {
		return nil
	}
	if appScope == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "application id is required"})
	}

	// Unlike the user export this is built in memory first, so a failure is still
	// a status code rather than a truncated download. The row cap makes that safe.
	doc, err := h.svc.ExportRBAC(c.Request().Context(), tenantID, *appScope)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: rbac export failed")
		return fail(c, http.StatusInternalServerError, "export_failed")
	}

	if doc.ExceedsImportLimit() {
		c.Response().Header().Set("X-RBAC-Export-Exceeds-Import-Limit", "true")
	}

	format := strings.ToLower(c.QueryParam("format"))
	if format != "" && format != "json" && format != "csv" {
		return c.JSON(http.StatusBadRequest, APIError{Error: "invalid_format", Message: "format must be json or csv"})
	}

	h.auditAdminTenantMeta(c, claims, &tenantID, audit.ActionAdminRBACExported, "application", "", appScope,
		map[string]any{"format": format, "permissions": len(doc.Permissions), "roles": len(doc.Roles)})

	if format == "csv" {
		var buf bytes.Buffer
		if err := admin.WriteRBACCSV(doc, &buf); err != nil {
			if errors.Is(err, admin.ErrRBACCSVUnsupported) {
				return c.JSON(http.StatusUnprocessableEntity, APIError{Error: "csv_unsupported", Message: err.Error()})
			}
			h.logger.Error().Err(err).Msg("admin: rbac csv export failed")
			return fail(c, http.StatusInternalServerError, "export_failed")
		}
		c.Response().Header().Set(echo.HeaderContentDisposition, `attachment; filename="rbac.csv"`)
		return c.Blob(http.StatusOK, "text/csv", buf.Bytes())
	}
	c.Response().Header().Set(echo.HeaderContentDisposition, `attachment; filename="rbac.json"`)
	return c.JSON(http.StatusOK, doc)
}

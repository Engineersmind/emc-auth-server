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

// bindRBACImportDocument reads and decodes a bounded RBAC import payload.
// Unknown fields and trailing data are refused for the reasons given on
// bindImportDocument: a typo'd key ("permisions") must fail the upload, not
// import a file with its permissions silently dropped.
func bindRBACImportDocument(c echo.Context) (admin.RBACImportDocument, error) {
	var doc admin.RBACImportDocument
	dec := json.NewDecoder(io.LimitReader(c.Request().Body, maxRBACImportBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return doc, err
	}
	if dec.More() {
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
// @Summary      Export an application's permissions and roles
// @Description  Returns permissions and roles in the import document shape. format=json (default) or format=csv. Requires permissions:read and roles:read for the application.
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

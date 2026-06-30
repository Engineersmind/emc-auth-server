package handlers

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// AgentHandler handles agent registration and authentication endpoints (08-01).
type AgentHandler struct {
	agentSvc *auth.AgentService
	jwtSvc   *auth.JWTService
	logger   zerolog.Logger
}

// NewAgentHandler creates an AgentHandler.
func NewAgentHandler(agentSvc *auth.AgentService, jwtSvc *auth.JWTService, logger zerolog.Logger) *AgentHandler {
	return &AgentHandler{agentSvc: agentSvc, jwtSvc: jwtSvc, logger: logger}
}

// RegisterAgentRequest is the request body for POST /api/v1/admin/agents.
type RegisterAgentRequest struct {
	Name         string   `json:"name"`
	AgentType    string   `json:"agent_type"`
	Capabilities []string `json:"capabilities"`
}

// AuthenticateAgentRequest is the request body for POST /api/v1/agents/authenticate.
type AuthenticateAgentRequest struct {
	Key      string `json:"key"`
	TenantID string `json:"tenant_id"`
}

// RegisterAgent handles POST /api/v1/admin/agents.
//
// @Summary      Register a new agent
// @Description  Creates an agent registration and returns the raw API key once. Requires admin:access.
// @Tags         agent-management
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      RegisterAgentRequest  true  "Agent details"
// @Success      201   {object}  auth.AgentRegistrationResult
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/admin/agents [post]
func (h *AgentHandler) RegisterAgent(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return echo.ErrUnauthorized
	}

	tenantID, err := strconv.ParseInt(claims.TenantID, 10, 64)
	if err != nil {
		return echo.ErrUnauthorized
	}

	var req RegisterAgentRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	if req.AgentType == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "agent_type is required")
	}

	result, err := h.agentSvc.RegisterAgent(c.Request().Context(), tenantID, req.Name, req.AgentType, req.Capabilities)
	if err != nil {
		h.logger.Error().Err(err).Msg("register agent failed")
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	return c.JSON(http.StatusCreated, result)
}

// ListAgents handles GET /api/v1/admin/agents.
//
// @Summary      List agent registrations
// @Description  Returns all active agent registrations for the requesting tenant. Requires admin:access.
// @Tags         agent-management
// @Produce      json
// @Security     BearerAuth
// @Success      200  {array}   auth.AgentWithStats
// @Failure      500  {object}  map[string]string
// @Router       /api/v1/admin/agents [get]
func (h *AgentHandler) ListAgents(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return echo.ErrUnauthorized
	}

	tenantID, err := strconv.ParseInt(claims.TenantID, 10, 64)
	if err != nil {
		return echo.ErrUnauthorized
	}

	agents, err := h.agentSvc.ListAgentsWithStats(c.Request().Context(), tenantID)
	if err != nil {
		h.logger.Error().Err(err).Msg("list agents failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list agents")
	}

	return c.JSON(http.StatusOK, agents)
}

// RevokeAgent handles DELETE /api/v1/admin/agents/:id.
//
// @Summary      Revoke an agent registration
// @Description  Revokes an agent registration belonging to the requesting tenant. Requires admin:access.
// @Tags         agent-management
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "Agent UUID"
// @Success      204  "No Content"
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/admin/agents/{id} [delete]
func (h *AgentHandler) RevokeAgent(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return echo.ErrUnauthorized
	}

	tenantID, err := strconv.ParseInt(claims.TenantID, 10, 64)
	if err != nil {
		return echo.ErrUnauthorized
	}

	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid agent id")
	}

	if err := h.agentSvc.RevokeAgent(c.Request().Context(), tenantID, agentID); err != nil {
		h.logger.Error().Err(err).Msg("revoke agent failed")
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	}

	return c.NoContent(http.StatusNoContent)
}

// GetAgentAnalysis handles GET /api/v1/admin/agents/analysis.
//
// @Summary      Get 24h agent risk analysis
// @Description  Returns risk-scored analysis for all active agents in the tenant. Requires admin:access.
// @Tags         agent-management
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  auth.AgentAnalysis
// @Failure      500  {object}  map[string]string
// @Router       /api/v1/admin/agents/analysis [get]
func (h *AgentHandler) GetAgentAnalysis(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return echo.ErrUnauthorized
	}

	tenantID, err := strconv.ParseInt(claims.TenantID, 10, 64)
	if err != nil {
		return echo.ErrUnauthorized
	}

	analysis, err := h.agentSvc.AnalyzeAgents(c.Request().Context(), tenantID)
	if err != nil {
		h.logger.Error().Err(err).Msg("agent analysis failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to analyze agents")
	}

	return c.JSON(http.StatusOK, analysis)
}

// AuthenticateAgent handles POST /api/v1/agents/authenticate.
//
// @Summary      Authenticate an agent and issue a JWT
// @Description  Validates an agent API key and returns a signed short-lived JWT. Public — no prior auth required.
// @Tags         agent-auth
// @Accept       json
// @Produce      json
// @Param        body  body      AuthenticateAgentRequest  true  "Agent key and tenant ID"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Router       /api/v1/agents/authenticate [post]
func (h *AgentHandler) AuthenticateAgent(c echo.Context) error {
	var req AuthenticateAgentRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Key == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "key is required")
	}

	identity, err := h.agentSvc.AuthenticateAgent(c.Request().Context(), req.Key)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid agent key")
	}

	token, err := h.jwtSvc.SignAgent(c.Request().Context(), identity)
	if err != nil {
		h.logger.Error().Err(err).Msg("sign agent jwt failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to issue token")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(auth.AgentTokenTTL.Seconds()),
		"agent_id":     identity.AgentID.String(),
		"agent_type":   identity.AgentType,
	})
}

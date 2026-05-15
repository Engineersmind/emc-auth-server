package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// HealthResponse is the JSON body returned by the health endpoint.
type HealthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
}

// HealthHandler returns HTTP 200 with a JSON status body.
//
// @Summary     Health check
// @Tags        system
// @Produce     json
// @Success     200  {object}  HealthResponse
// @Router      /health [get]
func HealthHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, HealthResponse{
		Status:  "ok",
		Service: "emc-auth-server",
	})
}

package middleware

import (
	"github.com/labstack/echo/v4"
	emw "github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog"
)

// RequestLogger returns an Echo middleware that logs every request as a
// structured JSON line using the provided zerolog.Logger.
//
// Field order: request_id, method, uri, status, latency, remote_ip, error.
func RequestLogger(logger zerolog.Logger) echo.MiddlewareFunc {
	return emw.RequestLoggerWithConfig(emw.RequestLoggerConfig{
		LogURI:       true,
		LogStatus:    true,
		LogMethod:    true,
		LogLatency:   true,
		LogRequestID: true,
		LogError:     true,
		LogRemoteIP:  true,
		LogValuesFunc: func(c echo.Context, v emw.RequestLoggerValues) error {
			evt := logger.Info()
			if v.Error != nil {
				evt = logger.Error().AnErr("error", v.Error)
			}
			evt.
				Str("request_id", v.RequestID).
				Str("method", v.Method).
				Str("uri", v.URI).
				Int("status", v.Status).
				Dur("latency", v.Latency).
				Str("remote_ip", v.RemoteIP).
				Msg("request")
			return nil
		},
	})
}

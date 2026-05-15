package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	e := echo.New()
	e.HideBanner = false

	// Global middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())
	e.Use(middleware.RequestID())

	// Health check
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(200, map[string]string{
			"status":  "ok",
			"service": "emc-auth-server",
		})
	})

	// TODO: wire up route groups
	// api := e.Group("/api/v1")
	// auth routes, admin routes, SAML, OIDC...

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("EMC Auth Server starting on :%s", port)
	e.Logger.Fatal(e.Start(":" + port))
}

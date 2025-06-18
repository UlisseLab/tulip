package main

import (
	"os"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"tulip/pkg/db"

	"log/slog"
)

func main() {
	// Load .env if present (for local development)
	_ = godotenv.Load()

	// Load configuration from environment variables
	cfg, err := LoadConfig()
	if err != nil {
		slog.Error("Failed to load config", slog.Any("err", err))
		os.Exit(1)
	}

	// Initialize MongoDB connection using pkg/db
	mongoURI := cfg.MongoServer()
	mdb := db.ConnectMongo(mongoURI)

	// Set up Echo server
	e := echo.New()

	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus:  true,
		LogURI:     true,
		LogMethod:  true,
		LogLatency: true,

		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			slog.Info("request",
				"status", v.Status,
				"latency", v.Latency,
				"method", v.Method,
				"uri", v.URI,
			)
			return nil
		},
	}))

	e.Use(middleware.Recover()) // Recover from panics and log them
	e.Use(middleware.CORS())    // Enable CORS for all origins
	e.Use(middleware.Gzip())    // Enable Gzip compression for responses

	// Register all API endpoints using the API struct from api.go
	api := &API{DB: mdb, Config: cfg}
	api.RegisterRoutes(e)

	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}
	slog.Info("Starting server", "port", port)
	if err := e.Start(":" + port); err != nil {
		slog.Error("Echo server failed", slog.Any("err", err))
		os.Exit(1)
	}
}

package main

import (
	"context"
	"log"
	"net/http"
	"oidc-example/server/handlers"
	"oidc-example/server/middleware"
	"oidc-example/server/storage"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize storage
	storageConfig := getStorageConfig()
	store, err := storage.NewStorage(storageConfig)
	if err != nil {
		log.Fatal("Failed to initialize storage:", err)
	}
	defer store.Close()

	// Test database connection
	if err := store.Ping(context.Background()); err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(store)
	oidcHandler := handlers.NewOIDCHandler(store)
	userHandler := handlers.NewUserHandler(store)

	// Create router with middleware
	router := setupRouter(authHandler, oidcHandler, userHandler, store)

	// Start server
	startServer(router)
}

func getStorageConfig() storage.Config {
	// Get storage type from environment variable
	storageType := os.Getenv("STORAGE_TYPE")
	if storageType == "" {
		storageType = "memory" // default to memory for development
	}

	switch storageType {
	case "mysql":
		connectionString := os.Getenv("DATABASE_URL")
		if connectionString == "" {
			connectionString = "oidc:oidc@tcp(localhost:3306)/oidc?parseTime=true"
		}
		return storage.MySQLConfig(connectionString)
	case "memory":
		return storage.MemoryConfig()
	default:
		log.Fatalf("Unknown storage type: %s", storageType)
		return storage.Config{}
	}
}

func setupRouter(authHandler *handlers.AuthHandler, oidcHandler *handlers.OIDCHandler, userHandler *handlers.UserHandler, store storage.Storage) *gin.Engine {
	// Create Gin router
	router := gin.New()

	// Middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.CORS())
	router.Use(middleware.RequestLogger())
	router.Use(middleware.SecurityHeaders())

	// Public routes
	public := router.Group("/api/v1")
	{
		// Auth routes
		public.POST("/register", authHandler.Register)
		public.POST("/login", authHandler.Login)

		// OIDC discovery and endpoints
		public.GET("/.well-known/openid-configuration", oidcHandler.Discovery)
		public.GET("/oauth2/authorize", oidcHandler.Authorize)
		public.POST("/oauth2/token", oidcHandler.Token)
		public.GET("/oauth2/userinfo", oidcHandler.UserInfo)
		public.GET("/oauth2/jwks", oidcHandler.JWKS)
	}

	// Protected routes (require authentication)
	protected := router.Group("/api/v1")
	protected.Use(middleware.AuthMiddleware(store))
	{
		protected.GET("/users/me", userHandler.GetCurrentUser)
		protected.PUT("/users/me", userHandler.UpdateUser)
		protected.GET("/clients", userHandler.GetClients)
		protected.POST("/logout", authHandler.Logout)
	}

	// Admin routes (optional - for management)
	admin := router.Group("/admin/api/v1")
	admin.Use(middleware.AuthMiddleware(store))
	admin.Use(middleware.AdminMiddleware())
	{
		// Add admin endpoints here
	}

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"version":   "1.0.0",
		})
	})

	// Default route
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message":   "OIDC Server API",
			"version":   "1.0.0",
			"endpoints": []string{"/api/v1", "/admin/api/v1", "/health"},
		})
	})

	// 404 handler
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Not Found",
			"message": "The requested resource was not found",
		})
	})

	return router
}

func startServer(router *gin.Engine) {
	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Server starting on :%s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Create context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exited")
}

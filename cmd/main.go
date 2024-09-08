package main

import (
	"Tz/internal/handler"
	"Tz/internal/repository"
	"fmt"
	_ "github.com/jackc/pgx/v4/stdlib"
	"net/http"
)

func main() {
	dataSourceName := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable",
		`localhost`, `postgres`, `625325`, `users`)
	repository.InitDB(dataSourceName)

	http.HandleFunc("/api/user/register", handler.CreateUser)
	http.HandleFunc("/api/user/login", handler.AuthUser)
	http.Handle("/protected-endpoint", handler.JWTMiddleware(http.HandlerFunc(handler.ProtectedEndpoint)))
	http.Handle("/api/user/order", handler.JWTMiddleware(http.HandlerFunc(handler.CreateOrder)))

	http.ListenAndServe(":8080", nil)
}

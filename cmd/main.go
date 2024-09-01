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
	repository.CreateUsersTable()

	http.HandleFunc("/api/user/register", handler.CreateUser)
	http.ListenAndServe(":8080", nil)
}

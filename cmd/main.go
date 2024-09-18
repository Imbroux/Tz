package main

import (
	"Tz/internal/handler"
	"Tz/internal/repository"
	"fmt"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/joho/godotenv"
	"go.uber.org/zap"
	"net/http"
	"os"
)

func main() {
	handler.InitZap()
	router := handler.InitRoutes()

	if err := godotenv.Load(); err != nil {
		handler.Logger.Error("error loading env")
	}

	dataSourceName := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable",
		`localhost`, `postgres`, os.Getenv("DB_PASSWORD"), `postgres`)
	repository.InitDB(dataSourceName)

	if err := http.ListenAndServe(":8080", router); err != nil {
		handler.Logger.Fatal("Сервер не запустился", zap.Error(err))
	}
}

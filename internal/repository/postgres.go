package repository

import (
	"database/sql"
	"log"
)

var DB *sql.DB

func InitDB(dataSourceName string) {
	var err error
	DB, err = sql.Open("pgx", dataSourceName)
	if err != nil {
		log.Fatalf("Error connecting to db: %v", err)
	}

	log.Println("Database connection established.")
}

func CreateUsersTable() {
	createTableQuery := `
  CREATE TABLE IF NOT EXISTS users (
   id SERIAL PRIMARY KEY,
   login TEXT UNIQUE NOT NULL,
   password TEXT NOT NULL
  );
 `

	_, err := DB.Exec(createTableQuery)
	if err != nil {
		panic(err)
	}

}

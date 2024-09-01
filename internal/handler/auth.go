package handler

import (
	"Tz/internal/repository"
	"encoding/json"
	"net/http"
)

type User struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func CreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var newUser User
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	var existingUser string
	err = repository.DB.QueryRow("SELECT login FROM users WHERE login = $1", newUser.Login).Scan(&existingUser)
	if err == nil {
		http.Error(w, "Login already taken", http.StatusConflict)
		return
	}

	_, err = repository.DB.Exec("INSERT INTO users (login, password) VALUES ($1, $2)", newUser.Login, newUser.Password)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	response := "User registered successfully"
	jsonResponse, _ := json.Marshal(response)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}

func AuthUser() {

}

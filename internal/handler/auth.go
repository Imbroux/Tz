package handler

import (
	"Tz/internal/repository"
	"database/sql"
	"encoding/json"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

type User struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		Logger.Error("Error decoding request body", zap.Error(err))
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	Logger.Info("Registering user", zap.String("login", user.Login))

	var exists bool
	err := repository.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE login=$1)", user.Login).Scan(&exists)
	if err != nil {
		Logger.Error("Database query error", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	if exists {
		Logger.Warn("Login already taken", zap.String("login", user.Login))
		http.Error(w, "Login already taken", http.StatusConflict)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		Logger.Error("Password hashing error", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	_, err = repository.DB.Exec("INSERT INTO users (login, password_hash) VALUES ($1, $2)", user.Login, string(hashedPassword))
	if err != nil {
		Logger.Error("Database insert error", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	token, err := GenerateJWT(user.Login)
	if err != nil {
		Logger.Error("Error generating JWT", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Expires:  time.Now().Add(24 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
	})

	response := map[string]string{"token": token}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)

	Logger.Info("User registered successfully", zap.String("login", user.Login))

}

func SignIn(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		Logger.Error("Error decoding request body", zap.Error(err))
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	Logger.Info("Signing in user", zap.String("login", user.Login))

	var storedHash string
	err := repository.DB.QueryRow("SELECT password_hash FROM users WHERE login=$1", user.Login).Scan(&storedHash)
	if err != nil {
		if err == sql.ErrNoRows {
			Logger.Warn("User not found", zap.String("login", user.Login))
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		Logger.Error("Database query error", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(user.Password))
	if err != nil {
		Logger.Warn("Invalid password", zap.String("login", user.Login))
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := GenerateJWT(user.Login)
	if err != nil {
		Logger.Error("Error generating JWT", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Expires:  time.Now().Add(24 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
	})

	response := map[string]string{"token": token}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	Logger.Info("User signed in successfully", zap.String("login", user.Login))
}

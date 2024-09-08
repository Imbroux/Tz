package handler

import (
	"Tz/internal/repository"
	"context"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"strings"
	"time"
)

var jwtKey = []byte("565h5N4rV-")

type Claims struct {
	Login string `json:"login"`
	jwt.StandardClaims
}

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

func AuthUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var credentials struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	var storedPassword string
	err = repository.DB.QueryRow("SELECT password FROM users WHERE login = $1", credentials.Login).Scan(&storedPassword)
	if err != nil || storedPassword != credentials.Password {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token, err := GenerateJWT(credentials.Login)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	jsonResponse, _ := json.Marshal(map[string]string{"token": token})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}

func GenerateJWT(login string) (string, error) {
	expirationTime := time.Now().Add(5 * time.Hour)
	claims := &Claims{
		Login: login,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)

}

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if strings.HasPrefix(tokenString, "Bearer ") {
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "login", claims.Login)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

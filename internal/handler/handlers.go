package handler

import (
	"Tz/internal/repository"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
	_ "log"
	"net/http"
	"strconv"
	"strings"
)

var ErrInvalidKey = errors.New("invalid key")

func CreateOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, err := getUserIDFromToken(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var orderNumber string
	err = json.NewDecoder(r.Body).Decode(&orderNumber)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if !ValidateCardNumber(orderNumber) {
		http.Error(w, "Invalid Order Number Format", http.StatusUnprocessableEntity)
		return
	}

	var existingOrderUserID int
	err = repository.DB.QueryRow("SELECT user_id FROM orders WHERE details = $1", orderNumber).Scan(&existingOrderUserID)
	if err == nil {
		if existingOrderUserID == userID {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Order already exists for this user"))
			return
		} else {
			http.Error(w, "Order already exists for another user", http.StatusConflict)
			return
		}
	} else if err != sql.ErrNoRows {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	_, err = repository.DB.Exec(
		"INSERT INTO orders (user_id, status, details) VALUES ($1, $2, $3)",
		userID, "pending", orderNumber,
	)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte("Order accepted for processing"))
}

func ProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
	login := r.Context().Value("login").(string)
	response := map[string]string{"message": "This is a protected endpoint", "user": login}
	jsonResponse, _ := json.Marshal(response)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}

func getUserIDFromToken(tokenString string) (int, error) {
	if strings.HasPrefix(tokenString, "Bearer ") {
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidKey
		}
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		return 0, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return 0, ErrInvalidKey
	}

	userID, ok := claims["user_id"].(float64)
	if !ok {
		return 0, ErrInvalidKey
	}

	return int(userID), nil
}

func ValidateCardNumber(number string) bool {
	number = strings.Join(strings.Fields(number), "")

	if _, err := strconv.Atoi(number); err != nil {
		return false
	}

	digits := make([]int, len(number))
	for i, ch := range number {
		digits[i] = int(ch - '0')
	}

	sum := 0
	shouldDouble := false

	for i := len(digits) - 1; i >= 0; i-- {
		digit := digits[i]

		if shouldDouble {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}

		sum += digit
		shouldDouble = !shouldDouble
	}

	return sum%10 == 0
}

package handler

import (
	"Tz/internal/repository"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
	"io"
	_ "log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	Logger     *zap.Logger
	userCtxKey = "user"
)

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type OrderResponse struct {
	Number     string    `json:"number"`
	Status     string    `json:"status"`
	Accrual    int       `json:"accrual,omitempty"`
	UploadedAt time.Time `json:"uploaded_at"`
}

type BalanceResponse struct {
	Current   float64 `json:"current"`
	Withdrawn float64 `json:"withdrawn"`
}
type WithdrawRequest struct {
	Order string  `json:"order"`
	Sum   float64 `json:"sum"`
}
type Withdrawal struct {
	Order       string    `json:"order"`
	Sum         float64   `json:"sum"`
	ProcessedAt time.Time `json:"processed_at"`
}

type AccrualInfo struct {
	Order   string  `json:"order"`
	Status  string  `json:"status"`
	Accrual float64 `json:"accrual,omitempty"` // Поле "accrual" может отсутствовать
}

func InitRoutes() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/api/user/register", SignUp).Methods("POST")
	router.HandleFunc("/api/user/login", SignIn).Methods("POST")
	protectedRoutes := router.PathPrefix("/api").Subrouter()
	protectedRoutes.Use(AuthMiddleware)
	protectedRoutes.HandleFunc("/protected/resource", ProtectedHandler).Methods("GET")
	protectedRoutes.HandleFunc("/user/order", Order).Methods("POST")
	protectedRoutes.HandleFunc("/user/orders", GetOrders).Methods("GET")
	protectedRoutes.HandleFunc("/user/balance", GetBalance).Methods("GET")
	protectedRoutes.HandleFunc("/user/balance/withdraw", WithdrawBalance).Methods("POST")
	protectedRoutes.HandleFunc("/user/balance/withdrawals", GetWithdrawals).Methods("GET")
	protectedRoutes.HandleFunc("/orders/{number}", GetAccrualInfo).Methods("GET")

	return router
}

func InitZap() {
	var err error
	Logger, err = zap.NewProduction()
	if err != nil {
		panic(err)
	}
}

func Order(w http.ResponseWriter, r *http.Request) {
	claims := UserFromContext(r.Context())
	if claims == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		Logger.Error("Error reading request body", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	orderNumber := string(body)
	orderNumber = strings.TrimSpace(orderNumber)

	if !regexp.MustCompile(`^\d+$`).MatchString(orderNumber) {
		http.Error(w, "Invalid order number format", http.StatusUnprocessableEntity)
		return
	}

	if !ValidateCardNumber(orderNumber) {
		http.Error(w, "Invalid order number", http.StatusUnprocessableEntity)
		return
	}

	var exists bool
	err = repository.DB.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM orders WHERE login=$1 AND order_number=$2)",
		claims.Username, orderNumber,
	).Scan(&exists)
	if err != nil {
		Logger.Error("Database query error", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	if exists {
		Logger.Info("Order number already uploaded by this user", zap.String("order_number", orderNumber))
		http.Error(w, "Order number already uploaded", http.StatusOK)
		return
	}

	err = repository.DB.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM orders WHERE order_number=$1)",
		orderNumber,
	).Scan(&exists)
	if err != nil {
		Logger.Error("Database query error", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	if exists {
		Logger.Warn("Order number already uploaded by another user", zap.String("order_number", orderNumber))
		http.Error(w, "Order number already uploaded by another user", http.StatusConflict)
		return
	}

	_, err = repository.DB.Exec(
		"INSERT INTO orders (login, order_number, status) VALUES ($1, $2, $3)",
		claims.Username,
		orderNumber,
		"NEW",
	)
	if err != nil {
		Logger.Error("Database insert error", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	Logger.Info("Order number accepted", zap.String("order_number", orderNumber))
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintln(w, "Order number accepted")
}

func GetOrders(w http.ResponseWriter, r *http.Request) {
	claims := UserFromContext(r.Context())
	if claims == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := repository.DB.Query(
		`SELECT order_number, status, accrual, uploaded_at 
         FROM orders 
         WHERE login=$1 
         ORDER BY uploaded_at ASC`, claims.Username)
	if err != nil {
		Logger.Error("Database query error", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var orders []OrderResponse

	for rows.Next() {
		var order OrderResponse
		var accrual sql.NullInt32

		err := rows.Scan(&order.Number, &order.Status, &accrual, &order.UploadedAt)
		if err != nil {
			Logger.Error("Error scanning row", zap.Error(err))
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		if accrual.Valid {
			order.Accrual = int(accrual.Int32)
		}

		orders = append(orders, order)
	}

	if len(orders) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	response, err := json.Marshal(orders)
	if err != nil {
		Logger.Error("Error marshalling response", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

func GetBalance(w http.ResponseWriter, r *http.Request) {
	claims := UserFromContext(r.Context())
	if claims == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	Logger.Info("Fetching balance for user", zap.String("login", claims.Username))

	var currentBalance, withdrawn float64
	err := repository.DB.QueryRow(
		"SELECT current_balance, withdrawn_balance FROM users WHERE login=$1",
		claims.Username,
	).Scan(&currentBalance, &withdrawn)
	if err != nil {
		Logger.Error("Database query error", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	balanceResponse := BalanceResponse{
		Current:   currentBalance,
		Withdrawn: withdrawn,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(balanceResponse); err != nil {
		Logger.Error("Error encoding response", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
	}
}

func WithdrawBalance(w http.ResponseWriter, r *http.Request) {
	claims := UserFromContext(r.Context())
	if claims == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req WithdrawRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Logger.Error("Error decoding request body", zap.Error(err))
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if !regexp.MustCompile(`^\d+$`).MatchString(req.Order) {
		http.Error(w, "Invalid order number format", http.StatusUnprocessableEntity)
		return
	}

	if req.Sum <= 0 {
		http.Error(w, "Invalid withdrawal amount", http.StatusUnprocessableEntity)
		return
	}

	var currentBalance float64
	err := repository.DB.QueryRow(
		"SELECT current_balance FROM users WHERE login=$1",
		claims.Username,
	).Scan(&currentBalance)
	if err != nil {
		Logger.Error("Database query error", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	if currentBalance < req.Sum {
		http.Error(w, "Insufficient funds", http.StatusPaymentRequired)
		return
	}

	_, err = repository.DB.Exec(
		"UPDATE users SET current_balance = current_balance - $1 WHERE login=$2",
		req.Sum, claims.Username,
	)
	if err != nil {
		Logger.Error("Database update error", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	_, err = repository.DB.Exec(
		"INSERT INTO withdrawals (login, order_number, amount) VALUES ($1, $2, $3)",
		claims.Username, req.Order, req.Sum,
	)
	if err != nil {
		Logger.Error("Database insert error", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	Logger.Info("Balance withdrawn successfully", zap.String("login", claims.Username), zap.String("order", req.Order), zap.Float64("amount", req.Sum))
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Withdrawal successful")
}

func GetWithdrawals(responseWriter http.ResponseWriter, r *http.Request) {
	userLogin, ok := r.Context().Value("user_login").(string)
	if !ok {
		Logger.Error("Unauthorized access attempt")
		http.Error(responseWriter, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := repository.DB.Query(`
        SELECT order_number, amount, created_at
        FROM withdrawals
        WHERE login = $1
        ORDER BY created_at ASC`, userLogin)
	if err != nil {
		Logger.Error("Database query error", zap.Error(err))
		http.Error(responseWriter, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var withdrawals []Withdrawal
	for rows.Next() {
		var w Withdrawal
		if err := rows.Scan(&w.Order, &w.Sum, &w.ProcessedAt); err != nil {
			Logger.Error("Error scanning row", zap.Error(err))
			http.Error(responseWriter, "Server error", http.StatusInternalServerError)
			return
		}
		withdrawals = append(withdrawals, w)
	}

	if len(withdrawals) == 0 {
		responseWriter.WriteHeader(http.StatusNoContent)
		return
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(responseWriter).Encode(withdrawals); err != nil {
		Logger.Error("Error encoding JSON response", zap.Error(err))
		http.Error(responseWriter, "Server error", http.StatusInternalServerError)
	}
}

func GetAccrualInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orderNumber := vars["number"]

	if len(orderNumber) == 0 {
		http.Error(w, "Invalid order number", http.StatusBadRequest)
		return
	}

	// Запрос информации о расчёте начислений баллов
	// Здесь можно сделать запрос к внешней системе или базе данных.

	accrualData := AccrualInfo{
		Order:   orderNumber,
		Status:  "PROCESSED",
		Accrual: 500,
	}

	switch accrualData.Status {
	case "PROCESSED":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(accrualData); err != nil {
			Logger.Error("Error encoding JSON response", zap.Error(err))
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
	case "INVALID":
		w.WriteHeader(http.StatusNoContent)
	case "PROCESSING":
		http.Error(w, "Processing", http.StatusAccepted)
	case "REGISTERED":
		http.Error(w, "Registered", http.StatusAccepted)
	default:
		http.Error(w, "Unknown status", http.StatusInternalServerError)
	}
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

func GenerateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)

	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(os.Getenv("JWTKEY")))
	if err != nil {
		return "", err
	}
	Logger.Info("Generated JWT token", zap.String("token", tokenString))
	return tokenString, nil
}

func ParseJWT(tokenString string) (*Claims, error) {
	secretKey := []byte(os.Getenv("JWTKEY"))

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
			claims, err := ParseJWT(token)
			if err != nil {
				Logger.Error("Invalid token", zap.Error(err))
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), userCtxKey, claims)
			r = r.WithContext(ctx)
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func UserFromContext(ctx context.Context) *Claims {
	return ctx.Value(userCtxKey).(*Claims)
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {

	claims, ok := r.Context().Value("claims").(*Claims)
	if !ok {
		http.Error(w, "Failed to retrieve claims", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Hello, %s! This is a protected resource.", claims.Username)
}

// @title Address API
// @version 1.0
// @description This is a simple API for address geocoding and user authentication.
// @host localhost:8080
// @BasePath /api
// @securityDefinitions.apiKey ApiKeyAuth
// @in header
// @name Authorization

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "proxy/docs"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth"
	httpSwagger "github.com/swaggo/http-swagger"
	"golang.org/x/crypto/bcrypt"
)

// @title Swagger Example API
// @version 1.0
// @description This is a sample server Petstore server.

// @Host("api.swagger.com")
// @BasePath
type RequestAddressSearch struct {
	Query string `json:"query"`
}

type ResponseAddresses struct {
	Lat string `json:"geo_lat"`
	Lng string `json:"geo_lon"`
}

type ResponseAddress struct {
	Suggestions []struct {
		Address ResponseAddresses `json:"data"`
	} `json:"suggestions"`
}

// ErrorResponse представляет ответ с ошибкой
// @Description Ошибка, возникающая при обработке запроса
// @Success 400 {object} ErrorResponse
type ErrorResponse struct {
	BadRequest      string `json:"400"`
	DadataBad       string `json:"500"`
	SuccefulRequest string `json:"200"`
}

var (
	tokenAuth *jwtauth.JWTAuth
	users     = make(map[string]string)
)

func init() {
	tokenAuth = jwtauth.New("HS256", []byte("your_secret_key"), nil)
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Register(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		return
	}
	if _, exists := users[user.Username]; exists {
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	if err != nil {
		http.Error(w, "Could not hash password", http.StatusInternalServerError)
		return
	}
	users[user.Username] = string(hashedPassword)
	w.WriteHeader(http.StatusCreated)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		return
	}
	hashedPassword, exists := users[user.Username]
	if !exists || bcrypt.CompareHashAndPassword([]byte(hashedPassword),
		[]byte(user.Password)) != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	claims := map[string]interface{}{
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	}
	_, tokenString, _ := tokenAuth.Encode(claims)

	w.Header().Set("Authorization", "Bearer "+tokenString)
	w.WriteHeader(http.StatusOK)
}

// @Summary Get Geo Coordinates
// @Description This endpoint allows you to get geo coordinates by address
// @Param address body RequestAddressSearch true "Address search query"
// @Router /api/address/geocode [post]
// @Success 200 {object} ResponseAddress "Успешное выполнение"
// @Success 400 {object} ErrorResponse "Ошибка запроса"
// @Success 500 {object} ErrorResponse "Ошибка подключения к серверу"
func getGeoCoordinates(query string) (string, error) {
	url := "http://suggestions.dadata.ru/suggestions/api/4_1/rs/suggest/address"
	reqData := map[string]string{"query": query}

	jsonData, err := json.Marshal(reqData)
	if err != nil {
		panic(err)
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "token d9e0649452a137b73d941aa4fb4fcac859372c8c")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	fmt.Println(string(body))
	var response ResponseAddress
	err = json.Unmarshal(body, &response)
	if err != nil {
		panic(err)
	}

	if len(response.Suggestions) > 0 {
		return fmt.Sprintf("%s %s", response.Suggestions[0].Address.Lat, response.Suggestions[0].Address.Lng), nil
	}

	return "", fmt.Errorf("no suggestions found")
}

func main() {
	signalChan := make(chan os.Signal, 1)

	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	r := chi.NewRouter()
	srv := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	go func() {
		r.Use(middleware.Logger)
		r.Get("/swagger/*", httpSwagger.WrapHandler)
		r.Post("/api/register", Register)
		r.Post("/api/login", Login)
		r.Post("/api/address/geocode", func(w http.ResponseWriter, r *http.Request) {
			geo, err := getGeoCoordinates("москва сухонская 11") // Здесь можно передать запрос из тела
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write([]byte(geo))
		})

		r.Post("/api/address/search", func(w http.ResponseWriter, r *http.Request) {
			geo, err := getGeoCoordinates("москва сухонская 11") // Здесь можно передать запрос из тела
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			proxyMiddleware(geo)(w, r)
		})

		http.ListenAndServe(":8080", r)
	}()
	<-signalChan
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		fmt.Printf("Ошибка при завершении %v", err)
	} else {
		fmt.Printf("Grace close")
	}
}

func proxyMiddleware(geo string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(geo))
	})
}

package main

import (
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// @title Address API
// @version 1.0
// @description API для поиска адресов и получения геокодирования.
// @host localhost:8080
// @BasePath /api

// @RequestAddressGeocode представляет запрос для геокодирования
// @Description Этот эндпоинт позволяет получить адрес по географическим координатам.
// @Param address body RequestAddressGeocode true "Географические координаты"

type RequestAddressSearch struct {
	Query string `json:"query"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

type ResponseAddress struct {
	Addresses []*Address `json:"addresses"`
}

type RequestAddressGeocode struct {
	Lat string `json:"lat"`
	Lng string `json:"lng"`
}

type Address struct {
	Street  string `json:"street"`
	City    string `json:"city"`
	State   string `json:"state"`
	ZipCode string `json:"zip_code"`
	Country string `json:"country"`
}

func main() {
	r := gin.Default()

	r.POST("/geocode", getGeocode)
	r.Run(":8080")
}

// @Success 200 {object} ResponseAddress
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// Логика геокодирования
func getGeocode(c *gin.Context) {
	var geocode RequestAddressGeocode
	if err := c.ShouldBindJSON(&geocode); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Message: "Invalid request"})
		return
	}
	response, err := http.Get(fmt.Sprintf("https://dadata.ru/api/v2/geocode?lat=%s&lng=%s", geocode.Lat, geocode.Lng))
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Message: "Internal server error"})
		return
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Message: "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": string(body),
	})
}

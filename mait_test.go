package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestGetGeocode_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.POST("/geocode", getGeocode)
	lat := "55.7558"
	lng := "37.6173"
	requestBody, _ := json.Marshal(RequestAddressGeocode{Lat: lat, Lng: lng})
	req, _ := http.NewRequest(http.MethodPost, "/geocode", bytes.NewBuffer(requestBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.NotNil(t, response["data"])
}

func TestGetGeocode_BadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.POST("/geocode", getGeocode)

	req, _ := http.NewRequest(http.MethodPost, "/geocode", bytes.NewBuffer([]byte(`{"lat": "55.7558}`)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "400", response["error"])
}

func TestGetGeocode_InternalServerError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.POST("/geocode", getGeocode)

	lat := "invalid_latitude"
	lng := "invalid_longitude"
	requestBody, _ := json.Marshal(RequestAddressGeocode{Lat: lat, Lng: lng})
	req, _ := http.NewRequest(http.MethodPost, "/geocode", bytes.NewBuffer(requestBody))
	req.Header.Set("Content-type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "500", response["error"])
}

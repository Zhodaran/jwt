// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {},
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/api/address/geocode": {
            "post": {
                "security": [
                    {
                        "BearerAuth": []
                    }
                ],
                "description": "This endpoint allows you to get geo coordinates by latitude and longitude.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "geo"
                ],
                "summary": "Get Geo Coordinates by Latitude and Longitude",
                "parameters": [
                    {
                        "type": "number",
                        "description": "Latitude",
                        "name": "lat",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "number",
                        "description": "Longitude",
                        "name": "lng",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Bearer {token}",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Успешное выполнение",
                        "schema": {
                            "$ref": "#/definitions/main.ResponseAddress"
                        }
                    },
                    "400": {
                        "description": "Ошибка запроса",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    },
                    "500": {
                        "description": "Ошибка подключения к серверу",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/api/address/search": {
            "post": {
                "security": [
                    {
                        "BearerAuth": []
                    }
                ],
                "description": "This endpoint allows you to get geo coordinates by address.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "geo"
                ],
                "summary": "Get Geo Coordinates by Address",
                "parameters": [
                    {
                        "description": "Address search query",
                        "name": "address",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/main.RequestAddressSearch"
                        }
                    },
                    {
                        "type": "string",
                        "description": "Bearer {token}",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Успешное выполнение",
                        "schema": {
                            "$ref": "#/definitions/main.ResponseAddress"
                        }
                    },
                    "400": {
                        "description": "Ошибка запроса",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    },
                    "500": {
                        "description": "Ошибка подключения к серверу",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/api/login": {
            "post": {
                "description": "This endpoint allows a user to log in with their username and password.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "users"
                ],
                "summary": "Login a user",
                "parameters": [
                    {
                        "description": "User login details",
                        "name": "user",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/main.User"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Login successful",
                        "schema": {
                            "$ref": "#/definitions/main.LoginResponse"
                        }
                    },
                    "400": {
                        "description": "Invalid request",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    },
                    "401": {
                        "description": "Invalid credentials",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/api/register": {
            "post": {
                "description": "This endpoint allows you to register a new user with a username and password.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "users"
                ],
                "summary": "Register a new user",
                "parameters": [
                    {
                        "description": "User registration details",
                        "name": "user",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/main.User"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "User registered successfully",
                        "schema": {
                            "$ref": "#/definitions/main.TokenResponse"
                        }
                    },
                    "400": {
                        "description": "Invalid request",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    },
                    "409": {
                        "description": "User already exists",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "main.Address": {
            "type": "object",
            "properties": {
                "city": {
                    "type": "string"
                },
                "geo_lat": {
                    "type": "string"
                },
                "geo_lon": {
                    "type": "string"
                },
                "house": {
                    "type": "string"
                },
                "street": {
                    "type": "string"
                }
            }
        },
        "main.ErrorResponse": {
            "type": "object",
            "properties": {
                "200": {
                    "type": "string"
                },
                "400": {
                    "type": "string"
                },
                "500": {
                    "type": "string"
                }
            }
        },
        "main.LoginResponse": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string"
                }
            }
        },
        "main.RequestAddressSearch": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string"
                }
            }
        },
        "main.ResponseAddress": {
            "type": "object",
            "properties": {
                "suggestions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "data": {
                                "$ref": "#/definitions/main.Address"
                            }
                        }
                    }
                }
            }
        },
        "main.TokenResponse": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string"
                }
            }
        },
        "main.User": {
            "type": "object",
            "properties": {
                "password": {
                    "type": "string"
                },
                "username": {
                    "type": "string"
                }
            }
        }
    },
    "securityDefinitions": {
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1.0",
	Host:             "localhost:8080",
	BasePath:         "",
	Schemes:          []string{},
	Title:            "Address API",
	Description:      "Этот эндпоинт позволяет получить адрес по наименованию",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}

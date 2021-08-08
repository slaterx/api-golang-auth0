package main

import (
	"encoding/json"
	"errors"
	"github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type (
	// authHandler wraps a http handler for authenticated requests
	authHandler struct {
		http.Handler
	}
	// openHandler wraps a http handler for unauthenticated requests
	openHandler struct {
		http.Handler
	}
	// JSONWebKeys wraps the object containing json web keys
	JSONWebKeys struct {
		Keys []JSONWebKey `json:"keys"`
	}
	// JSONWebKey is the struct with the key and its metadata
	JSONWebKey struct {
		Kty string   `json:"kty"`
		Kid string   `json:"kid"`
		Use string   `json:"use"`
		N   string   `json:"n"`
		E   string   `json:"e"`
		X5c []string `json:"x5c"`
	}
	// FixedClaims contains a fix for https://github.com/auth0/go-jwt-middleware/issues/72
	// as per https://github.com/auth0/go-jwt-middleware/issues/72#issuecomment-788389180
	FixedClaims struct {
		jwt.StandardClaims
		Permissions []string `json:"permissions,omitempty"`
	}
)

// ServeHTTP wraps auth over an HTTP handler
func (authHandler authHandler) ServeHTTP(writer http.ResponseWriter, reader *http.Request) {
	authHandler.Handler.ServeHTTP(writer, reader)
}

// ServeHTTP wraps auth over an HTTP handler
func (openHandler openHandler) ServeHTTP(writer http.ResponseWriter, reader *http.Request) {
	openHandler.Handler.ServeHTTP(writer, reader)
}

// ServePublicHttp provides http server method for object httpServer
func ServePublicHttp(writer http.ResponseWriter, request *http.Request) {
	var err error
	writer.Header().Set("Content-Type", "application/json")
	log.Print("Received request on /api/messages/public")

	switch request.Method {
	case "GET":
		writer.WriteHeader(http.StatusOK)
		_, err = writer.Write([]byte(`{"message": "The API doesn't require an access token to share this message."}`))
	default:
		writer.WriteHeader(http.StatusNotFound)
		log.Printf("Received method %v, which I don't understand", request.Method)
		_, err = writer.Write([]byte(`{"message": "Not found"}`))
	}

	if err != nil {
		log.Fatalf("Error while processing request %v: %v", request.Method, err)
	}

}

// ServeProtectedHttp provides http server method for object httpServer
func ServeProtectedHttp(writer http.ResponseWriter, request *http.Request) {
	var err error
	log.Print("Received request on /api/messages/protected")
	user := request.Context().Value("user")

	for _, permission := range user.(*jwt.Token).Claims.(*FixedClaims).Permissions {
		log.Printf("Checking permission %v, which should be equal to protected", permission)
		if permission == "protected" {
			log.Print("Permission 'protected' found in token")
			writer.Header().Set("Content-Type", "application/json")

			switch request.Method {
			case "GET":
				writer.WriteHeader(http.StatusOK)
				_, err = writer.Write([]byte(`{"message": "The API successfully validated your access token."}`))
			default:
				writer.WriteHeader(http.StatusNotFound)
				log.Printf("Received method %v, which I don't understand", request.Method)
				_, err = writer.Write([]byte(`{"message": "Not found"}`))
			}

			if err != nil {
				log.Fatalf("Error while processing request %v: %v", request.Method, err)
			}
			return
		}
	}

	writer.WriteHeader(http.StatusUnauthorized)
	log.Print("Did not find required permission in token, unauthorized")
	_, err = writer.Write([]byte(`{"message": "Unauthorized"}`))

}

// ServeAdminHttp provides http server method for object httpServer
func ServeAdminHttp(writer http.ResponseWriter, request *http.Request) {
	var err error
	log.Print("Received request on /api/messages/admin")
	user := request.Context().Value("user")

	for _, permission := range user.(*jwt.Token).Claims.(*FixedClaims).Permissions {
		log.Printf("Checking permission %v, which should be equal to admin", permission)
		if permission == "admin" {
			log.Print("Permission 'admin' found in token")
			writer.Header().Set("Content-Type", "application/json")

			switch request.Method {
			case "GET":
				writer.WriteHeader(http.StatusOK)
				_, err = writer.Write([]byte(`{"message": "The API successfully recognized you as an admin."}`))
			default:
				writer.WriteHeader(http.StatusNotFound)
				log.Printf("Received method %v, which I don't understand", request.Method)
				_, err = writer.Write([]byte(`{"message": "Not found"}`))
			}

			if err != nil {
				log.Fatalf("Error while processing request %v: %v", request.Method, err)
			}
			return
		}
	}

	writer.WriteHeader(http.StatusUnauthorized)
	log.Print("Did not find required permission in token, unauthorized")
	_, err = writer.Write([]byte(`{"message": "Unauthorized"}`))

}

// main provides main functionality of application
func main() {
	log.Print("Starting server...")
	// Start interrupt listener
	setupGracefulShutdown()

	// Configure JWT authentication
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			// Verify Audience claim
			if !token.Claims.(*FixedClaims).VerifyAudience("YOUR_AUDIENCE", false) {
				return token, errors.New("Invalid audience.")
			}

			// Verify Issuer claim
			if !token.Claims.(*FixedClaims).VerifyIssuer("YOUR_DOMAIN", false) {
				return token, errors.New("Invalid issuer.")
			}

			// Verify Expiry claim
			if !token.Claims.(*FixedClaims).VerifyExpiresAt(time.Now().Unix(), false) {
				return token, errors.New("Token expired.")
			}

			cert, err := downloadCert(token)
			if err != nil {
				panic(err.Error())
			}

			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		},
		SigningMethod: jwt.SigningMethodRS256,
		Claims:        &FixedClaims{},
	})

	// Start mux router
	router := mux.NewRouter()
	log.Print("Listening on /api/messages/public")
	router.HandleFunc("/api/messages/public", ServePublicHttp)
	log.Print("Listening on /api/messages/protected")
	router.HandleFunc("/api/messages/protected", ServeProtectedHttp)
	log.Print("Listening on /api/messages/admin")
	router.HandleFunc("/api/messages/admin", ServeAdminHttp)

	// Start serve mux
	server := http.NewServeMux()
	server.Handle("/api/messages/public", openHandler{router})
	server.Handle("/api/messages/protected", jwtMiddleware.Handler(authHandler{router}))
	server.Handle("/api/messages/admin", jwtMiddleware.Handler(authHandler{router}))

	// Enable CORS on endpoint
	setupCors := cors.New(cors.Options{
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowCredentials: true,
		AllowedHeaders:   []string{"Content-Type", "Origin", "Accept", "*"},
	})

	log.Print("Running on localhost, port 8080")
	log.Print(http.ListenAndServe(":8080", setupCors.Handler(server)))

}

// setupGracefulShutdown creates a 'listener' for OS interrupt signals
// on a new goroutine
func setupGracefulShutdown() {
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Printf("exiting (%v)", c)
		os.Exit(0)
	}()
}

// downloadCert connects to auth0 to obtain certificate
func downloadCert(token *jwt.Token) (cert string, err error) {
	response, err := http.Get("https://YOUR_DOMAIN/.well-known/jwks.json")

	if err != nil {
		return
	}

	var keys = JSONWebKeys{}
	err = json.NewDecoder(response.Body).Decode(&keys)

	if err != nil {
		return
	}

	for k := range keys.Keys {
		if token.Header["kid"] == keys.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + keys.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err = errors.New("key could not be obtained")
		return
	}

	return
}

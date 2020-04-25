package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"strings"
	"time"
)

// Create a struct that models the structure of a user in the request body
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

// Output from decrypting a token
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type restInfo struct {
	Cert string
	Key  string
	Port string
}

var flags restInfo

// jwtKey is shared to encrypt the token. Fix the sharing method for production use.
var jwtKey = []byte("my_secret_key")

func main() {
	flagInit()

	http.HandleFunc("/signin", Signin)
	http.HandleFunc("/welcome", Welcome)
	http.HandleFunc("/refresh", Refresh)
	log.Fatal(http.ListenAndServeTLS(":"+flags.Port, flags.Cert, flags.Key, nil))
}

func Signin(w http.ResponseWriter, r *http.Request) {
	// CORS Allowed
	enableCors(&w)
	setupResponse(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	var creds Credentials
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get the expected password from our in memory map
	expectedPassword := "password"

	// If a password exists for the given user
	// AND, if it is the same as the password we received, the we can move ahead
	// if NOT, then we return an "Unauthorized" status
	fmt.Printf("EXPECTED %+v, CREDSPWD %+v, CREDS %+v\n", expectedPassword, creds.Password, creds)
	if expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Declare the expiration time of the token
	// here, we have kept it as 5 minutes
	expirationTime := time.Now().Add(2 * time.Hour)
	// Create the JWT claims, which includes the username and expiry time
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
	fmt.Printf("TOKEN %+v\n", tokenString)
	w.Write([]byte(tokenString))
}

func Welcome(w http.ResponseWriter, r *http.Request) {
	// CORS
	enableCors(&w)
	setupResponse(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer")

	// Verify index before using
	if len(splitToken) != 2 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tknStr := strings.TrimSpace(splitToken[1])

	// Initialize a new instance of `Claims`
	claims := &Claims{}

	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Finally, return the welcome message to the user, along with their
	// username given in the token
	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	// CORS
	enableCors(&w)
	setupResponse(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer")

	// Verify index before using
	if len(splitToken) != 2 {
		fmt.Printf("REQ %+v\n", reqToken)
		fmt.Printf("Token %+v\n", splitToken)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tknStr := strings.TrimSpace(splitToken[1])

	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// (END) The code uptil this point is the same as the first part of the `Welcome` route

	// We ensure that a new token is not issued until enough time has elapsed
	// In this case, a new token will only be issued if the old token is within
	// 2 hours of expiry. Otherwise, return a bad request status
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 2*time.Hour {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Now, create a new token for the current use, with a renewed expiration time
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Return the renewed token
	w.Write([]byte(tokenString))
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}

func setupResponse(w *http.ResponseWriter, req *http.Request) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
}

func flagInit() {
	restcert := flag.String("restcert", "", "Rest Certificate File")
	restkey := flag.String("restkey", "", "Rest Key File")
	restport := flag.String("restport", "8113", "Rest interface https port")
	flag.Parse()
	flags.Cert = *restcert
	flags.Key = *restkey
	flags.Port = *restport
	fmt.Printf("Flags used %+v\n", flags)
	return
}

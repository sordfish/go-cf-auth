package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/coreos/go-oidc"
)

var (
	ctx        = context.TODO()
	teamDomain = os.Getenv("CF_TEAMDOMAIN")
	certsURL   = fmt.Sprintf("%s/cdn-cgi/access/certs", teamDomain)

	// policyAUD is your application AUD value
	policyAUD = os.Getenv("CF_POLICY_AUD")

	config = &oidc.Config{
		ClientID: policyAUD,
	}
	keySet   = oidc.NewRemoteKeySet(ctx, certsURL)
	verifier = oidc.NewVerifier(teamDomain, keySet, config)
)

// VerifyToken is a middleware to verify a CF Access token
func VerifyToken(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		headers := r.Header

		// Make sure that the incoming request has our token header
		//  Could also look in the cookies for CF_AUTHORIZATION
		accessJWT := headers.Get("Cf-Access-Jwt-Assertion")
		if accessJWT == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("No token on the request"))
			return
		}

		// Verify the access token
		ctx := r.Context()
		_, err := verifier.Verify(ctx, accessJWT)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("Invalid token: %s", err.Error())))
			return
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func CheckReadiness(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ready"))
	}
	return http.HandlerFunc(fn)
}

func CheckLiveness(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}
	return http.HandlerFunc(fn)
}

func MainHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})
}

func main() {

	if policyAUD == "" || policyAUD == "NOTSET" {
		fmt.Println("CF_POLICY_AUD env var not set")
		os.Exit(1)
	}

	if teamDomain == "" || teamDomain == "NOTSET" {
		fmt.Println("CF_TEAMDOMAIN env var not set")
		os.Exit(1)
	}

	http.Handle("/", VerifyToken(MainHandler()))
	http.Handle("/livez", CheckLiveness(MainHandler()))
	http.Handle("/readyz", CheckReadiness(MainHandler()))
	http.ListenAndServe(":3000", nil)
}

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/shivas/evesso"
)

func main() {
	const state = "mysecretstate"

	ctx := context.Background()

	type authReply struct {
		code  string
		state string
	}

	// to run this please create EVE 3rd party app with callback to: http://localhost:8080 (any path), and set environment variables used below
	client, err := evesso.NewClient(ctx, nil, os.Getenv("EVE_CLIENT_ID"), os.Getenv("EVE_CLIENT_SECRET"), "http://localhost:8080/auth/callback")
	if err != nil {
		log.Fatal(err)
	}

	authURL := client.AuthenticateURL(state)
	fmt.Printf("Auth Start URL: %s\n", authURL)

	authChan := make(chan authReply)

	go func() {
		errServer := http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			code := r.URL.Query()["code"]
			state := r.URL.Query()["state"]

			select {
			case authChan <- authReply{code: code[0], state: state[0]}:

			default:
			}
		}))
		if errServer != nil {
			log.Fatal(err)
		}
	}()

	codeState := <-authChan
	fmt.Printf("%#v\n", codeState)

	if codeState.state != state {
		log.Fatal(errors.New("received state back missmatched"))
	}

	r, err := client.ExchangeCode(ctx, codeState.code)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("accesstoken:\n%s\n", r.AccessToken)

	decodedToken, err := client.ParseToken(ctx, r.AccessToken)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("is token valid: %t\n", decodedToken.Valid)

	characterID, characterName, err := client.GetCharacterDetails(decodedToken)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Character: %q with ID: %d logged in.\n", characterName, characterID)

	err = client.RevokeToken(ctx, r.RefreshToken)
	if err != nil {
		log.Fatal(err)
	}
}

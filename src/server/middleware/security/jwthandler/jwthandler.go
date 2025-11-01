package jwthandler

import (
	"log"

	"github.com/goharbor/harbor/src/common"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func ParseToken(token string, jwkSet jwk.Set) (jwt.Token, error) {
	// parse the token
	parsedToken, err := jwt.Parse([]byte(token), jwt.WithKeySet(jwkSet), jwt.WithValidate(true), jwt.WithAcceptableSkew(common.JwtLeeway))
	if err != nil {
		log.Printf("\n\nFailed to verify JWT signature: %v", err)
	}

	log.Println("\n\nJWT signature validation successful!")
	log.Printf("Parsed Token: %+v\n", parsedToken)

	return parsedToken, nil
}

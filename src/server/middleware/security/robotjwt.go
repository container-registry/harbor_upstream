// Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/goharbor/harbor/src/common"
	"github.com/goharbor/harbor/src/common/security"
	robotCtx "github.com/goharbor/harbor/src/common/security/robot"
	federated_idp "github.com/goharbor/harbor/src/controller/federatedidp"
	robot_ctl "github.com/goharbor/harbor/src/controller/robot"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/pkg/token"
	"github.com/goharbor/harbor/src/server/middleware/security/jwthandler"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// JWK represents a single JSON Web Key
type JWK struct {
	Kid *string  `json:"kid,omitempty"` // Key ID
	Kty *string  `json:"kty,omitempty"` // Key Type
	Use *string  `json:"use,omitempty"` // Public Key Use
	N   *string  `json:"n,omitempty"`   // RSA modulus
	E   *string  `json:"e,omitempty"`   // RSA exponent
	X5c []string `json:"x5c,omitempty"`
	// Add other fields as needed with omitempty
}

// JWKS represents a set of JSON Web Keys
type JWKS struct {
	Keys []JWK `json:"keys,omitempty"`
}

type robotjwt struct{}

// TODO: finally remove debug logs with kumar prefix

func (r *robotjwt) Generate(req *http.Request) security.Context {
	log.Warningf("if you are seeing this kumar, it means you are starting the robot validation")
	log := log.G(req.Context())
	var jwkSet jwk.Set

	log.Warningf("inside the request: %v", req)
	log.Warningf("inside the request headers: %v", req.Header)

	// get the jwt
	tokenStr := bearerToken(req)
	if len(tokenStr) == 0 {
		tokenStr = basicAuthToken(req)
		if len(tokenStr) == 0 {
			log.Warningf("no JWT token found")
			return nil
		} else {
			log.Warningf("the jwt token is %s", tokenStr)
		}
		// return nil
	}

	// kumar, log the jwt token
	log.Warningf("the jwt token is %s", tokenStr)

	jwtToken, _ := jwt.Parse(tokenStr, nil)
	// if err != nil {
	//  log.Warningf("failed to parse token: %v", err)
	// 	if jwtToken != nil {
	// 		log.Warningf("okay, the parsed jwt token is %v", jwtToken)
	// 	}
	// }

	issuer, err := jwtToken.Claims.GetIssuer()
	if err != nil {
		log.Warningf("failed to get issuer from token: %v", err)
		return nil
	}
	kid := jwtToken.Header["kid"].(string)

	// based on the issuer, get the jwks jwks-uri
	// get it from the database
	// federated_idp.Ctl.Get(req.Context(), issuer, *&model.FederatedIdp{})
	idp, err := federated_idp.Ctl.GetIdpByIssuer(req.Context(), issuer)
	if err != nil {
		log.Warningf("failed to get federated idp by issuer: %s", err)
		return nil
	}

	if idp.OfflineValidation {
		// do offline validation
		jwkskeysString := idp.JWKSKeys
		if len(jwkskeysString) == 0 {
			log.Warningf("federated idp %s has no jwks keys", idp.Name)
			return nil
		}
		log.Warningf("federated idp jwks keys: %s", idp.JWKSKeys)
		jwkSet, err = jwk.Parse([]byte(jwkskeysString))
		if err != nil {
			log.Warningf("failed to parse JWK set: %v", err)
			return nil
		}
		log.Warningf("\n\n JWK Set: %v", jwkSet)
		_, ok := jwkSet.LookupKeyID(kid)
		if !ok {
			log.Warningf("failed to find key with kid: %s", kid)
			return nil
		}
	} else {
		// do online validation
		jwkSet, err = GetAndParseJWK(req.Context(), idp.JWKSURI, log)
		if err != nil {
			log.Warningf("failed to get jwks set: %v", err)
			return nil
		}
		log.Warningf("\n\n JWK Set: %v", jwkSet)
		_, ok := jwkSet.LookupKeyID(kid)
		if !ok {
			log.Warningf("failed to find key with kid: %s", kid)
			return nil
		}
	}

	// parse and validate the token
	parsedToken, err := jwthandler.ParseToken(tokenStr, jwkSet)
	if err != nil {
		log.Warningf("failed to parse token: %v", err)
		// TODO: return error
		// return nil
	}

	log.Warningf("parsedToken is: %v", parsedToken)

	// put claims from the issuer
	cl := jwt.MapClaims{}
	cl = jwtToken.Claims.(jwt.MapClaims)
	log.Warningf("claims supported by idp: %v", idp.ClaimsSupported)
	log.Warningf("the claims is %v", cl)

	// make sure it satisfies all the identity provider's claims
	idpClaims, err := federated_idp.Ctl.ListClaimsIdpOnly(req.Context(), idp.ID, "")
	if err != nil {
		log.Warningf("failed to get claims from idp: %v", err)
		return nil
	}

	// validate the token claims with idp claims
	for _, claim := range idpClaims {
		log.Warningf("current claim: path - %s, value - %s", claim.ClaimPath, claim.Value)
		var val string
		err := parsedToken.Get(claim.ClaimPath, &val)
		if err != nil {
			log.Warningf("failed to get claim %s from token: %v", claim.ClaimPath, err)
			return nil
		}

		if strings.TrimSpace(val) != strings.TrimSpace(claim.Value) {
			log.Warningf("claim %s, with value %s does not match with idp value: %v", claim.ClaimPath, claim.Value, val)
			return nil
		}
	}

	// claims, ok := jwtToken.Claims.(*v2TokenClaims)
	tokenClaims := jwtToken.Claims.(jwt.MapClaims)
	log.Warningf("the claims from token is %v", tokenClaims)

	// get list of claims from the token
	// Now you can access everything, e.g.
	for k, v := range tokenClaims {
		fmt.Println("claim:", k, "value:", v)
	}

	// query the token claims on idp and get robot
	rid, err := federated_idp.Ctl.GetTopMatchedRobot(req.Context(), idp.ID, tokenClaims)
	if err != nil {
		log.Warningf("failed to get robot id: %v", err)
		return nil
	}

	// kumar delete the debug logs
	log.Warningf("kumar, the robot id is : %d", rid)
	log.Warningf("kumar, given token is valid proceeding with claim validation")
	log.Warningf("if you are seeing this kumar, it means you are done with the robot validation")

	if rid == 0 {
		log.Warningf("no robot account matched the provided token claims")
		return nil
	}

	robot, err := robot_ctl.Ctl.Get(req.Context(), rid, &robot_ctl.Option{
		WithPermission: true,
	})
	if err != nil {
		log.Errorf("failed to get robot with id: %d, %v", rid, err)
		return nil
	}
	if robot == nil {
		log.Warningf("kumaruu, robot is nil")
		return nil
	}
	if robot.Disabled {
		log.Errorf("failed to authenticate deactivated robot account: %s", robot.Name)
		return nil
	}
	now := time.Now().Unix()
	if robot.ExpiresAt != -1 && robot.ExpiresAt <= now {
		log.Errorf("the robot account is expired: %s", robot.Name)
		return nil
	}

	log.Debugf("a robot security context generated for request %s %s", req.Method, req.URL.Path)
	return robotCtx.NewSecurityContext(robot)
}

// TODO: replace this function with a robust one
// the function should be able to take the jwks-uri and return the public key

// TODO: replace this function with a robust one
// it should be able to take the JWK or PEM from DB and return the public key

func GetAndParseJWK(ctx context.Context, jwksUri string, log *log.Logger) (jwk.Set, error) {
	set, err := jwk.Fetch(ctx, jwksUri)
	if err != nil {
		log.Warningf("failed to parse JWK: %s", err)
		return nil, err
	}

	return set, nil
}

func getJWKFromJWKS(jwksJSON string, tokenKid string) (*JWK, error) {
	// 1. Parse JWKS JSON into Go struct
	var jwks JWKS
	if err := json.Unmarshal([]byte(jwksJSON), &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}

	// 2. Find the JWK that matches the token's kid
	for _, key := range jwks.Keys {
		if key.Kid != nil && *key.Kid == tokenKid {
			return &key, nil
		}
	}

	return nil, fmt.Errorf("no matching JWK found for kid: %s", tokenKid)
}

// jwkToPublicKey converts a JWK to a PKIX-encoded public key byte slice.
func jwkToPublicKey(jwk JWK) ([]byte, error) {
	// First, try to use the x5c field if it's available. This is the preferred method.
	if len(jwk.X5c) > 0 {
		certBytes, err := base64.StdEncoding.DecodeString(jwk.X5c[0])
		if err != nil {
			return nil, fmt.Errorf("failed to decode certificate from x5c: %w", err)
		}

		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		pkixBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key from certificate: %w", err)
		}
		return pkixBytes, nil
	}

	// If x5c is not present, fall back to decoding n and e.
	if jwk.N == nil || jwk.E == nil {
		return nil, fmt.Errorf("JWK does not contain 'n', 'e', or 'x5c' fields")
	}

	// Decode 'n' (modulus)
	modulusBytes, err := base64.RawURLEncoding.DecodeString(*jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus 'n': %w", err)
	}
	modulus := new(big.Int).SetBytes(modulusBytes)

	// Decode 'e' (exponent)
	exponentBytes, err := base64.RawURLEncoding.DecodeString(*jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent 'e': %w", err)
	}
	exponent := new(big.Int).SetBytes(exponentBytes).Int64()

	// Create an rsa.PublicKey struct
	pubKey := &rsa.PublicKey{
		N: modulus,
		E: int(exponent),
	}

	// Marshal the public key to PKIX format
	pkixBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	return pkixBytes, nil
}

// getRSAPublicKeyFromJWK converts a JWK RSA key into Go's rsa.PublicKey
func getRSAPublicKeyFromJWK(jwk *JWK) (*rsa.PublicKey, error) {
	if jwk.Kty == nil || *jwk.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %v", jwk.Kty)
	}
	if jwk.N == nil || jwk.E == nil {
		return nil, fmt.Errorf("missing modulus or exponent in JWK")
	}

	// --- Decode modulus N ---
	nBytes, err := base64.RawURLEncoding.DecodeString(*jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// --- Decode exponent E ---
	// handle "AQAB" and similar short exponents
	eBytes, err := base64.RawURLEncoding.DecodeString(*jwk.E)
	if err != nil {
		// fallback: try with standard padding
		eBytes, err = base64.URLEncoding.DecodeString(*jwk.E)
		if err != nil {
			return nil, fmt.Errorf("failed to decode exponent: %w", err)
		}
	}

	// convert exponent bytes to int
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e == 0 {
		return nil, fmt.Errorf("invalid exponent: 0")
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// Convert *rsa.PublicKey -> PEM []byte
func publicKeyToPEMBytes(pubKey *rsa.PublicKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})

	return pemBytes, nil
}

func ParseToken(signMethod jwt.SigningMethod, publicKey any, rawToken string, claims jwt.Claims) (*token.Token, error) {
	var parser = jwt.NewParser(jwt.WithLeeway(common.JwtLeeway), jwt.WithValidMethods([]string{signMethod.Alg()}))
	tokn, err := parser.ParseWithClaims(rawToken, claims, func(_ *jwt.Token) (any, error) {
		switch signMethod.Alg() {
		case "RS256":
			pk := publicKey.(rsa.PublicKey)
			return &pk, nil
		case "ES256":
			pk := publicKey.(ecdsa.PublicKey)
			return &pk, nil
		default:
			return publicKey, nil
		}
	})
	if err != nil {
		log.Errorf("parse token error, %v", err)
		return nil, err
	}

	if !tokn.Valid {
		log.Errorf("invalid jwt token, %v", tokn)
		return nil, fmt.Errorf("invalid jwt token")
	}
	return &token.Token{
		Token: *tokn,
	}, nil
}

// //nolint:govet
// func Example_jwk_marshal_json() {
// 	// JWKs that inherently involve randomness such as RSA and EC keys are
// 	// not used in this example, because they may produce different results
// 	// depending on the environment.
// 	//
// 	// (In fact, even if you use a static source of randomness, tests may fail
// 	// because of internal changes in the Go runtime).
//
// 	raw := []byte("01234567890123456789012345678901234567890123456789ABCDEF")
//
// 	// This would create a symmetric key
// 	key, err := jwk.Import(raw)
// 	if err != nil {
// 		fmt.Printf("failed to create symmetric key: %s\n", err)
// 		return
// 	}
// 	if _, ok := key.(jwk.SymmetricKey); !ok {
// 		fmt.Printf("expected jwk.SymmetricKey, got %T\n", key)
// 		return
// 	}
//
// 	key.Set(jwk.KeyIDKey, "mykey")
//
// 	buf, err := json.MarshalIndent(key, "", "  ")
// 	if err != nil {
// 		fmt.Printf("failed to marshal key into JSON: %s\n", err)
// 		return
// 	}
// 	fmt.Printf("%s\n", buf)
//
// 	// OUTPUT:
// 	// {
// 	//   "k": "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODlBQkNERUY",
// 	//   "kid": "mykey",
// 	//   "kty": "oct"
// 	// }
// }

// basicAuthToken extracts only the password (e.g., JWT) from an Authorization: Basic header.
func basicAuthToken(req *http.Request) string {
	log.Warningf("kumaruu,inside the basicauthtoken")
	if req == nil {
		log.Warningf("thhe request is nil")
		return ""
	}

	// Get the "Authorization" header value
	h := req.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Basic ") {
		log.Warningf("kumaruu header is not Basic: %s", h)
		return ""
	}

	// Extract the base64-encoded portion after "Basic "
	encoded := strings.TrimSpace(strings.TrimPrefix(h, "Basic "))

	// Decode base64 value → gives "username:password"
	decodedBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Warningf("kumaruu failed to decode base64: %s", err)
		return ""
	}
	decoded := string(decodedBytes)

	log.Warningf("kumaruu, decoded auth is %s", decoded)
	// Split on the first ':' and return only password part
	parts := strings.SplitN(decoded, ":", 2)
	if len(parts) != 2 {
		log.Warningf("kumaruu invalid decoded string: %s", decoded)
		return ""
	}

	// ✅ Return only the password (JWT token)
	return parts[1]
}

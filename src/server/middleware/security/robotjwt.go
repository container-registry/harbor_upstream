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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/goharbor/harbor/src/common"
	"github.com/goharbor/harbor/src/common/security"
	robotCtx "github.com/goharbor/harbor/src/common/security/robot"
	federated_idp "github.com/goharbor/harbor/src/controller/federatedidp"
	robot_ctl "github.com/goharbor/harbor/src/controller/robot"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/pkg/token"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type robotjwt struct{}

func defaultOptions() *token.Options {
	return token.DefaultTokenOptions()
}

// TODO: finally remove debug logs with kumar prefix

func (r *robotjwt) Generate(req *http.Request) security.Context {
	log.Warningf("if you are seeing this kumar, it means you are starting the robot validation")
	log := log.G(req.Context())

	// get the jwt
	tokenStr := bearerToken(req)
	if len(tokenStr) == 0 {
		return nil
	}

	// kumar, log the jwt token
	log.Warningf("the jwt token is %s", tokenStr)

	// get the jwks key
	// first get the issuer from the token
	tokene, _ := jwt.Parse(tokenStr, nil)
	issuer, err := tokene.Claims.GetIssuer()
	if err != nil {
		log.Warningf("failed to get issuer from token: %v", err)
		return nil
	}

	// based on the issuer, get the jwks jwks-uri
	// get it from the database
	// federated_idp.Ctl.Get(req.Context(), issuer, *&model.FederatedIdp{})
	idp, err := federated_idp.Ctl.GetIdpByIssuer(req.Context(), issuer)
	if err != nil {
		log.Warningf("failed to get federated idp by issuer: %s", err)
		return nil
	}

	var jwkskeys string
	if idp.OfflineValidation {
		// do offline validation
		jwkskeys = idp.JWKSKeys
		if len(jwkskeys) == 0 {
			log.Warningf("federated idp %s has no jwks keys", idp.Name)
			return nil
		}
	} else {
		// do online validation
		jwkskeys, err := GetAndParseJWK(req.Context(), idp.JWKSURI, log)
		if err != nil {
			log.Warningf("failed to get jwks keys: %s", err)
			return nil
		}
		if len(jwkskeys) == 0 {
			log.Warningf("federated idp %s has no jwks keys", idp.Name)
			return nil
		}
	}

	// query for the right robot account

	// validate jwt token against the jwks key

	// TODO: get the token options from db
	defaultOpt := defaultOptions()
	if defaultOpt == nil {
		log.Warningf("failed to get default options")
		return nil
	}

	// kumar, update the default Options, temporarily for testing and verifying
	defaultOpt.Issuer = idp.Issuer
	// TODO: remove hardcoded to RS256
	defaultOpt.SignMethod = jwt.GetSigningMethod("RS256")
	defaultOpt.PrivateKey = []byte("")
	defaultOpt.PublicKey = []byte("")

	// TODO: no hardcoded JWK, use the JWK from DB
	//
	// TODO: Find a robust library to parse the JWK and PEM for offline use case
	// TODO: remove the below hardcoded x5c and n, e
	// x5c := `MIIDKzCCAhOgAwIBAgIUDnwm6eRIqGFA3o/P1oBrChvx/nowDQYJKoZIhvcNAQELBQAwJTEjMCEGA1UEAwwaYWN0aW9ucy5zZWxmLXNpZ25lZC5naXRodWIwHhcNMjQwMTIzMTUyNTM2WhcNMzQwMTIwMTUyNTM2WjAlMSMwIQYDVQQDDBphY3Rpb25zLnNlbGYtc2lnbmVkLmdpdGh1YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOTGp5svs8LJN8BH7VzXShWXnOK0lhDVuI0xnr5bwHFPc924CwaIEFb6mC7bvW2lZtgd633uaJ2naG6vKaOVGpCdGLE4ohH11nUk+2CNknZL7/oTmDHGSmGeHRb7kjtb0Ng4BJMPzmTYmCNUudfDFhHDcZz1Obuu85GsABrC5ZlzWzspYFXwUSaxvII+rHK/rAbOC2gmt5IOSLmgh3taQfp0mB6Lxlf89HoBPNwtPfBX8DtXTWQVnqODm4W+WfmWBSyXGX54DGNMyZwlTZqR0FjoMXxopId3MIuDGKxa2weDU5cW60N2y/qxikeV99fL3sg5aPA8s9iljKG0+MAfVNUCAwEAAaNTMFEwHQYDVR0OBBYEFIPALo5VanJ6E1B9eLQgGO+uGV65MB8GA1UdIwQYMBaAFIPALo5VanJ6E1B9eLQgGO+uGV65MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGS0hZE+DqKIRi49Z2KDOMOaSZnAYgqq6ws9HJHT09MXWlMHB8E/apvy2ZuFrcSu14ZLweJid+PrrooXEXEO6azEakzCjeUb9G1QwlzP4CkTcMGCw1Snh3jWZIuKaw21f7mp2rQ+YNltgHVDKY2s8AD273E8musEsWxJl80/MNvMie8Hfh4n4/Xl2r6t1YPmUJMoXAXdTBb0hkPy1fUu3r2T+1oi7Rw6kuVDfAZjaHupNHzJeDOg2KxUoK/GF2/M2qpVrd19Pv/JXNkQXRE4DFbErMmA7tXpp1tkXJRPhFui/Pv5H9cPgObEf9x6W4KnCXzT3ReeeRDKF8SqGTPELsc=`

	// TODO: improve the overall flow
	// TODO: get the public key from jwks-uri
	// start things from the db
	// pubKey, err := ParseJWKx5cToPublicKey(x5c)
	// if err != nil {
	// 	log.Fatalf("failed: %v", err)
	// }

	// pubKey, err := ParseJWKtoPublicKey(n, e)
	// if err != nil {
	// 	log.Fatalf("failed to parse JWK: %v", err)
	// }

	// defaultOpt.PublicKey = pubKey

	// TODO: create more dynamic base claims based on the issuer.
	// put claims from the issuer
	cl := jwt.MapClaims{}

	// kumar, log the claims
	log.Warningf("the claims is %v", cl)

	// token.parse will just check the validity of the token and parse the token, validating the given claims
	t, err := token.Parse(defaultOpt, tokenStr, cl)
	if err != nil {
		log.Warningf("failed to decode bearer token: %v", err)
		return nil
	}

	// check if the signature is valid
	if !t.Valid {
		log.Warningf("the token is invalid: %v", t)
		return nil
	}

	tokenClaims := t.Claims.(jwt.MapClaims)

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
	log.Warningf("kumar, given token is valid proceeding with claim validation")

	// TODO: validate the token with the custom claims
	// TODO: find a robust library to check with all custom claims from DB
	var v = jwt.NewValidator(jwt.WithLeeway(common.JwtLeeway), jwt.WithAudience("my-registry"))
	if err := v.Validate(t.Claims); err != nil {
		log.Warningf("failed to validate bearer token claims: %v", err)
		return nil
	}
	// TODO: replace the v2TokenClaims with a custom struct holding custom claims from DB
	// probably hold as any/interface{} or map[string]interface{}
	claims, ok := t.Claims.(*v2TokenClaims)
	if !ok {
		log.Warningf("invalid token claims.")
		return nil
	}
	// kumar, improve the below thing
	// TODO: add checks for the requested resource by analyzing the requesturl
	if len(claims.Subject) == 0 {
		log.Warningf("invalid token claims, no access.")
		return nil
	}
	// return v2token.New(req.Context(), claims.Subject, claims.Access)
	log.Warningf("if you are seeing this kumar, it means you are done with the robot validation")

	// kumar, hardcoded robot name
	// TODO: based on the request, get the robot most qualified robot name
	// project robot accounts will take precedence over system robot accounts

	// kumar, the above should be a function that fetches the correct robot name for the given token

	// TODO: more checks need to be done
	// below are the normal steps for robot account flow

	// The robot name can be used as the unique identifier to locate robot as it contains the project name.
	robot, err := robot_ctl.Ctl.Get(req.Context(), rid, &robot_ctl.Option{
		WithPermission: true,
	})
	if err != nil {
		log.Errorf("failed to get robot with id: %d, %v", rid, err)
		return nil
	}
	if robot == nil {
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

func GetAndParseJWK(ctx context.Context, jwksUri string, log *log.Logger) ([]jwk.Key, error) {
	set, err := jwk.Fetch(ctx, jwksUri)
	if err != nil {
		log.Warningf("failed to parse JWK: %s", err)
		return nil, err
	}

	// Key sets can be serialized back to JSON
	{
		jsonbuf, err := json.Marshal(set)
		if err != nil {
			log.Warningf("failed to marshal key set into JSON: %s", err)
			return nil, err
		}
		log.Warningf("jsonbuf: %s", jsonbuf)
	}

	var keys []jwk.Key
	for i := 0; i < set.Len(); i++ {
		var rawkey any        // This is where we would like to store the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
		key, ok := set.Key(i) // This retrieves the corresponding jwk.Key
		if !ok {
			log.Warningf("failed to get key at index %d", i)
			return nil, err
		}

		// jws and jwe operations can be performed using jwk.Key, but you could also
		// covert it to their "raw" forms, such as *rsa.PrivateKey or *ecdsa.PrivateKey
		if err := jwk.Export(key, &rawkey); err != nil {
			log.Warningf("failed to create public key: %s", err)
			return nil, err
		}
		_ = rawkey

		// You can create jwk.Key from a raw key, too
		fromRawKey, err := jwk.Import(rawkey)
		if err != nil {
			log.Warningf("failed to acquire raw key from jwk.Key: %s", err)
			return nil, err
		}

		// Keys can be serialized back to JSON
		jsonbuf, err := json.Marshal(key)
		if err != nil {
			log.Warningf("failed to marshal key into JSON: %s", err)
			return nil, err
		}

		fromJSONKey, err := jwk.Parse(jsonbuf)
		if err != nil {
			log.Warningf("failed to parse json: %s", err)
			return nil, err
		}
		_ = fromJSONKey
		_ = fromRawKey
		// log the above items
		log.Warningf("the key is %v", key)
		log.Warningf("the raw key is %v", rawkey)
		log.Warningf("the from raw key is %v", fromRawKey)
		log.Warningf("the from json key is %v", fromJSONKey)

		keys = append(keys, key)
	}
	return keys, nil
}

//
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

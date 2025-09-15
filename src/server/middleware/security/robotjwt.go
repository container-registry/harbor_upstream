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
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/goharbor/harbor/src/common"
	"github.com/goharbor/harbor/src/common/security"
	robotCtx "github.com/goharbor/harbor/src/common/security/robot"
	robot_ctl "github.com/goharbor/harbor/src/controller/robot"
	"github.com/goharbor/harbor/src/lib/config"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/lib/q"
	"github.com/goharbor/harbor/src/pkg/token"
	"github.com/golang-jwt/jwt/v5"
)

type robotjwt struct{}

func defaultOptions() *token.Options {
	return token.DefaultTokenOptions()
}

// TODO: replace this function with a robust one
// the function should be able to take the jwks-uri and return the public key

// TODO: replace this function with a robust one
// it should be able to take the JWK or PEM from DB and return the public key

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

	// TODO: get the token options from db
	defaultOpt := defaultOptions()
	if defaultOpt == nil {
		log.Warningf("failed to get default options")
		return nil
	}

	// kumar, update the default Options, temporarily for testing and verifying
	defaultOpt.Issuer = "https://gitlab.com"
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
	cl := &v2TokenClaims{}
	// kumar, log the claims
	log.Warningf("the claims is %v", cl)

	// TODO: remove hard coded robot account
	var name string
	log.Warningf("going to run get robot account fuunction")
	robotacc, err := getRobotAccount(req, log)
	if err != nil {
		log.Errorf("failed to get robot account so now assinging the default robot account - robot_potta: %v", err)
		name = "robot_potta"
	} else {
		name = robotacc.Name
	}
	log.Warningf("done ran get robot account fuunction")
	log.Warningf("robot account we got was: %s", name)

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
	robots, err := robot_ctl.Ctl.List(req.Context(), q.New(q.KeyWords{
		"name": strings.TrimPrefix(name, config.RobotPrefix(req.Context())),
	}), &robot_ctl.Option{
		WithPermission: true,
	})
	if err != nil {
		log.Errorf("failed to list robots: %v", err)
		return nil
	}
	if len(robots) == 0 {
		return nil
	}

	robot := robots[0]
	// if utils.Encrypt(secret, robot.Salt, utils.SHA256) != robot.Secret {
	// 	log.Errorf("failed to authenticate robot account: %s", name)
	// 	return nil
	// }
	if robot.Disabled {
		log.Errorf("failed to authenticate deactivated robot account: %s", name)
		return nil
	}
	now := time.Now().Unix()
	if robot.ExpiresAt != -1 && robot.ExpiresAt <= now {
		log.Errorf("the robot account is expired: %s", name)
		return nil
	}

	log.Debugf("a robot security context generated for request %s %s", req.Method, req.URL.Path)
	return robotCtx.NewSecurityContext(robot)
}

// get the robot account with max matching claims
func getRobotAccount(req *http.Request, log *log.Logger) (*robot_ctl.Robot, error) {
	// TODO: get the robot account with max matching claims
	return nil, fmt.Errorf("completely failed to get robot account")
}

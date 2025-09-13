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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/goharbor/harbor/src/common"
	"github.com/goharbor/harbor/src/common/rbac"
	rbac_project "github.com/goharbor/harbor/src/common/rbac/project"
	"github.com/goharbor/harbor/src/common/security"
	robotCtx "github.com/goharbor/harbor/src/common/security/robot"
	"github.com/goharbor/harbor/src/controller/project"
	robot_ctl "github.com/goharbor/harbor/src/controller/robot"
	"github.com/goharbor/harbor/src/lib"
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

// mapMethodToAction maps HTTP verbs to Harbor RBAC actions
// func mapMethodToAction(method string) types.Action {
// 	switch method {
// 	case http.MethodGet, http.MethodHead:
// 		return rbac.ActionPull // GET/HEAD → pull
// 	case http.MethodPost, http.MethodPut, http.MethodPatch:
// 		return rbac.ActionPush // POST/PUT/PATCH → push
// 	case http.MethodDelete:
// 		return rbac.ActionDelete
// 	default:
// 		return "" // unknown
// 	}
// }

// TODO: replace this function with a robust one
// the function should be able to take the jwks-uri and return the public key
//
// ParseJWKx5cToPublicKey takes the x5c cert string and converts it to PEM []byte
func ParseJWKx5cToPublicKey(x5c string) ([]byte, error) {
	// decode base64 DER cert
	der, err := base64.StdEncoding.DecodeString(x5c)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x5c: %w", err)
	}

	// parse DER into x509.Certificate
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert: %w", err)
	}

	// marshal public key (RSA/ECDSA depending on cert)
	derBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// encode to PEM
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})

	return pemBytes, nil
}

// TODO: replace this function with a robust one
// it should be able to take the JWK or PEM from DB and return the public key
//
// // ParseJWKtoPublicKey converts JWK (n, e) into PEM []byte
// func ParseJWKtoPublicKey(n, e string) ([]byte, error) {
// 	// base64url decode modulus
// 	nb, err := base64.RawURLEncoding.DecodeString(n)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to decode n: %w", err)
// 	}
//
// 	// base64url decode exponent
// 	eb, err := base64.RawURLEncoding.DecodeString(e)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to decode e: %w", err)
// 	}
//
// 	// convert exponent bytes to int
// 	var exp int
// 	if len(eb) < 4 {
// 		eb4 := make([]byte, 4)
// 		copy(eb4[4-len(eb):], eb)
// 		exp = int(binary.BigEndian.Uint32(eb4))
// 	} else {
// 		exp = int(new(big.Int).SetBytes(eb).Int64())
// 	}
//
// 	// construct rsa.PublicKey
// 	pub := &rsa.PublicKey{
// 		N: new(big.Int).SetBytes(nb),
// 		E: exp,
// 	}
//
// 	// convert to PKIX DER
// 	der, err := x509.MarshalPKIXPublicKey(pub)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to marshal public key: %w", err)
// 	}
//
// 	// encode to PEM
// 	pemBytes := pem.EncodeToMemory(&pem.Block{
// 		Type:  "PUBLIC KEY",
// 		Bytes: der,
// 	})
//
// 	return pemBytes, nil
// }

// TODO: finally remove debug logs with kumar prefix

func (r *robotjwt) Generate(req *http.Request) security.Context {
	log.Warningf("if you are seeing this kumar, it means you are starting the robot validation")
	log := log.G(req.Context())

	// TODO: check if the request is from container runtime
	// if yes, get the resource needed from the request
	//
	// if !strings.HasPrefix(req.URL.Path, "/v2") {
	// 	return nil
	// }

	// get the jwt
	tokenStr := bearerToken(req)
	if len(tokenStr) == 0 {
		return nil
	}

	// kumar, log the jwt token
	log.Warningf("the jwt token is %s", tokenStr)

	// parse the jwt
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
	// parse jwk to PublicKey
	// n := "4cxDjTcJRJFID6UCgepPV45T1XDz_cLXSPgMur00WXB4jJrR9bfnZDx6dWqwps2dCw-lD3Fccj2oItwdRQ99In61l48MgiJaITf5JK2c63halNYiNo22_cyBG__nCkDZTZwEfGdfPRXSOWMg1E0pgGc1PoqwOdHZrQVqTcP3vWJt8bDQSOuoZBHSwVzDSjHPY6LmJMEO42H27t3ZkcYtS5crU8j2Yf-UH5U6rrSEyMdrCpc9IXe9WCmWjz5yOQa0r3U7M5OPEKD1-8wuP6_dPw0DyNO_Ei7UerVtsx5XSTd-Z5ujeB3PFVeAdtGxJ23oRNCq2MCOZBa58EGeRDLR7Q"
	// e := "AQAB"

	// TODO: no hardcoded values, get everything needed from DB
	//
	// TODO: Find a robust library to parse the JWK and PEM for offline use case
	// TODO: remove the below hardcoded x5c and n, e
	x5c := `MIIDKzCCAhOgAwIBAgIUDnwm6eRIqGFA3o/P1oBrChvx/nowDQYJKoZIhvcNAQELBQAwJTEjMCEGA1UEAwwaYWN0aW9ucy5zZWxmLXNpZ25lZC5naXRodWIwHhcNMjQwMTIzMTUyNTM2WhcNMzQwMTIwMTUyNTM2WjAlMSMwIQYDVQQDDBphY3Rpb25zLnNlbGYtc2lnbmVkLmdpdGh1YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOTGp5svs8LJN8BH7VzXShWXnOK0lhDVuI0xnr5bwHFPc924CwaIEFb6mC7bvW2lZtgd633uaJ2naG6vKaOVGpCdGLE4ohH11nUk+2CNknZL7/oTmDHGSmGeHRb7kjtb0Ng4BJMPzmTYmCNUudfDFhHDcZz1Obuu85GsABrC5ZlzWzspYFXwUSaxvII+rHK/rAbOC2gmt5IOSLmgh3taQfp0mB6Lxlf89HoBPNwtPfBX8DtXTWQVnqODm4W+WfmWBSyXGX54DGNMyZwlTZqR0FjoMXxopId3MIuDGKxa2weDU5cW60N2y/qxikeV99fL3sg5aPA8s9iljKG0+MAfVNUCAwEAAaNTMFEwHQYDVR0OBBYEFIPALo5VanJ6E1B9eLQgGO+uGV65MB8GA1UdIwQYMBaAFIPALo5VanJ6E1B9eLQgGO+uGV65MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGS0hZE+DqKIRi49Z2KDOMOaSZnAYgqq6ws9HJHT09MXWlMHB8E/apvy2ZuFrcSu14ZLweJid+PrrooXEXEO6azEakzCjeUb9G1QwlzP4CkTcMGCw1Snh3jWZIuKaw21f7mp2rQ+YNltgHVDKY2s8AD273E8musEsWxJl80/MNvMie8Hfh4n4/Xl2r6t1YPmUJMoXAXdTBb0hkPy1fUu3r2T+1oi7Rw6kuVDfAZjaHupNHzJeDOg2KxUoK/GF2/M2qpVrd19Pv/JXNkQXRE4DFbErMmA7tXpp1tkXJRPhFui/Pv5H9cPgObEf9x6W4KnCXzT3ReeeRDKF8SqGTPELsc=`

	// TODO: improve the overall flow
	pubKey, err := ParseJWKx5cToPublicKey(x5c)
	if err != nil {
		log.Fatalf("failed: %v", err)
	}

	// pubKey, err := ParseJWKtoPublicKey(n, e)
	// if err != nil {
	// 	log.Fatalf("failed to parse JWK: %v", err)
	// }

	defaultOpt.PublicKey = pubKey

	cl := &v2TokenClaims{}
	// kumar, log the claims
	log.Warningf("the claims is %v", cl)

	// get artifact info
	ai := lib.GetArtifactInfo(req.Context())
	bmDigest := ai.BlobMountDigest
	bmRepo := ai.BlobMountRepository
	bmProjectName := ai.BlobMountProjectName
	projectName := ai.ProjectName
	repository := ai.Repository
	digest := ai.Digest
	tag := ai.Tag
	reference := ai.Reference
	// get the type of request
	RequestMethod := req.Method
	if RequestMethod == "" {
		// hnadle the case when the request method is empty
		RequestMethod = "GET"
	}
	log.Debugf("bmDigest: %s, bmRepo: %s, bmProjectName: %s", bmDigest, bmRepo, bmProjectName)
	log.Debugf("projectName: %s, repository: %s, digest: %s, tag: %s, reference: %s", projectName, repository, digest, tag, reference)

	// send the request method and the artifact info to get the right robot account
	// give me a fucction name
	var name string
	log.Warningf("going to run get robot account fuunction")
	robotacc := getRobotAccount(req, RequestMethod, ai, log)
	if len(robotacc.Name) == 0 {
		log.Errorf("failed to get robot account so now assinging the default robot account - robot_potta")
		name = "robot_potta"
	} else {
		name = robotacc.Name
	}
	log.Warningf("done ran get robot account fuunction")
	log.Warningf("robot account we got was: %s", name)

	// token.parse will both validate the token with default needed claims and verify the signature
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

	// sneak in the robot name
	// name, secret, ok := req.BasicAuth()
	// if !ok {
	// 	return nil
	// }
	// if !strings.HasPrefix(name, config.RobotPrefix(req.Context())) {
	// 	return nil
	// }

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

func getRobotAccount(req *http.Request, RequestMethod string, ai lib.ArtifactInfo, log *log.Logger) *robot_ctl.Robot {
	switch RequestMethod {
	case http.MethodGet, http.MethodHead:

		log.Warningf("going to get all robot accounts")

		// create a custom query
		query := q.New(q.KeyWords{
			"permissions.access.action": "pull",                                // only get robot accounts with pull permission
			"permissions.namespace":     fmt.Sprintf("{%s *}", ai.ProjectName), // union match project name and *
		})
		// get all robot accounts
		robots, err := robot_ctl.Ctl.List(req.Context(),
			// should do a better query
			// q.New(q.KeyWords{"name": strings.TrimPrefix(ai.ProjectName, config.RobotPrefix(ctx)),}),
			query,
			&robot_ctl.Option{
				WithPermission: true,
			})
		if err != nil {
			log.Errorf("failed to list robots: %v", err)
			return nil
		}
		if len(robots) == 0 {
			return nil
		}

		// Marshal to pretty JSON
		data, err := json.MarshalIndent(robots, "", "  ")
		if err != nil {
			log.Errorf("failed to marshal robots: %v", err)
			return nil
		}
		log.Warningf("robots: %s", string(data))

		for _, robot := range robots {
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
			// robotCtx.NewSecurityContext(robot)

			// get security context for every robot account
			sctx := robotCtx.NewSecurityContext(robot)

			log.Warningf("got new security context for robot: %v", sctx)
			project, err := project.Ctl.Get(req.Context(), ai.ProjectName)
			if err != nil {
				log.Errorf("failed to get project in robotjwt: %v", err)
				return nil
			}
			log.Warningf("got project: %v", project)
			// apply security context to the RequestMethod
			// problem is if robot acc is not right we need to remove the security context from the request context
			// req = req.WithContext(security.NewContext(req.Context(), sctx))
			// now get the resource hard coded to list tags
			resource := rbac_project.NewNamespace(project.ProjectID).Resource(rbac.ResourceRepository)
			if sctx.Can(req.Context(), rbac.ActionPull, resource) {
				return robot
			}

			// if baseAPI.HasProjectPermission(req.Context(), ai.ProjectName, rbac.ActionPull, rbac.ResourceArtifact) {
			// 	return robot
			// }
		}
		return nil
	}
	return nil
}

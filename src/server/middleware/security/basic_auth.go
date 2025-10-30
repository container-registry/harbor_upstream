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
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/goharbor/harbor/src/common/models"
	"github.com/goharbor/harbor/src/common/security"
	"github.com/goharbor/harbor/src/common/security/local"
	"github.com/goharbor/harbor/src/core/auth"
	"github.com/goharbor/harbor/src/lib/log"
)

type basicAuth struct{}

func trueClientIPHeaderName() string {
	// because the true client IP header varies based on the foreground proxy/lb settings,
	// make it configurable by env
	name := os.Getenv("TRUE_CLIENT_IP_HEADER")
	if len(name) == 0 {
		name = "x-forwarded-for"
	}
	return name
}

// GetClientIP get client ip from request
func GetClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	ip := r.Header.Get(trueClientIPHeaderName())
	if len(ip) > 0 {
		return ip
	}
	return r.RemoteAddr
}

// GetUserAgent get the user agent of current request
func GetUserAgent(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.Header.Get("user-agent")
}

func IsJWT(token string) bool {
	// Trim any surrounding spaces just in case
	token = strings.TrimSpace(token)

	// Split the token by '.'
	parts := strings.Split(token, ".")

	// A valid JWT always has exactly 3 parts
	if len(parts) != 3 {
		log.Warningf("invalid jwt token doesn't have 3 parts: has %v: %s", parts, token)
		return false
	}

	// Each part should be non-empty (base64url-encoded)
	if slices.Contains(parts, "") {
		log.Warningf("invalid jwt token has empty part: %s", token)
		return false
	}

	return true
}

func (b *basicAuth) Generate(req *http.Request) security.Context {
	log := log.G(req.Context())
	username, password, ok := req.BasicAuth()
	if !ok {
		return nil
	}

	// if password is jwt use jwt auth
	if IsJWT(password) {
		log.Warningf("JWT is coming inside db_auth, skipping db_auth")
		return nil
	}
	user, err := auth.Login(req.Context(), models.AuthModel{
		Principal: username,
		Password:  password,
	})

	if err != nil {
		log.WithField("client IP", GetClientIP(req)).WithField("user agent", GetUserAgent(req)).Errorf("failed to authenticate user:%s, error:%v", username, err)
		return nil
	}
	if user == nil {
		log.Debug("basic auth user is nil")
		return nil
	}
	log.Debugf("a basic auth security context generated for request %s %s", req.Method, req.URL.Path)
	return local.NewSecurityContext(user)
}

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

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-openapi/runtime/middleware"

	"github.com/goharbor/harbor/src/common/rbac"

	federated_idp "github.com/goharbor/harbor/src/controller/federatedidp"
	"github.com/goharbor/harbor/src/lib"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/lib/q"
	pkg "github.com/goharbor/harbor/src/pkg/federatedidp/model"
	"github.com/goharbor/harbor/src/server/v2.0/handler/model"
	"github.com/goharbor/harbor/src/server/v2.0/models"
	operation "github.com/goharbor/harbor/src/server/v2.0/restapi/operations/federated_idp"
)

func newFederatedIDPAPI() *fedIDPAPI {
	return &fedIDPAPI{
		fedidpCtl: federated_idp.Ctl,
	}
}

type fedIDPAPI struct {
	BaseAPI
	fedidpCtl federated_idp.Controller
}

// ListClaimRules
func (fAPI *fedIDPAPI) ListClaimRules(ctx context.Context, params operation.ListClaimRulesParams) middleware.Responder {
	if err := fAPI.RequireAuthenticated(ctx); err != nil {
		return fAPI.SendError(ctx, err)
	}

	f := &pkg.FederatedIdp{
		ID: params.ID,
	}
	if err := fAPI.requireAccess(ctx, f, rbac.ActionList); err != nil {
		return fAPI.SendError(ctx, err)
	}

	var claimpath string
	if params.ClaimPath != nil && *params.ClaimPath != "" {
		claimpath = *params.ClaimPath
	}

	claims, err := fAPI.fedidpCtl.ListClaims(ctx, params.ID, claimpath)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	var results []*models.ClaimRule
	for _, c := range claims {
		results = append(results, model.NewClaimRule(&c).ToSwagger())
	}

	return operation.NewListClaimRulesOK().
		WithPayload(results)
}

// DeleteClaimRule
func (fAPI *fedIDPAPI) DeleteClaimRules(ctx context.Context, params operation.DeleteClaimRulesParams) middleware.Responder {
	if err := fAPI.RequireAuthenticated(ctx); err != nil {
		return fAPI.SendError(ctx, err)
	}

	f := &pkg.FederatedIdp{
		ID: params.ID,
	}
	if err := fAPI.requireAccess(ctx, f, rbac.ActionDelete); err != nil {
		return fAPI.SendError(ctx, err)
	}

	if len(params.Claims.Rules) == 0 {
		return fAPI.SendError(ctx, errors.New(nil).WithMessage("no claim rules provided").WithCode(errors.BadRequestCode))
	}

	var rules []pkg.ClaimRule
	for _, c := range params.Claims.Rules {
		rules = append(rules, model.FromSwagger(c))
	}

	err := fAPI.fedidpCtl.DeleteClaims(ctx, rules)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	return operation.NewDeleteClaimRulesOK()
}

func (fAPI *fedIDPAPI) CreateClaimRules(ctx context.Context, params operation.CreateClaimRulesParams) middleware.Responder {
	if err := fAPI.RequireAuthenticated(ctx); err != nil {
		return fAPI.SendError(ctx, err)
	}

	f := &pkg.FederatedIdp{
		ID: params.ID,
	}
	if err := fAPI.requireAccess(ctx, f, rbac.ActionCreate); err != nil {
		return fAPI.SendError(ctx, err)
	}

	if len(params.Claims.Rules) == 0 {
		return fAPI.SendError(ctx, errors.New(nil).WithMessage("no claim rules provided").WithCode(errors.BadRequestCode))
	}

	var rules []pkg.ClaimRule
	for _, c := range params.Claims.Rules {
		rules = append(rules, model.FromSwagger(c))
	}

	err := fAPI.fedidpCtl.CreateClaims(ctx, params.ID, rules)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	return operation.NewCreateClaimRulesCreated()
}

func (fAPI *fedIDPAPI) CreateFederatedIdp(ctx context.Context, params operation.CreateFederatedIdpParams) middleware.Responder {
	var (
		jwksKeys            string
		supportedAlgorithms string
		claimsSupported     string
	)

	if err := fAPI.validate(params.Idp); err != nil {
		return fAPI.SendError(ctx, err)
	}

	query := q.New(q.KeyWords{"name": params.Idp.Name})
	existing, err := fAPI.fedidpCtl.List(ctx, query)
	if err != nil {
		log.Errorf("failed to validate federatedidp name: %v", err)
		err := errors.New(err).WithMessagef(
			"failed to validate federatedidp name",
		).WithCode(errors.PreconditionCode)
		return fAPI.SendError(ctx, err)
	}

	if len(existing) > 0 {
		err := errors.
			ConflictError(nil).
			WithMessage("federatedidp with this name already exists")
		return fAPI.SendError(ctx, err)
	}

	if params.Idp.OfflineValidation {
		// assign jwksKeys
		jwksKeys = string(toRawMessage(params.Idp.JwksKeys))
	}

	// idp optional params validation
	if len(params.Idp.SupportedAlgorithms) > 0 {
		supportedAlgorithms = strings.Join(params.Idp.SupportedAlgorithms, ",")
	}
	if len(params.Idp.ClaimsSupported) > 0 {
		claimsSupported = strings.Join(params.Idp.ClaimsSupported, ",")
	}

	fIdp := &pkg.FederatedIdp{
		Name:                params.Idp.Name,
		Description:         params.Idp.Description,
		Issuer:              params.Idp.Issuer,
		OpenIDConfigURL:     params.Idp.OpenidConfigURL,
		JWKSURI:             params.Idp.JwksURI,
		JWKSKeys:            jwksKeys,
		OfflineValidation:   params.Idp.OfflineValidation,
		SupportedAlgorithms: supportedAlgorithms,
		ClaimsSupported:     claimsSupported,
		ProjectID:           params.Idp.ProjectID,
		CreationTime:        time.Now(),
		UpdateTime:          time.Now(),
	}

	if err := fAPI.requireAccess(ctx, fIdp, rbac.ActionCreate); err != nil {
		return fAPI.SendError(ctx, err)
	}

	fedIdpId, err := fAPI.fedidpCtl.Create(ctx, fIdp)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	created, err := fAPI.fedidpCtl.Get(ctx, fedIdpId)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	return operation.NewCreateFederatedIdpCreated().WithPayload(model.NewFederatedIdp(created).ToSwagger())
}

func (fAPI *fedIDPAPI) DeleteFederatedIdp(ctx context.Context, params operation.DeleteFederatedIdpParams) middleware.Responder {
	if err := fAPI.RequireAuthenticated(ctx); err != nil {
		return fAPI.SendError(ctx, err)
	}

	f, err := fAPI.fedidpCtl.Get(ctx, params.ID)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	if err := fAPI.requireAccess(ctx, f, rbac.ActionDelete); err != nil {
		return fAPI.SendError(ctx, err)
	}

	robotIdps, err := fAPI.fedidpCtl.ListRobotIdpByIdpID(ctx, params.ID)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	if len(robotIdps) > 0 {
		return fAPI.SendError(ctx, errors.New(nil).WithMessage("Please delete the associated robots before deleting the federated idp").WithCode(errors.BadRequestCode))
	}

	// for _, robotIdp := range robotIdps {
	// 	if err := fAPI.fedidpCtl.DeleteRobotIdpByRobotID(ctx, robotIdp.RobotID); err != nil {
	// 		return fAPI.SendError(ctx, err)
	// 	}
	// }

	if err := fAPI.fedidpCtl.Delete(ctx, params.ID); err != nil {
		return fAPI.SendError(ctx, err)
	}
	return operation.NewDeleteFederatedIdpOK()
}

func (fAPI *fedIDPAPI) ListFederatedIdps(ctx context.Context, params operation.ListFederatedIdpsParams) middleware.Responder {
	if err := fAPI.RequireAuthenticated(ctx); err != nil {
		return fAPI.SendError(ctx, err)
	}

	query, err := fAPI.BuildQuery(ctx, params.Q, params.Sort, params.Page, params.PageSize)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	var projectID int64
	var level string
	// GET /api/v2.0/federated-idp or GET /api/v2.0/federated-idp?q=Level=system to get all of system level federated idps.
	// GET /api/v2.0/federated-idp?q=Level=project to get all of project level federated idps.
	// GET /api/v2.0/federated-idp?q=Level=project,ProjectID=1
	if _, ok := query.Keywords["Level"]; ok {
		if !isValidLevel(query.Keywords["Level"].(string)) {
			return fAPI.SendError(ctx, errors.New(nil).WithMessage("bad request error level input").WithCode(errors.BadRequestCode))
		}
		level = query.Keywords["Level"].(string)
		if level == federated_idp.LEVELPROJECT {
			if _, ok := query.Keywords["ProjectID"]; !ok {
				return fAPI.SendError(ctx, errors.BadRequestError(nil).WithMessage("must with project ID when to query project robots"))
			}
			pid, err := strconv.ParseInt(query.Keywords["ProjectID"].(string), 10, 64)
			if err != nil || pid <= 0 {
				return fAPI.SendError(ctx, errors.BadRequestError(nil).WithMessage("ProjectID must be a positive integer"))
			}
			projectID = pid
		} else if level == federated_idp.LEVELSYSTEM {
			query.Keywords["ProjectID"] = 0
		}
	} else {
		level = federated_idp.LEVELSYSTEM
		query.Keywords["ProjectID"] = 0
	}

	f := &pkg.FederatedIdp{
		ProjectID: projectID,
	}
	if err := fAPI.requireAccess(ctx, f, rbac.ActionList); err != nil {
		return fAPI.SendError(ctx, err)
	}

	total, err := fAPI.fedidpCtl.Count(ctx, query)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	fIdps, err := fAPI.fedidpCtl.List(ctx, query)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	var results []*models.FederatedIdp
	for _, f := range fIdps {
		results = append(results, model.NewFederatedIdp(f).ToSwagger())
	}

	return operation.NewListFederatedIdpsOK().
		WithXTotalCount(total).
		WithLink(fAPI.Links(ctx, params.HTTPRequest.URL, total, query.PageNumber, query.PageSize).String()).
		WithPayload(results)
}

func (fAPI *fedIDPAPI) PingFederatedIdpJWKS(ctx context.Context, params operation.PingFederatedIdpJWKSParams) middleware.Responder {
	if err := fAPI.RequireAuthenticated(ctx); err != nil {
		return fAPI.SendError(ctx, err)
	}

	if err := fAPI.RequireSystemAccess(ctx, rbac.ActionRead, rbac.ResourceFederatedIdp); err != nil {
		return fAPI.SendError(ctx, err)
	}

	url, err := lib.ValidateURL(params.Jwks.JwksURI)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	// fetch jwks from url and return the jwks json
	resp, err := http.Get(url)
	if err != nil {
		return fAPI.SendError(ctx, fmt.Errorf("failed to fetch JWKS: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fAPI.SendError(ctx, fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode))
	}

	// Read body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fAPI.SendError(ctx, fmt.Errorf("failed to read JWKS response: %v", err))
	}

	// Return raw JSON directly
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return fAPI.SendError(ctx, fmt.Errorf("invalid JSON from JWKS endpoint: %v", err))
	}

	return operation.NewPingFederatedIdpJWKSOK().WithPayload(payload)
}

func (fAPI *fedIDPAPI) PingFederatedIdpOpenIDConfig(ctx context.Context, params operation.PingFederatedIdpOpenIDConfigParams) middleware.Responder {
	if err := fAPI.RequireAuthenticated(ctx); err != nil {
		return fAPI.SendError(ctx, err)
	}

	if err := fAPI.RequireSystemAccess(ctx, rbac.ActionRead, rbac.ResourceFederatedIdp); err != nil {
		return fAPI.SendError(ctx, err)
	}

	url, err := lib.ValidateURL(params.OpenidConfigURL.OpenidConfigURL)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	// Ensure the URL points to a proper OpenID configuration endpoint
	if !strings.HasSuffix(url, "/.well-known/openid-configuration") {
		return fAPI.SendError(ctx, fmt.Errorf("URL must end with '/.well-known/openid-configuration'"))
	}

	// Fetch OpenID Config JSON
	resp, err := http.Get(url)
	if err != nil {
		return fAPI.SendError(ctx, fmt.Errorf("failed to fetch OpenID configuration: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fAPI.SendError(ctx, fmt.Errorf("OpenID configuration endpoint returned %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fAPI.SendError(ctx, fmt.Errorf("failed to read OpenID configuration response: %v", err))
	}

	// Return raw JSON directly
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return fAPI.SendError(ctx, fmt.Errorf("invalid JSON from OpenID configuration endpoint: %v", err))
	}

	return operation.NewPingFederatedIdpOpenIDConfigOK().WithPayload(payload)
}

func (fAPI *fedIDPAPI) GetFederatedIdp(ctx context.Context, params operation.GetFederatedIdpParams) middleware.Responder {
	if err := fAPI.RequireAuthenticated(ctx); err != nil {
		return fAPI.SendError(ctx, err)
	}

	f, err := fAPI.fedidpCtl.Get(ctx, params.ID)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}
	if err := fAPI.requireAccess(ctx, f, rbac.ActionRead); err != nil {
		return fAPI.SendError(ctx, err)
	}

	return operation.NewGetFederatedIdpOK().WithPayload(model.NewFederatedIdp(f).ToSwagger())
}

func (fAPI *fedIDPAPI) UpdateFederatedIdp(ctx context.Context, params operation.UpdateFederatedIdpParams) middleware.Responder {
	var err error
	if err := fAPI.RequireAuthenticated(ctx); err != nil {
		return fAPI.SendError(ctx, err)
	}
	f, err := fAPI.fedidpCtl.Get(ctx, params.ID)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	err = fAPI.updateFedIdp(ctx, params, f)

	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	return operation.NewUpdateFederatedIdpOK()
}

func (fAPI *fedIDPAPI) requireAccess(ctx context.Context, f *pkg.FederatedIdp, action rbac.Action) error {
	if f.ProjectID > 0 {
		var ns any
		ns = f.ProjectID
		return fAPI.RequireProjectAccess(ctx, ns, action, rbac.ResourceFederatedIdp)
	} else if f.ProjectID == 0 {
		return fAPI.RequireSystemAccess(ctx, action, rbac.ResourceFederatedIdp)
	}
	return errors.ForbiddenError(nil)
}

// more validation
func (fAPI *fedIDPAPI) validate(fedIdp *models.FederatedIdp) error {

	// Validate IDP Name
	if err := validateFedIdpName(fedIdp.Name); err != nil {
		return err
	}

	// Validate Issuer URL
	if fedIdp.Issuer == "" {
		return errors.New(nil).WithMessage("invalid issuer: cannot be empty").WithCode(errors.BadRequestCode)
	}
	if !isValidIssuer(fedIdp.Issuer) {
		return errors.New(nil).WithMessagef(
			"invalid issuer URL: %q (must be a non-empty, valid HTTPS URL)", fedIdp.Issuer,
		).WithCode(errors.BadRequestCode)
	}

	log.Infof("fedIdp.OfflineValidation: %v", fedIdp.OfflineValidation)

	// Offline Validation Logic
	if fedIdp.OfflineValidation {
		log.Infof("inside validating for fedidp offline")
		// Check if keys exist
		if fedIdp.JwksKeys == nil {
			return errors.New(nil).WithMessage("offline validation requires JWKS keys").WithCode(errors.BadRequestCode)
		}
		// Validate JWKS Keys Format
		if err := validateJWKSKeys(fedIdp.JwksKeys); err != nil {
			return err
		}
	} else {
		log.Infof("inside validating for fedidp online what is wrong here")
		// Online Validation Logic
		// Validate OpenID Config URL
		if !isValidOpenIDConfigURL(fedIdp.OpenidConfigURL) {
			return errors.New(nil).WithMessagef(
				"invalid OpenID config URL: %q (must be a non-empty, valid HTTPS URL)", fedIdp.OpenidConfigURL,
			).WithCode(errors.BadRequestCode)
		}

		// Validate JWKS URI Format
		if err := validateJWKSURI(fedIdp.JwksURI); err != nil {
			return err
		}

		// Fetch the discovery document
		discovery, err := fetchOpenIDDiscovery(fedIdp.OpenidConfigURL)
		if err != nil {
			return errors.New(err).WithMessage("failed to fetch OpenID discovery document").WithCode(errors.BadRequestCode)
		}

		// Validate JWKS URI from discovery matches provided JWKS URI
		if fedIdp.JwksURI != "" && fedIdp.JwksURI != discovery.JWKSURI {
			return errors.New(nil).WithMessagef(
				"JWKS URI mismatch: provided=%q, discovery=%q", fedIdp.JwksURI, discovery.JWKSURI,
			).WithCode(errors.BadRequestCode)
		}

		log.Debugf("fedIdp.SupportedAlgorithms: %v", fedIdp.SupportedAlgorithms)
		log.Debugf("fedIdp.ClaimsSupported: %v", fedIdp.ClaimsSupported)
	}

	return nil
}

type OpenIDDiscovery struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

func fetchOpenIDDiscovery(url string) (*OpenIDDiscovery, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var discovery OpenIDDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, err
	}
	return &discovery, nil
}

func (fAPI *fedIDPAPI) updateFedIdp(ctx context.Context, params operation.UpdateFederatedIdpParams, f *pkg.FederatedIdp) error {
	if f != nil {
		f = applyUpdate(f, params.Idp)
	}

	if err := fAPI.validate(model.NewFederatedIdp(f).ToSwagger()); err != nil {
		return err
	}

	if err := fAPI.fedidpCtl.Update(ctx, f); err != nil {
		return err
	}
	return nil
}

func isValidIssuer(issuer string) bool {
	if issuer == "" {
		return false
	}
	url, err := lib.ValidateURL(issuer)
	if err != nil {
		return false
	}
	// Must be https and not empty
	return strings.HasPrefix(url, "https://")
}

func isValidOpenIDConfigURL(configURL string) bool {
	if configURL == "" {
		return false
	}
	_, err := lib.ValidateURL(configURL)
	if err != nil {
		return false
	}
	return true
}

func validateJWKSURI(jwksURI string) error {
	if jwksURI == "" {
		return nil // optional
	}
	_, err := lib.ValidateURL(jwksURI)
	if err != nil {
		return errors.BadRequestError(nil).WithMessage("invalid jwks_uri")
	}
	return nil
}

// --- JWKS Keys (offline validation) ---
func validateJWKSKeys(keys any) error {
	if keys == nil {
		return errors.BadRequestError(nil).
			WithMessage("jwks_keys must be provided when offline validation is enabled")
	}
	// Optional: attempt to marshal/unmarshal to ensure it's valid JSON
	_, err := json.Marshal(keys)
	if err != nil {
		return errors.BadRequestError(nil).
			WithMessage("invalid jwks_keys JSON structure")
	}
	return nil
}

// validateName validates the robot name, especially '+' cannot be a valid character
func validateFedIdpName(name string) error {
	federatedidpName := `^[a-z0-9]+(?:[._-][a-z0-9]+)*$`
	legal := regexp.MustCompile(federatedidpName).MatchString(name)
	if !legal {
		return errors.BadRequestError(nil).WithMessage("federatedidp name is not in lower case or contains illegal characters")
	}

	return nil
}

func toRawMessage(v any) json.RawMessage {
	switch val := v.(type) {
	case json.RawMessage:
		return val
	case []byte:
		return json.RawMessage(val)
	case string:
		return json.RawMessage([]byte(val))
	default:
		b, _ := json.Marshal(val) // fallback: encode to JSON
		return b
	}
}

// ApplyUpdate converts a FederatedIdpUpdate to pkg.FederatedIdp, applying only non-nil fields.
func applyUpdate(p *pkg.FederatedIdp, update *models.FederatedIdpUpdate) *pkg.FederatedIdp {
	if p == nil || update == nil {
		return p
	}

	// Update only non-nil fields
	if update.Name != nil {
		p.Name = *update.Name
	}
	if update.Description != nil {
		p.Description = *update.Description
	}
	if update.Issuer != nil {
		p.Issuer = *update.Issuer
	}
	if update.OpenidConfigURL != nil {
		p.OpenIDConfigURL = *update.OpenidConfigURL
	}
	if update.JwksURI != nil {
		p.JWKSURI = *update.JwksURI
	}
	if update.OfflineValidation != nil {
		p.OfflineValidation = *update.OfflineValidation
	}
	if update.ClaimsSupported != nil {
		p.ClaimsSupported = strings.Join(update.ClaimsSupported, ",")
	}
	if update.SupportedAlgorithms != nil {
		p.SupportedAlgorithms = strings.Join(update.SupportedAlgorithms, ",")
	}
	if update.JwksKeys != nil {
		// Convert any to json.RawMessage string
		raw, err := json.Marshal(update.JwksKeys)
		if err == nil {
			p.JWKSKeys = string(raw)
		}
	}

	return p
}

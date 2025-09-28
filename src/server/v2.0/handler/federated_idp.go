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
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-openapi/runtime/middleware"

	"github.com/goharbor/harbor/src/common/rbac"

	// robotSc "github.com/goharbor/harbor/src/common/security/robot"

	// robotSc "github.com/goharbor/harbor/src/common/security/robot"
	"github.com/goharbor/harbor/src/common/utils"
	federated_idp "github.com/goharbor/harbor/src/controller/federatedidp"
	"github.com/goharbor/harbor/src/controller/robot"
	"github.com/goharbor/harbor/src/lib"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/pkg/permission/types"
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

func (fAPI *fedIDPAPI) CreateFederatedIdp(ctx context.Context, params operation.CreateFederatedIdpParams) middleware.Responder {
	if err := validateName(params.Idp.Name); err != nil {
		return fAPI.SendError(ctx, err)
	}

	if err := fAPI.validate(params.Idp); err != nil {
		return fAPI.SendError(ctx, err)
	}

	fIdp := &models.FederatedIdp{
		Name:                params.Idp.Name,
		Description:         params.Idp.Description,
		Issuer:              params.Idp.Issuer,
		OpenidConfigURL:     params.Idp.OpenidConfigURL,
		JwksURI:             params.Idp.JwksURI,
		JwksKeys:            toRawMessage(params.Idp.JwksKeys),
		OfflineValidation:   params.Idp.OfflineValidation,
		SupportedAlgorithms: params.Idp.SupportedAlgorithms,
		ClaimsSupported:     params.Idp.ClaimsSupported,
		ProjectID:           params.Idp.ProjectID,
		UpdateTime:          time.Now(),
	}

	if err := fAPI.requireAccess(ctx, fIdp, rbac.ActionCreate); err != nil {
		return fAPI.SendError(ctx, err)
	}

	_, err := fAPI.fedidpCtl.Create(ctx, fIdp)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	// TODO: check if we need the location
	// location := fmt.Sprintf("%s/%d", strings.TrimSuffix(params.HTTPRequest.URL.Path, "/"), created.ID)
	return operation.NewCreateFederatedIdpCreated()
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

	f := &models.FederatedIdp{
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
		results = append(results, f)
	}

	return operation.NewListFederatedIdpsOK().
		WithXTotalCount(total).
		WithLink(fAPI.Links(ctx, params.HTTPRequest.URL, total, query.PageNumber, query.PageSize).String()).
		WithPayload(results)
}

func (fAPI *fedIDPAPI) GetRobotByID(ctx context.Context, params operation.GetRobotByIDParams) middleware.Responder {
	if err := fAPI.RequireAuthenticated(ctx); err != nil {
		return fAPI.SendError(ctx, err)
	}

	r, err := fAPI.robotCtl.Get(ctx, params.RobotID, &robot.Option{
		WithPermission: true,
	})
	if err != nil {
		return fAPI.SendError(ctx, err)
	}
	if err := fAPI.requireAccess(ctx, r, rbac.ActionRead); err != nil {
		return fAPI.SendError(ctx, err)
	}

	return operation.NewGetRobotByIDOK().WithPayload(model.NewRobot(r).ToSwagger())
}

func (fAPI *fedIDPAPI) UpdateRobot(ctx context.Context, params operation.UpdateRobotParams) middleware.Responder {
	var err error
	if err := fAPI.RequireAuthenticated(ctx); err != nil {
		return fAPI.SendError(ctx, err)
	}
	r, err := fAPI.robotCtl.Get(ctx, params.RobotID, &robot.Option{
		WithPermission: true,
	})
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	if !r.Editable {
		err = errors.DeniedError(nil).WithMessage("editing of legacy robot is not allowed")
	} else {
		err = fAPI.updateV2Robot(ctx, params, r)
	}
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	return operation.NewUpdateRobotOK()
}

func (fAPI *fedIDPAPI) RefreshSec(ctx context.Context, params operation.RefreshSecParams) middleware.Responder {
	if err := fAPI.RequireAuthenticated(ctx); err != nil {
		return fAPI.SendError(ctx, err)
	}

	r, err := fAPI.robotCtl.Get(ctx, params.RobotID, nil)
	if err != nil {
		return fAPI.SendError(ctx, err)
	}

	if err := fAPI.requireAccess(ctx, r, rbac.ActionUpdate); err != nil {
		return fAPI.SendError(ctx, err)
	}

	var secret string
	robotSec := &models.RobotSec{}
	if params.RobotSec.Secret != "" {
		if !robot.IsValidSec(params.RobotSec.Secret) {
			return fAPI.SendError(ctx, errors.New("the secret must be 8-128, inclusively, characters long with at least 1 uppercase letter, 1 lowercase letter and 1 number").WithCode(errors.BadRequestCode))
		}
		secret = utils.Encrypt(params.RobotSec.Secret, r.Salt, utils.SHA256)
		robotSec.Secret = ""
	} else {
		sec, pwd, _, err := robot.CreateSec(r.Salt)
		if err != nil {
			return fAPI.SendError(ctx, err)
		}
		secret = sec
		robotSec.Secret = pwd
	}

	r.Secret = secret
	if err := fAPI.robotCtl.Update(ctx, r, nil); err != nil {
		return fAPI.SendError(ctx, err)
	}

	return operation.NewRefreshSecOK().WithPayload(robotSec)
}

func (fAPI *fedIDPAPI) requireAccess(ctx context.Context, f *models.FederatedIdp, action rbac.Action) error {
	if f.ProjectID > 0 {
		var ns interface{}
		ns = f.ProjectID
		return fAPI.RequireProjectAccess(ctx, ns, action, rbac.ResourceFederatedIdp)
	} else if f.ProjectID == 0 {
		return fAPI.RequireSystemAccess(ctx, action, rbac.ResourceFederatedIdp)
	}
	return errors.ForbiddenError(nil)
}

// more validation
func (fAPI *fedIDPAPI) validate(fedIdp *models.FederatedIdp) error {
	if !isValidIssuer(fedIdp.Issuer) {
		return errors.New(nil).WithMessagef("invalid issuer URL: %q (must be a non-empty, valid HTTPS URL)", fedIdp.Issuer).WithCode(errors.BadRequestCode)
	}

	if fedIdp.OfflineValidation {
		// is valid jwks-key
	} else {
		// is valid openid config url
		if !isValidOpenIDConfigURL(fedIdp.OpenidConfigURL) {
			return errors.New(nil).WithMessagef("invalid openid config URL: %q (must be a non-empty, valid HTTPS URL)", fedIdp.OpenidConfigURL).WithCode(errors.BadRequestCode)
		}
		// fetch discovery document and validate

		// is valid jwks-uri
		// is supported algo && claims supported
	}

	if !isValidLevel(level) {
		return errors.New(nil).WithMessagef("bad request error level input: %s", level).WithCode(errors.BadRequestCode)
	}

	if len(permissions) == 0 {
		return errors.New(nil).WithMessage("bad request empty permission").WithCode(errors.BadRequestCode)
	}

	for _, perm := range permissions {
		if len(perm.Access) == 0 {
			return errors.New(nil).WithMessage("bad request empty access").WithCode(errors.BadRequestCode)
		}
	}

	// to create a project robot, the permission must be only one project scope.
	if level == robot.LEVELPROJECT && len(permissions) > 1 {
		return errors.New(nil).WithMessage("bad request permission").WithCode(errors.BadRequestCode)
	}

	provider := rbac.GetPermissionProvider()
	// to validate the access scope
	for _, perm := range permissions {
		if perm.Kind == robot.LEVELSYSTEM {
			polices := provider.GetPermissions(rbac.ScopeSystem)
			for _, acc := range perm.Access {
				if !containsAccess(polices, acc) {
					return errors.New(nil).WithMessagef("bad request permission: %s:%s", acc.Resource, acc.Action).WithCode(errors.BadRequestCode)
				}
			}
		} else if perm.Kind == robot.LEVELPROJECT {
			polices := provider.GetPermissions(rbac.ScopeProject)
			for _, acc := range perm.Access {
				if !containsAccess(polices, acc) {
					return errors.New(nil).WithMessagef("bad request permission: %s:%s", acc.Resource, acc.Action).WithCode(errors.BadRequestCode)
				}
			}
		} else {
			return errors.New(nil).WithMessagef("bad request permission level: %s", perm.Kind).WithCode(errors.BadRequestCode)
		}
	}

	return nil
}

func (fAPI *fedIDPAPI) updateV2Robot(ctx context.Context, params operation.UpdateRobotParams, r *robot.Robot) error {
	if params.Robot.Duration == nil {
		params.Robot.Duration = &r.Duration
	}
	if err := fAPI.validate(*params.Robot.Duration, params.Robot.Level, params.Robot.Permissions); err != nil {
		return err
	}
	if r.Level != robot.LEVELSYSTEM {
		projectID, err := getProjectID(ctx, params.Robot.Permissions[0].Namespace)
		if err != nil {
			return err
		}
		if r.ProjectID != projectID {
			return errors.BadRequestError(nil).WithMessage("cannot update the project id of robot")
		}
	}
	r.ProjectNameOrID = params.Robot.Permissions[0].Namespace
	if err := fAPI.requireAccess(ctx, r, rbac.ActionUpdate); err != nil {
		return err
	}
	if params.Robot.Level != r.Level || params.Robot.Name != r.Name {
		return errors.BadRequestError(nil).WithMessage("cannot update the level or name of robot")
	}

	if r.Duration != *params.Robot.Duration {
		r.Duration = *params.Robot.Duration
		if *params.Robot.Duration == -1 {
			r.ExpiresAt = -1
		} else {
			r.ExpiresAt = r.CreationTime.AddDate(0, 0, int(*params.Robot.Duration)).Unix()
		}
	}

	r.Description = params.Robot.Description
	r.Disabled = params.Robot.Disable
	if len(params.Robot.Permissions) != 0 {
		if err := lib.JSONCopy(&r.Permissions, params.Robot.Permissions); err != nil {
			log.Warningf("failed to call JSONCopy on robot permission when updateV2Robot, error: %v", err)
		}
	}

	if err := fAPI.robotCtl.Update(ctx, r, &robot.Option{
		WithPermission: true,
	}); err != nil {
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

func validateJWKSURI(jwksURI string) (string, error) {
	if jwksURI == "" {
		return "", nil // optional
	}
	url, err := lib.ValidateURL(jwksURI)
	if err != nil {
		return "", errors.BadRequestError(nil).WithMessage("invalid jwks_uri")
	}
	return url, nil
}

// --- JWKS Keys (offline validation) ---
func validateJWKSKeys(keys interface{}) error {
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

// --- Supported Algorithms ---
func validateSupportedAlgorithms(algs []string) error {
	allowedAlgs := map[string]bool{
		"RS256": true, "RS384": true, "RS512": true,
		"ES256": true, "ES384": true, "ES512": true,
		"PS256": true, "PS384": true, "PS512": true,
	}
	for _, alg := range algs {
		if !allowedAlgs[alg] {
			return errors.BadRequestError(nil).
				WithMessage(fmt.Sprintf("unsupported or insecure signing algorithm: %s", alg))
		}
	}
	return nil
}

// --- Supported Claims ---
func validateClaimsSupported(claims []string) error {
	// Example: restrict to common claims; adjust based on your needs
	allowedClaims := map[string]bool{
		"sub": true, "email": true, "name": true, "groups": true,
	}
	for _, claim := range claims {
		if !allowedClaims[claim] {
			return errors.BadRequestError(nil).
				WithMessage(fmt.Sprintf("unsupported claim: %s", claim))
		}
	}
	return nil
}

func isValidLevel(l string) bool {
	return l == robot.LEVELSYSTEM || l == robot.LEVELPROJECT
}

func isValidDuration(d int64) bool {
	return d == -1 || (d > 0 && d < math.MaxInt32)
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

func containsAccess(policies []*types.Policy, item *models.Access) bool {
	for _, po := range policies {
		if po.Resource.String() == item.Resource && po.Action.String() == item.Action {
			return true
		}
	}
	return false
}

// isValidPermissionScope checks if permission slice A is a subset of permission slice B
func isValidPermissionScope(creating []*models.RobotPermission, creator []*robot.Permission) bool {
	creatorMap := make(map[string]*robot.Permission)
	for _, creatorPerm := range creator {
		key := fmt.Sprintf("%s:%s", creatorPerm.Kind, creatorPerm.Namespace)
		creatorMap[key] = creatorPerm
	}

	hasLessThanOrEqualAccess := func(creating []*models.Access, creator []*types.Policy) bool {
		creatorMap := make(map[string]*types.Policy)
		for _, creatorP := range creator {
			key := fmt.Sprintf("%s:%s:%s", creatorP.Resource, creatorP.Action, creatorP.Effect)
			creatorMap[key] = creatorP
		}
		for _, creatingP := range creating {
			key := fmt.Sprintf("%s:%s:%s", creatingP.Resource, creatingP.Action, creatingP.Effect)
			if _, found := creatorMap[key]; !found {
				return false
			}
		}
		return true
	}

	for _, pCreating := range creating {
		key := fmt.Sprintf("%s:%s", pCreating.Kind, pCreating.Namespace)
		creatorPerm, found := creatorMap[key]
		if !found {
			allProjects := fmt.Sprintf("%s:*", pCreating.Kind)
			if creatorPerm, found = creatorMap[allProjects]; !found {
				return false
			}
		}
		if !hasLessThanOrEqualAccess(pCreating.Access, creatorPerm.Access) {
			return false
		}
	}
	return true
}
func toRawMessage(v interface{}) json.RawMessage {
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

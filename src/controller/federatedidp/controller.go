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

package federated_idp

import (
	"context"

	"github.com/goharbor/harbor/src/lib"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/q"
	"github.com/goharbor/harbor/src/pkg"
	"github.com/goharbor/harbor/src/pkg/federatedidp"
	"github.com/goharbor/harbor/src/pkg/federatedidp/model"
	"github.com/goharbor/harbor/src/pkg/project"
	"github.com/goharbor/harbor/src/pkg/replication"
	"github.com/golang-jwt/jwt/v5"
)

// Ctl is a global registry controller instance
var Ctl = NewController()

type Controller interface {
	// Create the federated idp
	Create(ctx context.Context, federatedIdp *model.FederatedIdp) (id int64, err error)
	// Count returns the count of federated idps according to the query
	Count(ctx context.Context, query *q.Query) (count int64, err error)
	// List federated idps according to the query
	List(ctx context.Context, query *q.Query) (federatedIdps []*model.FederatedIdp, err error)
	// Get the federated idp specified by ID
	Get(ctx context.Context, id int64) (federatedIdp *model.FederatedIdp, err error)
	// Get the federated idp specified by IDP Name
	GetIdpByIssuer(ctx context.Context, issuer string) (federatedIdp *model.FederatedIdp, err error)
	// GetTopMatchedRobot ...
	GetTopMatchedRobot(ctx context.Context, issuerID int64, tokenClaims jwt.MapClaims) (int64, error)
	// Update the specified federated idp
	Update(ctx context.Context, federatedIdp *model.FederatedIdp, props ...string) (err error)
	// Delete the federated idp specified by ID
	Delete(ctx context.Context, id int64) (err error)
	// ListClaims returns all the claims associated with federated idp specified by ID
	ListClaims(ctx context.Context, id int64, claim_path string) (claims []model.ClaimRule, err error)
	// ListClaimsIdpOnly returns the claims of the federated idp only specified by ID
	ListClaimsIdpOnly(ctx context.Context, id int64, claim_path string) (claims []model.ClaimRule, err error)
	// CreateClaims creates the claims
	CreateClaims(ctx context.Context, idpID int64, claims []model.ClaimRule) (err error)
	// DeleteClaims deletes the claims according to the query
	DeleteClaims(ctx context.Context, claims []model.ClaimRule) (err error)
	// CreateRobotIdp creates a new RobotIdentityProvider record
	CreateRobotIdp(ctx context.Context, idpID, robotID int64) (int64, error)
	// DeleteRobotIdpByIdpID deletes a RobotIdentityProvider record
	DeleteRobotIdpByIdpID(ctx context.Context, idpID int64) error
	// DeleteRobotIdpByRobotID deletes a RobotIdentityProvider record
	DeleteRobotIdpByRobotID(ctx context.Context, robotID int64) error
	// DeleteClaimRulesByRobotID deletes all claim_rules records associated with a given robot ID
	DeleteClaimRulesByRobotID(ctx context.Context, robotID int64) error
	// HasRobotIdpByRobotID checks if a given robot has at least one associated identity provider.
	HasRobotIdpByRobotID(ctx context.Context, robotID int64) (bool, error)
	// ListRobotIdpByIdpID lists all robot_identity_providers associated with the given IDP ID
	ListRobotIdpByIdpID(ctx context.Context, idpID int64) ([]model.RobotIdentityProvider, error)
}

// NewController creates an instance of the federated idp controller
func NewController() Controller {
	return &controller{
		fidpMgr: federatedidp.Mgr,
		proMgr:  pkg.ProjectMgr,
	}
}

type controller struct {
	fidpMgr federatedidp.Manager
	repMgr  replication.Manager
	proMgr  project.Manager
}

func (c *controller) Create(ctx context.Context, federatedidp *model.FederatedIdp) (int64, error) {
	if err := c.validate(ctx, federatedidp); err != nil {
		return 0, err
	}
	return c.fidpMgr.Create(ctx, federatedidp)
}

func (c *controller) validate(ctx context.Context, fed *model.FederatedIdp) error {
	if len(fed.Name) == 0 {
		return errors.New(nil).WithCode(errors.BadRequestCode).
			WithMessage("name cannot be empty")
	}
	if len(fed.Name) > 64 {
		return errors.New(nil).WithCode(errors.BadRequestCode).
			WithMessage("the max length of name is 64")
	}
	if len(fed.Issuer) == 0 {
		return errors.New(nil).WithCode(errors.BadRequestCode).
			WithMessage("issuer cannot be empty")
	}
	issuerURL, err := lib.ValidateURL(fed.Issuer)
	if err != nil {
		return errors.New(nil).WithCode(errors.BadRequestCode).
			WithMessage("invalid issuer URL")
	}
	fed.Issuer = issuerURL
	if len(fed.OpenIDConfigURL) > 0 {
		url, err := lib.ValidateURL(fed.OpenIDConfigURL)
		if err != nil {
			return errors.New(nil).WithCode(errors.BadRequestCode).
				WithMessage("invalid openid_config_url")
		}
		fed.OpenIDConfigURL = url
	}
	if fed.OfflineValidation {
		// Validate JWKS URI
		if len(fed.JWKSURI) == 0 {
			return errors.New(nil).WithCode(errors.BadRequestCode).
				WithMessage("invalid jwks_uri")
		} else {
			url, err := lib.ValidateURL(fed.JWKSURI)
			if err != nil {
				return errors.New(nil).WithCode(errors.BadRequestCode).
					WithMessage("invalid jwks_uri")
			}
			fed.JWKSURI = url
		}
		// check for jwks_keys
		if len(fed.JWKSKeys) == 0 {
			return errors.New(nil).WithCode(errors.BadRequestCode).
				WithMessage("invalid jwks_keys")
		}
	}
	// Validate Project ID
	if fed.ProjectID < 0 {
		return errors.New(nil).WithCode(errors.BadRequestCode).
			WithMessage("project_id must be set (use 0 for system level)")
	}

	return nil
}

func (c *controller) Count(ctx context.Context, query *q.Query) (int64, error) {
	return c.fidpMgr.Count(ctx, query)
}

func (c *controller) List(ctx context.Context, query *q.Query) ([]*model.FederatedIdp, error) {
	return c.fidpMgr.List(ctx, query)
}

func (c *controller) Get(ctx context.Context, id int64) (*model.FederatedIdp, error) {
	return c.fidpMgr.Get(ctx, id)
}

func (c *controller) GetIdpByIssuer(ctx context.Context, issuer string) (*model.FederatedIdp, error) {
	return c.fidpMgr.GetIdpByIssuer(ctx, issuer)
}

func (c *controller) GetTopMatchedRobot(ctx context.Context, issuerID int64, tokenClaims jwt.MapClaims) (int64, error) {
	return c.fidpMgr.GetTopMatchedRobot(ctx, issuerID, tokenClaims)
}

func (c *controller) Update(ctx context.Context, registry *model.FederatedIdp, props ...string) error {
	if err := c.validate(ctx, registry); err != nil {
		return err
	}
	return c.fidpMgr.Update(ctx, registry, props...)
}

func (c *controller) Delete(ctx context.Context, id int64) error {
	return c.fidpMgr.Delete(ctx, id)
}

func (c *controller) ListClaims(ctx context.Context, id int64, claim_path string) ([]model.ClaimRule, error) {
	return c.fidpMgr.ListClaims(ctx, id, claim_path)
}

func (c *controller) ListClaimsIdpOnly(ctx context.Context, id int64, claim_path string) ([]model.ClaimRule, error) {
	return c.fidpMgr.ListClaimsIdpOnly(ctx, id, claim_path)
}

func (c *controller) CreateClaims(ctx context.Context, idpID int64, claims []model.ClaimRule) error {
	return c.fidpMgr.CreateClaims(ctx, idpID, claims)
}

func (c *controller) DeleteClaims(ctx context.Context, claims []model.ClaimRule) error {
	return c.fidpMgr.DeleteClaims(ctx, claims)
}

func (c *controller) CreateRobotIdp(ctx context.Context, idpID, robotID int64) (int64, error) {
	idp := &model.RobotIdentityProvider{
		IdentityProviderID: idpID,
		RobotID:            robotID,
	}
	return c.fidpMgr.CreateRobotIdp(ctx, idp)
}

func (c *controller) DeleteRobotIdpByIdpID(ctx context.Context, idpID int64) error {
	return c.fidpMgr.DeleteRobotIdpByIdpID(ctx, idpID)
}

func (c *controller) DeleteRobotIdpByRobotID(ctx context.Context, robotID int64) error {
	return c.fidpMgr.DeleteRobotIdpByRobotID(ctx, robotID)
}

func (c *controller) HasRobotIdpByRobotID(ctx context.Context, robotID int64) (bool, error) {
	return c.fidpMgr.HasRobotIdpByRobotID(ctx, robotID)
}

func (c *controller) ListRobotIdpByIdpID(ctx context.Context, idpID int64) ([]model.RobotIdentityProvider, error) {
	return c.fidpMgr.ListRobotIdpByIdpID(ctx, idpID)
}

func (c *controller) DeleteClaimRulesByRobotID(ctx context.Context, robotID int64) error {
	return c.fidpMgr.DeleteClaimRulesByRobotID(ctx, robotID)
}

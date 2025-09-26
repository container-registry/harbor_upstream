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
	"time"

	"github.com/goharbor/harbor/src/lib"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/q"
	"github.com/goharbor/harbor/src/pkg"
	"github.com/goharbor/harbor/src/pkg/federatedidp"
	"github.com/goharbor/harbor/src/pkg/federatedidp/model"
	"github.com/goharbor/harbor/src/pkg/project"
	"github.com/goharbor/harbor/src/pkg/replication"
)

// Ctl is a global registry controller instance
var Ctl = NewController()
var regularHealthCheckInterval = 5 * time.Minute

type Controller interface {
	// Create the federated idp
	Create(ctx context.Context, federatedIdp *model.FederatedIdp) (id int64, err error)
	// Count returns the count of federated idps according to the query
	Count(ctx context.Context, query *q.Query) (count int64, err error)
	// List federated idps according to the query
	List(ctx context.Context, query *q.Query) (federatedIdps []*model.FederatedIdp, err error)
	// Get the federated idp specified by ID
	Get(ctx context.Context, id int64) (federatedIdp *model.FederatedIdp, err error)
	// Update the specified federated idp
	Update(ctx context.Context, federatedIdp *model.FederatedIdp, props ...string) (err error)
	// Delete the federated idp specified by ID
	Delete(ctx context.Context, id int64) (err error)
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
	} else {
		return errors.New(nil).WithCode(errors.BadRequestCode).
			WithMessage("Invalid federated idp configuration")
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

func (c *controller) Update(ctx context.Context, registry *model.FederatedIdp, props ...string) error {
	if err := c.validate(ctx, registry); err != nil {
		return err
	}
	return c.fidpMgr.Update(ctx, registry, props...)
}

func (c *controller) Delete(ctx context.Context, id int64) error {
	return c.fidpMgr.Delete(ctx, id)
}

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

package dao

import (
	"context"
	"time"

	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/orm"
	"github.com/goharbor/harbor/src/lib/q"
	"github.com/goharbor/harbor/src/pkg/federatedidp/model"
)

// DAO defines the interface to access the federatedidp data model
type DAO interface {
	// Create ...
	Create(ctx context.Context, r *model.FederatedIdp) (int64, error)

	// Update ...
	Update(ctx context.Context, r *model.FederatedIdp, props ...string) error

	// Get ...
	Get(ctx context.Context, id int64) (*model.FederatedIdp, error)

	// Count returns the total count of federatedidps according to the query
	Count(ctx context.Context, query *q.Query) (total int64, err error)

	// List ...
	List(ctx context.Context, query *q.Query) ([]*model.FederatedIdp, error)

	// Delete ...
	Delete(ctx context.Context, id int64) error

	// DeleteByProjectID ...
	DeleteByProjectID(ctx context.Context, projectID int64) error

	// ListClaims ...
	ListClaims(ctx context.Context, id int64, claim_path string) ([]model.ClaimRule, error)

	// CreateClaims ...
	CreateClaims(ctx context.Context, claims []model.ClaimRule) error
}

// New creates a default implementation for Dao
func New() DAO {
	return &dao{}
}

type dao struct{}

func (d *dao) Create(ctx context.Context, f *model.FederatedIdp) (int64, error) {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return 0, err
	}
	f.CreationTime = time.Now()
	id, err := ormer.Insert(f)
	if err != nil {
		// Check for unique constraint violation (issuer already exists)
		return 0, orm.WrapConflictError(err, "federated idp %d:%s already exists", f.ProjectID, f.Name)
	}
	return id, err
}

func (d *dao) Update(ctx context.Context, f *model.FederatedIdp, props ...string) error {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}
	n, err := ormer.Update(f, props...)
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.NotFoundError(nil).WithMessagef("federatedidp %d not found", f.ID)
	}
	return nil
}

func (d *dao) Get(ctx context.Context, id int64) (*model.FederatedIdp, error) {
	f := &model.FederatedIdp{
		ID: id,
	}
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := ormer.Read(f); err != nil {
		return nil, orm.WrapNotFoundError(err, "federatedidp %d not found", id)
	}
	return f, nil
}

func (d *dao) Count(ctx context.Context, query *q.Query) (int64, error) {
	qs, err := orm.QuerySetterForCount(ctx, &model.FederatedIdp{}, query)
	if err != nil {
		return 0, err
	}
	return qs.Count()
}

func (d *dao) Delete(ctx context.Context, id int64) error {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}
	n, err := ormer.Delete(&model.FederatedIdp{
		ID: id,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.NotFoundError(nil).WithMessagef("federatedidp %d not found", id)
	}
	return nil
}

func (d *dao) List(ctx context.Context, query *q.Query) ([]*model.FederatedIdp, error) {
	federatedidps := []*model.FederatedIdp{}

	qs, err := orm.QuerySetter(ctx, &model.FederatedIdp{}, query)
	if err != nil {
		return nil, err
	}
	if _, err = qs.All(&federatedidps); err != nil {
		return nil, err
	}
	return federatedidps, nil
}

func (d *dao) DeleteByProjectID(ctx context.Context, projectID int64) error {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}

	_, err = ormer.Raw("DELETE FROM identity_providers WHERE project_id = ?", projectID).Exec()

	return err
}

func (d *dao) ListClaims(ctx context.Context, id int64, claimPath string) ([]model.ClaimRule, error) {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	qs := ormer.QueryTable(new(model.ClaimRule)).Filter("identity_provider_id", id)

	if claimPath != "" {
		qs = qs.Filter("claim_path", claimPath)
	}

	var rules []model.ClaimRule
	_, err = qs.All(&rules)
	return rules, err
}

// CreateClaims inserts multiple ClaimRule records into the DB
func (d *dao) CreateClaims(ctx context.Context, claims []model.ClaimRule) error {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}

	if len(claims) == 0 {
		return nil // nothing to insert
	}

	// InsertMulti takes (bulkSize, slice)
	_, err = ormer.InsertMulti(len(claims), claims)
	return err
}

// DeleteClaim deletes a claim rule by IdentityProviderID+ClaimPath or RobotID+ClaimPath
func (d *dao) DeleteClaim(ctx context.Context, claim model.ClaimRule) error {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}

	if (claim.IdentityProviderID == 0 && claim.RobotID == 0) || claim.ClaimPath == "" {
		return errors.New(nil).WithCode(errors.BadRequestCode).
			WithMessage("invalid claim rule: missing identifiers or claim path")
	}

	qs := ormer.QueryTable(new(model.ClaimRule))

	// apply filter based on which ID is provided
	if claim.RobotID > 0 {
		qs = qs.Filter("robot_id", claim.RobotID)
	} else if claim.IdentityProviderID > 0 {
		qs = qs.Filter("identity_provider_id", claim.IdentityProviderID)
	}

	qs = qs.Filter("claim_path", claim.ClaimPath)

	count, err := qs.Count()
	if err != nil {
		return err
	}

	if count == 0 {
		return errors.New(nil).WithCode(errors.NotFoundCode).
			WithMessage("claim rule not found")
	} else if count > 1 {
		return errors.New(nil).WithCode(errors.BadRequestCode).
			WithMessage("multiple claim rules found, cannot delete, give more specific claim rule")
  }

	// delete matching record(s)
	num, err := qs.Delete()
	if err != nil {
		return err
	}

	if num == 0 {
		return errors.New(nil).WithCode(errors.NotFoundCode).
			WithMessage("claim rule not found")
	}

	return nil
}

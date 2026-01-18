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

	"github.com/goharbor/harbor/src/lib/orm"
	"github.com/goharbor/harbor/src/lib/q"
	"github.com/goharbor/harbor/src/pkg/tenant/model"
)

// DAO is the data access object interface for tenant
type DAO interface {
	// Create creates a new tenant
	Create(ctx context.Context, tenant *model.Tenant) (int64, error)
	// Get gets a tenant by ID
	Get(ctx context.Context, id int64) (*model.Tenant, error)
	// GetBySlug gets a tenant by slug
	GetBySlug(ctx context.Context, slug string) (*model.Tenant, error)
	// List lists tenants
	List(ctx context.Context, query *q.Query) ([]*model.Tenant, error)
	// Update updates a tenant
	Update(ctx context.Context, tenant *model.Tenant, props ...string) error
	// Delete deletes a tenant by ID
	Delete(ctx context.Context, id int64) error

	// Domain operations
	// CreateDomain creates a new domain mapping
	CreateDomain(ctx context.Context, domain *model.TenantDomain) (int64, error)
	// GetDomainByName gets a domain mapping by domain name
	GetDomainByName(ctx context.Context, domain string) (*model.TenantDomain, error)
	// ListDomainsByTenant lists all domains for a tenant
	ListDomainsByTenant(ctx context.Context, tenantID int64) ([]*model.TenantDomain, error)
	// DeleteDomain deletes a domain mapping
	DeleteDomain(ctx context.Context, id int64) error
}

// New creates a new tenant DAO
func New() DAO {
	return &dao{}
}

type dao struct{}

func (d *dao) Create(ctx context.Context, tenant *model.Tenant) (int64, error) {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return 0, err
	}
	return o.Insert(tenant)
}

func (d *dao) Get(ctx context.Context, id int64) (*model.Tenant, error) {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	tenant := &model.Tenant{ID: id}
	if err := o.Read(tenant); err != nil {
		return nil, err
	}
	return tenant, nil
}

func (d *dao) GetBySlug(ctx context.Context, slug string) (*model.Tenant, error) {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	tenant := &model.Tenant{Slug: slug}
	if err := o.Read(tenant, "slug"); err != nil {
		return nil, err
	}
	return tenant, nil
}

func (d *dao) List(ctx context.Context, query *q.Query) ([]*model.Tenant, error) {
	qs, err := orm.QuerySetter(ctx, &model.Tenant{}, query)
	if err != nil {
		return nil, err
	}
	var tenants []*model.Tenant
	if _, err := qs.All(&tenants); err != nil {
		return nil, err
	}
	return tenants, nil
}

func (d *dao) Update(ctx context.Context, tenant *model.Tenant, props ...string) error {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}
	if len(props) > 0 {
		_, err = o.Update(tenant, props...)
	} else {
		_, err = o.Update(tenant)
	}
	return err
}

func (d *dao) Delete(ctx context.Context, id int64) error {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}
	_, err = o.Delete(&model.Tenant{ID: id})
	return err
}

// Domain operations

func (d *dao) CreateDomain(ctx context.Context, domain *model.TenantDomain) (int64, error) {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return 0, err
	}
	return o.Insert(domain)
}

func (d *dao) GetDomainByName(ctx context.Context, domain string) (*model.TenantDomain, error) {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	td := &model.TenantDomain{Domain: domain}
	if err := o.Read(td, "domain"); err != nil {
		return nil, err
	}
	return td, nil
}

func (d *dao) ListDomainsByTenant(ctx context.Context, tenantID int64) ([]*model.TenantDomain, error) {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	var domains []*model.TenantDomain
	_, err = o.QueryTable(&model.TenantDomain{}).Filter("tenant_id", tenantID).All(&domains)
	if err != nil {
		return nil, err
	}
	return domains, nil
}

func (d *dao) DeleteDomain(ctx context.Context, id int64) error {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}
	_, err = o.Delete(&model.TenantDomain{ID: id})
	return err
}

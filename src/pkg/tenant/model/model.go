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

package model

import (
	"time"

	"github.com/beego/beego/v2/client/orm"
)

func init() {
	orm.RegisterModel(&Tenant{})
	orm.RegisterModel(&TenantDomain{})
}

// Tenant represents an organization/customer that can have multiple projects
type Tenant struct {
	ID           int64     `orm:"pk;auto;column(id)" json:"id"`
	Name         string    `orm:"column(name)" json:"name"`
	Slug         string    `orm:"column(slug)" json:"slug"` // URL-safe identifier for subdomain
	Status       string    `orm:"column(status)" json:"status"` // active, suspended, deleted
	Metadata     string    `orm:"column(metadata);type(jsonb)" json:"metadata"`
	CreationTime time.Time `orm:"column(creation_time);auto_now_add" json:"creation_time"`
	UpdateTime   time.Time `orm:"column(update_time);auto_now" json:"update_time"`
}

// TableName returns the table name for Tenant
func (t *Tenant) TableName() string {
	return "tenant"
}

// TenantDomain maps custom domains to tenants
// Supports both subdomain matching and custom domain mapping
type TenantDomain struct {
	ID           int64     `orm:"pk;auto;column(id)" json:"id"`
	TenantID     int64     `orm:"column(tenant_id)" json:"tenant_id"`
	Domain       string    `orm:"column(domain);unique" json:"domain"` // e.g., "registry.acme.com" or "acme" (for acme.harbor.io)
	DomainType   string    `orm:"column(domain_type)" json:"domain_type"` // "subdomain" or "custom"
	IsPrimary    bool      `orm:"column(is_primary)" json:"is_primary"` // Primary domain for this tenant
	Verified     bool      `orm:"column(verified)" json:"verified"` // DNS verification status
	CreationTime time.Time `orm:"column(creation_time);auto_now_add" json:"creation_time"`
	UpdateTime   time.Time `orm:"column(update_time);auto_now" json:"update_time"`
}

// TableName returns the table name for TenantDomain
func (t *TenantDomain) TableName() string {
	return "tenant_domain"
}

// TenantStatus constants
const (
	TenantStatusActive    = "active"
	TenantStatusSuspended = "suspended"
	TenantStatusDeleted   = "deleted"
)

// DomainType constants
const (
	DomainTypeSubdomain = "subdomain" // acme.harbor.io
	DomainTypeCustom    = "custom"    // registry.acme.com
)

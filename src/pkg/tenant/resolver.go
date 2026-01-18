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

package tenant

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/pkg/tenant/dao"
	"github.com/goharbor/harbor/src/pkg/tenant/model"
)

// Resolver resolves domain names to tenant IDs with caching
type Resolver interface {
	// Resolve resolves a domain/host to a tenant ID
	// Returns 0 if no tenant found
	Resolve(ctx context.Context, host string) (int64, error)

	// ResolveWithTenant resolves a domain/host to a full Tenant object
	ResolveWithTenant(ctx context.Context, host string) (*model.Tenant, error)

	// InvalidateCache invalidates the cache for a specific domain
	InvalidateCache(domain string)

	// InvalidateTenantCache invalidates all cache entries for a tenant
	InvalidateTenantCache(tenantID int64)

	// ClearCache clears the entire cache
	ClearCache()
}

// ResolverConfig configures the tenant resolver
type ResolverConfig struct {
	// BaseDomain is the base domain for subdomain matching (e.g., "harbor.io")
	BaseDomain string

	// CacheTTL is how long to cache domain->tenant mappings
	CacheTTL time.Duration

	// NegativeCacheTTL is how long to cache "not found" results
	NegativeCacheTTL time.Duration

	// MaxCacheSize is the maximum number of entries in the cache
	MaxCacheSize int
}

// DefaultResolverConfig returns default configuration
func DefaultResolverConfig() *ResolverConfig {
	return &ResolverConfig{
		BaseDomain:       "harbor.io",
		CacheTTL:         5 * time.Minute,
		NegativeCacheTTL: 1 * time.Minute,
		MaxCacheSize:     10000,
	}
}

// cacheEntry represents a cached domain->tenant mapping
type cacheEntry struct {
	tenantID  int64
	tenant    *model.Tenant
	expiresAt time.Time
	notFound  bool // true if this is a negative cache entry
}

type resolver struct {
	dao    dao.DAO
	config *ResolverConfig

	// cache maps domain -> cacheEntry
	cache sync.Map

	// tenantDomains maps tenantID -> []domain for cache invalidation
	tenantDomains sync.Map
}

// NewResolver creates a new tenant resolver
func NewResolver(config *ResolverConfig) Resolver {
	if config == nil {
		config = DefaultResolverConfig()
	}
	return &resolver{
		dao:    dao.New(),
		config: config,
	}
}

// Resolve resolves a domain/host to a tenant ID
func (r *resolver) Resolve(ctx context.Context, host string) (int64, error) {
	tenant, err := r.ResolveWithTenant(ctx, host)
	if err != nil {
		return 0, err
	}
	if tenant == nil {
		return 0, nil
	}
	return tenant.ID, nil
}

// ResolveWithTenant resolves a domain/host to a full Tenant object
func (r *resolver) ResolveWithTenant(ctx context.Context, host string) (*model.Tenant, error) {
	// Normalize host (remove port if present)
	host = normalizeHost(host)

	// Check cache first
	if entry, ok := r.getFromCache(host); ok {
		if entry.notFound {
			return nil, nil
		}
		return entry.tenant, nil
	}

	// Cache miss - resolve from database
	tenant, err := r.resolveFromDB(ctx, host)
	if err != nil {
		return nil, err
	}

	// Cache the result
	r.addToCache(host, tenant)

	return tenant, nil
}

// resolveFromDB resolves tenant from database
func (r *resolver) resolveFromDB(ctx context.Context, host string) (*model.Tenant, error) {
	// Strategy 1: Check tenant_domain table for exact match
	domain, err := r.dao.GetDomainByName(ctx, host)
	if err == nil && domain != nil {
		tenant, err := r.dao.Get(ctx, domain.TenantID)
		if err == nil && tenant != nil && tenant.Status == model.TenantStatusActive {
			r.trackTenantDomain(tenant.ID, host)
			return tenant, nil
		}
	}

	// Strategy 2: Extract subdomain and check tenant_domain table
	subdomain := r.extractSubdomain(host)
	if subdomain != "" && subdomain != host {
		domain, err := r.dao.GetDomainByName(ctx, subdomain)
		if err == nil && domain != nil {
			tenant, err := r.dao.Get(ctx, domain.TenantID)
			if err == nil && tenant != nil && tenant.Status == model.TenantStatusActive {
				r.trackTenantDomain(tenant.ID, host)
				return tenant, nil
			}
		}
	}

	// Strategy 3: Check tenant.slug directly (for simple subdomain matching)
	if subdomain != "" {
		tenant, err := r.dao.GetBySlug(ctx, subdomain)
		if err == nil && tenant != nil && tenant.Status == model.TenantStatusActive {
			r.trackTenantDomain(tenant.ID, host)
			return tenant, nil
		}
	}

	// Not found
	log.Debugf("No tenant found for host: %s", host)
	return nil, nil
}

// extractSubdomain extracts the subdomain from a host
// e.g., "acme.harbor.io" -> "acme", "registry.acme.com" -> ""
func (r *resolver) extractSubdomain(host string) string {
	if r.config.BaseDomain == "" {
		return ""
	}

	suffix := "." + r.config.BaseDomain
	if strings.HasSuffix(host, suffix) {
		subdomain := strings.TrimSuffix(host, suffix)
		// Only return if it's a simple subdomain (no dots)
		if !strings.Contains(subdomain, ".") {
			return subdomain
		}
	}
	return ""
}

// normalizeHost removes port and converts to lowercase
func normalizeHost(host string) string {
	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		// Check if it's not an IPv6 address
		if !strings.Contains(host, "]") || strings.LastIndex(host, "]") < idx {
			host = host[:idx]
		}
	}
	return strings.ToLower(host)
}

// Cache operations

func (r *resolver) getFromCache(domain string) (*cacheEntry, bool) {
	if val, ok := r.cache.Load(domain); ok {
		entry := val.(*cacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry, true
		}
		// Expired - remove from cache
		r.cache.Delete(domain)
	}
	return nil, false
}

func (r *resolver) addToCache(domain string, tenant *model.Tenant) {
	var entry *cacheEntry
	if tenant == nil {
		// Negative cache entry
		entry = &cacheEntry{
			notFound:  true,
			expiresAt: time.Now().Add(r.config.NegativeCacheTTL),
		}
	} else {
		entry = &cacheEntry{
			tenantID:  tenant.ID,
			tenant:    tenant,
			expiresAt: time.Now().Add(r.config.CacheTTL),
		}
	}
	r.cache.Store(domain, entry)
}

func (r *resolver) trackTenantDomain(tenantID int64, domain string) {
	// Track which domains belong to which tenant for invalidation
	val, _ := r.tenantDomains.LoadOrStore(tenantID, &sync.Map{})
	domainMap := val.(*sync.Map)
	domainMap.Store(domain, struct{}{})
}

// InvalidateCache invalidates the cache for a specific domain
func (r *resolver) InvalidateCache(domain string) {
	domain = normalizeHost(domain)
	r.cache.Delete(domain)
}

// InvalidateTenantCache invalidates all cache entries for a tenant
func (r *resolver) InvalidateTenantCache(tenantID int64) {
	if val, ok := r.tenantDomains.Load(tenantID); ok {
		domainMap := val.(*sync.Map)
		domainMap.Range(func(key, _ interface{}) bool {
			r.cache.Delete(key.(string))
			return true
		})
		r.tenantDomains.Delete(tenantID)
	}
}

// ClearCache clears the entire cache
func (r *resolver) ClearCache() {
	r.cache = sync.Map{}
	r.tenantDomains = sync.Map{}
}

// Global resolver instance
var (
	globalResolver     Resolver
	globalResolverOnce sync.Once
)

// GetResolver returns the global tenant resolver
func GetResolver() Resolver {
	globalResolverOnce.Do(func() {
		globalResolver = NewResolver(nil)
	})
	return globalResolver
}

// SetResolver sets the global tenant resolver (for testing)
func SetResolver(r Resolver) {
	globalResolver = r
}

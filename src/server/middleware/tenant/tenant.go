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
	"net/http"
	"strconv"

	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/pkg/tenant"
	"github.com/goharbor/harbor/src/pkg/tenant/model"
)

// Context keys for tenant information
type contextKey string

const (
	// TenantIDKey is the context key for tenant ID
	TenantIDKey contextKey = "tenant_id"

	// TenantKey is the context key for full tenant object
	TenantKey contextKey = "tenant"

	// HeaderTenantID is the HTTP header for explicit tenant ID
	HeaderTenantID = "X-Tenant-ID"
)

// Middleware creates HTTP middleware for tenant resolution
func Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			resolver := tenant.GetResolver()

			var tenantID int64
			var tenantObj *model.Tenant
			var err error

			// Priority 1: Explicit header (for API clients, testing)
			if headerID := r.Header.Get(HeaderTenantID); headerID != "" {
				tenantID, err = strconv.ParseInt(headerID, 10, 64)
				if err != nil {
					log.Warningf("Invalid X-Tenant-ID header: %s", headerID)
				}
			}

			// Priority 2: Resolve from host/domain
			if tenantID == 0 {
				tenantObj, err = resolver.ResolveWithTenant(ctx, r.Host)
				if err != nil {
					log.Errorf("Failed to resolve tenant for host %s: %v", r.Host, err)
					// Continue without tenant - might be system endpoint
				}
				if tenantObj != nil {
					tenantID = tenantObj.ID
				}
			}

			// Add tenant to context
			if tenantID > 0 {
				ctx = WithTenantID(ctx, tenantID)
				if tenantObj != nil {
					ctx = WithTenant(ctx, tenantObj)
				}
				log.Debugf("Request tenant: id=%d host=%s", tenantID, r.Host)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireTenant creates middleware that rejects requests without a tenant
func RequireTenant() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := TenantIDFromContext(r.Context())
			if tenantID == 0 {
				http.Error(w, "Tenant not found", http.StatusNotFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WithTenantID adds tenant ID to context
func WithTenantID(ctx context.Context, tenantID int64) context.Context {
	return context.WithValue(ctx, TenantIDKey, tenantID)
}

// WithTenant adds full tenant object to context
func WithTenant(ctx context.Context, t *model.Tenant) context.Context {
	return context.WithValue(ctx, TenantKey, t)
}

// TenantIDFromContext retrieves tenant ID from context
// Returns 0 if no tenant is set
func TenantIDFromContext(ctx context.Context) int64 {
	if ctx == nil {
		return 0
	}
	if id, ok := ctx.Value(TenantIDKey).(int64); ok {
		return id
	}
	return 0
}

// TenantFromContext retrieves full tenant object from context
// Returns nil if no tenant is set
func TenantFromContext(ctx context.Context) *model.Tenant {
	if ctx == nil {
		return nil
	}
	if t, ok := ctx.Value(TenantKey).(*model.Tenant); ok {
		return t
	}
	return nil
}

// MustTenantIDFromContext retrieves tenant ID from context
// Panics if no tenant is set (use only when tenant is required)
func MustTenantIDFromContext(ctx context.Context) int64 {
	id := TenantIDFromContext(ctx)
	if id == 0 {
		panic("tenant ID not found in context")
	}
	return id
}

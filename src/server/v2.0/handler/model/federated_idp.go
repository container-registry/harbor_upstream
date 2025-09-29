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
	"encoding/json"
	"strings"

	"github.com/go-openapi/strfmt"

	pkg "github.com/goharbor/harbor/src/pkg/federatedidp/model"
	"github.com/goharbor/harbor/src/server/v2.0/models"
)

// FederatedIdp ...
type FederatedIdp struct {
	*pkg.FederatedIdp
}

// ClaimRule ...
type ClaimRule struct {
	*pkg.ClaimRule
}

// ToSwagger converts a pkg.FederatedIdp to the swagger models.FederatedIdp
func (p *FederatedIdp) ToSwagger() *models.FederatedIdp {
	if p == nil {
		return nil
	}

	// convert JWKSKeys (json.RawMessage) to interface{}
	var jwks any
	// Unmarshal raw JSON into interface{} for swagger type
	if p.JWKSKeys != "" {
		_ = json.Unmarshal([]byte(p.JWKSKeys), &jwks)
	}

	return &models.FederatedIdp{
		ID:                  p.ID,
		Name:                p.Name,
		Description:         p.Description,
		Issuer:              p.Issuer,
		OpenidConfigURL:     p.OpenIDConfigURL,
		JwksURI:             p.JWKSURI,
		JwksKeys:            jwks,
		OfflineValidation:   p.OfflineValidation,
		SupportedAlgorithms: strings.Split(p.SupportedAlgorithms, ","),
		ClaimsSupported:     strings.Split(p.ClaimsSupported, ","),
		ProjectID:           p.ProjectID,
		CreationTime:        strfmt.DateTime(p.CreationTime),
		UpdateTime:          strfmt.DateTime(p.UpdateTime),
	}
}

// NewFederatedIdp ...
func NewFederatedIdp(f *pkg.FederatedIdp) *FederatedIdp {
	return &FederatedIdp{
		FederatedIdp: f,
	}
}

// NewClaimRule ...
func NewClaimRule(c *pkg.ClaimRule) *ClaimRule {
	return &ClaimRule{
		ClaimRule: c,
	}
}

// ToSwagger converts a pkg.FederatedIdp to the swagger models.FederatedIdp
func (p *ClaimRule) ToSwagger() *models.ClaimRule {
	if p == nil {
		return nil
	}

	return &models.ClaimRule{
		ID:                 p.ID,
		IdentityProviderID: p.IdentityProviderID,
		RobotID:            p.RobotID,
		ClaimPath:          p.ClaimPath,
		Value:              p.Value,
		CreationTime:       strfmt.DateTime(p.CreationTime),
	}
}

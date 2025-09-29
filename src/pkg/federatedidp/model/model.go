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
	"time"

	"github.com/beego/beego/v2/client/orm"

	"github.com/goharbor/harbor/src/lib/errors"
)

func init() {
	orm.RegisterModel(&FederatedIdp{})
}

// FederatedIdp holds the details of a federated idp.
type FederatedIdp struct {
	ID                  int64     `orm:"pk;auto;column(id)" json:"id"`
	Name                string    `orm:"column(name)" json:"name" sort:"default"`
	Description         string    `orm:"column(description)" json:"description"`
	Issuer              string    `orm:"column(issuer);unique" json:"issuer"`
	OpenIDConfigURL     string    `orm:"column(openid_config_url)" json:"openid_config_url"`
	JWKSURI             string    `orm:"column(jwks_uri)" json:"jwks_uri"`
	JWKSKeys            string    `orm:"column(jwks_keys);type(jsonb)" json:"jwks_keys"` // store JWKS JSON
	OfflineValidation   bool      `orm:"column(offline_validation)" json:"offline_validation"`
	SupportedAlgorithms string    `orm:"column(supported_algorithms)" json:"supported_algorithms"`
	ClaimsSupported     string    `orm:"column(claims_supported)" json:"claims_supported"`
	ProjectID           int64     `orm:"column(project_id)" json:"project_id"`
	CreationTime        time.Time `orm:"column(creation_time);auto_now_add" json:"creation_time"`
	UpdateTime          time.Time `orm:"column(update_time);auto_now" json:"update_time"`
}

// TableName ...
func (f *FederatedIdp) TableName() string {
	return "identity_providers"
}

// FromJSON parses FederatedIdp from json data
func (f *FederatedIdp) FromJSON(jsonData string) error {
	if len(jsonData) == 0 {
		return errors.New("empty json data to parse")
	}

	return json.Unmarshal([]byte(jsonData), f)
}

// ToJSON marshals Robot to JSON data
func (f *FederatedIdp) ToJSON() (string, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
